import { createHash } from "node:crypto";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";

export type LoopObservationKind =
  | "MODEL_OUTPUT"
  | "TOOL_CALL"
  | "TOOL_FAILURE"
  | "EMPTY_OUTPUT";
export type LoopObservationOutcome = "SUCCESS" | "FAILURE";
export type LoopBreakerHaltReason =
  | "REPEATED_FINGERPRINT"
  | "CONSECUTIVE_FAILURES"
  | "ALREADY_HALTED";
export type LoopBreakerDecisionKind = "CONTINUE" | "HALT";

export interface LoopBreakerPolicy {
  maxConsecutiveIdentical?: number;
  maxConsecutiveFailures?: number;
  maxHistoryEntries?: number;
  maxPayloadChars?: number;
}

export interface NormalizedLoopBreakerPolicy {
  maxConsecutiveIdentical: number;
  maxConsecutiveFailures: number;
  maxHistoryEntries: number;
  maxPayloadChars: number;
}

export interface LoopObservation {
  kind: LoopObservationKind;
  outcome: LoopObservationOutcome;
  payload?: string;
  toolName?: string;
  errorClass?: string;
}

export interface LoopBreakerHistoryEntry {
  sequence: number;
  fingerprint: string;
  kind: LoopObservationKind;
  outcome: LoopObservationOutcome;
}

export interface LoopBreakerState {
  schemaVersion: "toadaid.loop-breaker-state.v1";
  sequence: number;
  halted: boolean;
  haltReason: Exclude<LoopBreakerHaltReason, "ALREADY_HALTED"> | null;
  lastFingerprint: string | null;
  consecutiveIdentical: number;
  consecutiveFailures: number;
  history: readonly LoopBreakerHistoryEntry[];
}

export interface LoopBreakerDecision {
  schemaVersion: "toadaid.loop-breaker-decision.v1";
  decision: LoopBreakerDecisionKind;
  reason: LoopBreakerHaltReason | "NONE";
  fingerprint: string | null;
  sequence: number;
  consecutiveIdentical: number;
  consecutiveFailures: number;
}

export interface LoopBreakerResult {
  state: LoopBreakerState;
  decision: LoopBreakerDecision;
}

export type BoundedRepairOperation =
  | "STRIP_BOM"
  | "TRIM_OUTER_WHITESPACE"
  | "UNWRAP_JSON_CODE_FENCE"
  | "REMOVE_TRAILING_COMMAS";

export type BoundedRepairRefusalReason =
  | "AUTHORITY_REQUIRED"
  | "INVALID_JSON"
  | "INVALID_TOOL_CALL_SHAPE"
  | "UNSUPPORTED_JSON_VALUE"
  | "INPUT_TOO_LARGE";

export interface BoundedToolCall {
  tool: string;
  arguments: Readonly<Record<string, unknown>>;
}

interface BoundedRepairBase {
  schemaVersion: "toadaid.bounded-tool-call-repair.v1";
  inputSha256: string;
  outputSha256: string | null;
  operations: readonly BoundedRepairOperation[];
}

export interface BoundedRepairSuccess extends BoundedRepairBase {
  status: "VALID" | "REPAIRED";
  toolCall: BoundedToolCall;
}

export interface BoundedRepairRefusal extends BoundedRepairBase {
  status: "REFUSED";
  reason: BoundedRepairRefusalReason;
}

export type BoundedRepairResult = BoundedRepairSuccess | BoundedRepairRefusal;

const DEFAULT_MAX_IDENTICAL = 3;
const DEFAULT_MAX_FAILURES = 5;
const DEFAULT_MAX_HISTORY = 20;
const DEFAULT_MAX_PAYLOAD_CHARS = 65_536;
const MAX_THRESHOLD = 100;
const MAX_HISTORY = 500;
const MAX_PAYLOAD_CHARS = 1_000_000;
const MAX_REPAIR_INPUT_CHARS = 65_536;
const TOOL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const FORBIDDEN_ARGUMENT_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const MAX_JSON_DEPTH = 20;
const MAX_JSON_NODES = 5_000;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

export function normalizeLoopBreakerPolicy(
  policy: LoopBreakerPolicy = {},
): NormalizedLoopBreakerPolicy {
  return Object.freeze({
    maxConsecutiveIdentical: exactInteger(
      policy.maxConsecutiveIdentical,
      DEFAULT_MAX_IDENTICAL,
      2,
      MAX_THRESHOLD,
      "maxConsecutiveIdentical",
    ),
    maxConsecutiveFailures: exactInteger(
      policy.maxConsecutiveFailures,
      DEFAULT_MAX_FAILURES,
      2,
      MAX_THRESHOLD,
      "maxConsecutiveFailures",
    ),
    maxHistoryEntries: exactInteger(
      policy.maxHistoryEntries,
      DEFAULT_MAX_HISTORY,
      1,
      MAX_HISTORY,
      "maxHistoryEntries",
    ),
    maxPayloadChars: exactInteger(
      policy.maxPayloadChars,
      DEFAULT_MAX_PAYLOAD_CHARS,
      1,
      MAX_PAYLOAD_CHARS,
      "maxPayloadChars",
    ),
  });
}

export function createLoopBreakerState(): LoopBreakerState {
  return Object.freeze({
    schemaVersion: "toadaid.loop-breaker-state.v1",
    sequence: 0,
    halted: false,
    haltReason: null,
    lastFingerprint: null,
    consecutiveIdentical: 0,
    consecutiveFailures: 0,
    history: Object.freeze([]),
  });
}

function normalizeObservationText(
  kind: LoopObservationKind,
  value: string | undefined,
  label: string,
  maximum: number,
): string {
  if (value === undefined) return "";
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  if (value.length > maximum) throw new RangeError(`${label} exceeds ${maximum} characters`);
  const normalized = value.replace(/\r\n?/g, "\n").trim();
  return kind === "MODEL_OUTPUT" || kind === "EMPTY_OUTPUT"
    ? normalized.replace(/\s+/g, " ")
    : normalized;
}

function normalizeOptionalLabel(value: string | undefined, label: string): string {
  if (value === undefined) return "";
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (normalized.length > 256) throw new RangeError(`${label} exceeds 256 characters`);
  return normalized;
}

export function fingerprintLoopObservation(
  observation: LoopObservation,
  policyInput: LoopBreakerPolicy = {},
): string {
  const policy = normalizeLoopBreakerPolicy(policyInput);
  const allowedKinds: readonly LoopObservationKind[] = [
    "MODEL_OUTPUT",
    "TOOL_CALL",
    "TOOL_FAILURE",
    "EMPTY_OUTPUT",
  ];
  if (!allowedKinds.includes(observation.kind)) {
    throw new TypeError(`invalid loop observation kind: ${String(observation.kind)}`);
  }
  if (observation.outcome !== "SUCCESS" && observation.outcome !== "FAILURE") {
    throw new TypeError(`invalid loop observation outcome: ${String(observation.outcome)}`);
  }

  const canonical = JSON.stringify({
    kind: observation.kind,
    outcome: observation.outcome,
    payload: normalizeObservationText(observation.kind, observation.payload, "payload", policy.maxPayloadChars),
    toolName: normalizeOptionalLabel(observation.toolName, "toolName"),
    errorClass: normalizeOptionalLabel(observation.errorClass, "errorClass"),
  });
  return sha256(canonical);
}

function freezeLoopState(state: LoopBreakerState): LoopBreakerState {
  return Object.freeze({
    ...state,
    history: Object.freeze(state.history.map((entry) => Object.freeze({ ...entry }))),
  });
}

export function recordLoopObservation(
  state: LoopBreakerState,
  observation: LoopObservation,
  policyInput: LoopBreakerPolicy = {},
): LoopBreakerResult {
  const policy = normalizeLoopBreakerPolicy(policyInput);
  if (state.schemaVersion !== "toadaid.loop-breaker-state.v1") {
    throw new TypeError("invalid loop breaker state schema");
  }

  if (state.halted) {
    const decision = Object.freeze({
      schemaVersion: "toadaid.loop-breaker-decision.v1" as const,
      decision: "HALT" as const,
      reason: "ALREADY_HALTED" as const,
      fingerprint: state.lastFingerprint,
      sequence: state.sequence,
      consecutiveIdentical: state.consecutiveIdentical,
      consecutiveFailures: state.consecutiveFailures,
    });
    return Object.freeze({ state, decision });
  }

  const fingerprint = fingerprintLoopObservation(observation, policy);
  const sequence = state.sequence + 1;
  const consecutiveIdentical = state.lastFingerprint === fingerprint
    ? state.consecutiveIdentical + 1
    : 1;
  const consecutiveFailures = observation.outcome === "FAILURE"
    ? state.consecutiveFailures + 1
    : 0;

  let haltReason: Exclude<LoopBreakerHaltReason, "ALREADY_HALTED"> | null = null;
  if (consecutiveIdentical >= policy.maxConsecutiveIdentical) {
    haltReason = "REPEATED_FINGERPRINT";
  } else if (consecutiveFailures >= policy.maxConsecutiveFailures) {
    haltReason = "CONSECUTIVE_FAILURES";
  }

  const nextEntry: LoopBreakerHistoryEntry = Object.freeze({
    sequence,
    fingerprint,
    kind: observation.kind,
    outcome: observation.outcome,
  });
  const nextHistory = [...state.history, nextEntry].slice(-policy.maxHistoryEntries);
  const nextState = freezeLoopState({
    schemaVersion: "toadaid.loop-breaker-state.v1",
    sequence,
    halted: haltReason !== null,
    haltReason,
    lastFingerprint: fingerprint,
    consecutiveIdentical,
    consecutiveFailures,
    history: nextHistory,
  });
  const decision = Object.freeze({
    schemaVersion: "toadaid.loop-breaker-decision.v1" as const,
    decision: haltReason === null ? "CONTINUE" as const : "HALT" as const,
    reason: haltReason ?? "NONE" as const,
    fingerprint,
    sequence,
    consecutiveIdentical,
    consecutiveFailures,
  });
  return Object.freeze({ state: nextState, decision });
}

function repairAuthorityAllowed(authority: CapabilityAuthorityDecision): boolean {
  return authority.schemaVersion === "toadaid.capability-authority-decision.v1"
    && authority.capabilityId === "runtime:bounded-repair"
    && authority.installed === true
    && authority.decision === "ALLOW";
}

function trimWithOperation(value: string, operations: BoundedRepairOperation[]): string {
  const trimmed = value.trim();
  if (trimmed !== value) operations.push("TRIM_OUTER_WHITESPACE");
  return trimmed;
}

function unwrapJsonCodeFence(value: string, operations: BoundedRepairOperation[]): string {
  const match = value.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i);
  if (!match) return value;
  operations.push("UNWRAP_JSON_CODE_FENCE");
  return match[1] ?? "";
}

function removeTrailingCommas(value: string): { value: string; changed: boolean } {
  let output = "";
  let inString = false;
  let escaped = false;
  let changed = false;

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index] ?? "";
    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }

    if (char === ",") {
      let cursor = index + 1;
      while (cursor < value.length && /\s/.test(value[cursor] ?? "")) cursor += 1;
      const next = value[cursor];
      if (next === "}" || next === "]") {
        changed = true;
        continue;
      }
    }

    output += char;
  }

  return { value: output, changed };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateJsonValue(value: unknown, depth: number, counter: { nodes: number }): boolean {
  counter.nodes += 1;
  if (counter.nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((entry) => validateJsonValue(entry, depth + 1, counter));
  if (!isPlainRecord(value)) return false;

  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_ARGUMENT_KEYS.has(key)) return false;
    if (!validateJsonValue(entry, depth + 1, counter)) return false;
  }
  return true;
}

function freezeJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => freezeJsonValue(entry)));
  if (isPlainRecord(value)) {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, freezeJsonValue(entry)]),
    ));
  }
  return value;
}

function parseBoundedToolCall(value: string): BoundedToolCall | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!isPlainRecord(parsed)) return null;

  const keys = Object.keys(parsed).sort();
  if (keys.length !== 2 || keys[0] !== "arguments" || keys[1] !== "tool") return null;
  if (typeof parsed.tool !== "string" || !TOOL_NAME_PATTERN.test(parsed.tool)) return null;
  if (!isPlainRecord(parsed.arguments)) return null;
  if (!validateJsonValue(parsed.arguments, 0, { nodes: 0 })) return null;

  return Object.freeze({
    tool: parsed.tool,
    arguments: freezeJsonValue(parsed.arguments) as Readonly<Record<string, unknown>>,
  });
}

function refusal(
  inputSha256: string,
  operations: readonly BoundedRepairOperation[],
  reason: BoundedRepairRefusalReason,
): BoundedRepairRefusal {
  return Object.freeze({
    schemaVersion: "toadaid.bounded-tool-call-repair.v1",
    status: "REFUSED",
    reason,
    inputSha256,
    outputSha256: null,
    operations: Object.freeze([...operations]),
  });
}

export function repairToolCallSyntax(
  raw: string,
  authority: CapabilityAuthorityDecision,
): BoundedRepairResult {
  if (typeof raw !== "string") throw new TypeError("raw tool call must be a string");
  const inputSha256 = sha256(raw);
  const operations: BoundedRepairOperation[] = [];

  if (!repairAuthorityAllowed(authority)) {
    return refusal(inputSha256, operations, "AUTHORITY_REQUIRED");
  }
  if (raw.length > MAX_REPAIR_INPUT_CHARS) {
    return refusal(inputSha256, operations, "INPUT_TOO_LARGE");
  }

  let candidate = raw;
  if (candidate.startsWith("\uFEFF")) {
    candidate = candidate.slice(1);
    operations.push("STRIP_BOM");
  }
  candidate = trimWithOperation(candidate, operations);
  candidate = unwrapJsonCodeFence(candidate, operations);
  candidate = trimWithOperation(candidate, operations);
  const trailing = removeTrailingCommas(candidate);
  if (trailing.changed) operations.push("REMOVE_TRAILING_COMMAS");
  candidate = trailing.value;

  let parsed: unknown;
  try {
    parsed = JSON.parse(candidate);
  } catch {
    return refusal(inputSha256, operations, "INVALID_JSON");
  }

  if (!isPlainRecord(parsed)) {
    return refusal(inputSha256, operations, "INVALID_TOOL_CALL_SHAPE");
  }
  const keys = Object.keys(parsed).sort();
  if (keys.length !== 2 || keys[0] !== "arguments" || keys[1] !== "tool") {
    return refusal(inputSha256, operations, "INVALID_TOOL_CALL_SHAPE");
  }
  if (typeof parsed.tool !== "string" || !TOOL_NAME_PATTERN.test(parsed.tool) || !isPlainRecord(parsed.arguments)) {
    return refusal(inputSha256, operations, "INVALID_TOOL_CALL_SHAPE");
  }
  if (!validateJsonValue(parsed.arguments, 0, { nodes: 0 })) {
    return refusal(inputSha256, operations, "UNSUPPORTED_JSON_VALUE");
  }

  const toolCall = parseBoundedToolCall(candidate);
  if (!toolCall) return refusal(inputSha256, operations, "INVALID_TOOL_CALL_SHAPE");

  return Object.freeze({
    schemaVersion: "toadaid.bounded-tool-call-repair.v1",
    status: operations.length === 0 ? "VALID" : "REPAIRED",
    inputSha256,
    outputSha256: sha256(candidate),
    operations: Object.freeze([...operations]),
    toolCall,
  });
}
