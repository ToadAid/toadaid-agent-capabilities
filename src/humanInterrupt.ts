import { randomUUID } from "node:crypto";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import { runStateCapsuleSha256, validateRunStateCapsule, type RunStateCapsule } from "./runStateCapsule.js";
import {
  MAX_PROMPT_CHARS,
  MAX_RESPONDER_CHARS,
  MAX_SERIALIZED_BYTES,
  SHA256_PATTERN,
  assertId,
  boundedString,
  canonicalIso,
  exactInteger,
  normalizeHumanInterruptResponseSchema,
  normalizeReason,
  sha256,
  validateHumanInterruptResponse,
} from "./humanInterruptSchema.js";
import type {
  CreateHumanInterruptInput,
  HumanInterruptEnvelope,
  HumanInterruptRecord,
  HumanInterruptResolution,
  HumanInterruptResumeProof,
  HumanInterruptRunBinding,
  ResolveHumanInterruptInput,
} from "./humanInterruptTypes.js";

export { normalizeHumanInterruptResponseSchema, validateHumanInterruptResponse } from "./humanInterruptSchema.js";
export type {
  CreateHumanInterruptInput,
  HumanInterruptBooleanSchema,
  HumanInterruptContinuity,
  HumanInterruptEnvelope,
  HumanInterruptIntegerSchema,
  HumanInterruptObjectSchema,
  HumanInterruptReason,
  HumanInterruptRecord,
  HumanInterruptResolution,
  HumanInterruptResponse,
  HumanInterruptResponseScalar,
  HumanInterruptResponseSchema,
  HumanInterruptResumeProof,
  HumanInterruptRunBinding,
  HumanInterruptScalarSchema,
  HumanInterruptStatus,
  HumanInterruptStringSchema,
  ResolveHumanInterruptInput,
} from "./humanInterruptTypes.js";

function assertAuthority(authority: CapabilityAuthorityDecision, capabilityId: string): void {
  if (
    authority.schemaVersion !== "toadaid.capability-authority-decision.v1" ||
    authority.capabilityId !== capabilityId ||
    !authority.installed ||
    authority.decision !== "ALLOW"
  ) throw new Error(`human interrupt capability is not authorized: ${capabilityId}`);
}

function bindRunState(runState: RunStateCapsule): HumanInterruptRunBinding {
  validateRunStateCapsule(runState);
  const digest = runStateCapsuleSha256(runState);
  if (!SHA256_PATTERN.test(digest)) throw new TypeError("run-state SHA-256 is invalid");
  return Object.freeze({
    runId: assertId(runState.runId, "runState.runId"),
    runRevision: exactInteger(runState.revision, 0, 0, Number.MAX_SAFE_INTEGER, "runState.revision"),
    runStateSha256: digest,
  });
}

function freezeResolution(resolution: HumanInterruptResolution | null): HumanInterruptResolution | null {
  if (resolution === null) return null;
  const response = typeof resolution.response === "object" && resolution.response !== null
    ? Object.freeze({ ...resolution.response })
    : resolution.response;
  return Object.freeze({ ...resolution, response });
}

function freezeRecord(record: HumanInterruptRecord): HumanInterruptRecord {
  return Object.freeze({
    ...record,
    responseSchema: normalizeHumanInterruptResponseSchema(record.responseSchema),
    runBinding: Object.freeze({ ...record.runBinding }),
    resolution: freezeResolution(record.resolution),
    continuity: Object.freeze({ ...record.continuity }),
  });
}

export function humanInterruptRecordSha256(record: HumanInterruptRecord): string {
  return sha256(record);
}

export function validateHumanInterruptRecord(record: HumanInterruptRecord): HumanInterruptRecord {
  if (record.schemaVersion !== "toadaid.human-interrupt.v1") throw new TypeError("unsupported human interrupt schemaVersion");
  const interruptId = assertId(record.interruptId, "interruptId");
  const revision = exactInteger(record.revision, 0, 0, 1, "revision");
  if (record.status !== "OPEN" && record.status !== "RESOLVED") throw new TypeError("human interrupt status is invalid");
  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) throw new RangeError("updatedAt must not be earlier than createdAt");
  const runBinding = record.runBinding;
  assertId(runBinding.runId, "runBinding.runId");
  exactInteger(runBinding.runRevision, 0, 0, Number.MAX_SAFE_INTEGER, "runBinding.runRevision");
  if (!SHA256_PATTERN.test(runBinding.runStateSha256)) throw new TypeError("runBinding.runStateSha256 is invalid");
  const responseSchema = normalizeHumanInterruptResponseSchema(record.responseSchema);
  const reason = normalizeReason(record.reason);
  const prompt = boundedString(record.prompt, "prompt", MAX_PROMPT_CHARS);

  if (record.status === "OPEN") {
    if (revision !== 0 || record.resolution !== null || record.continuity.previousRecordSha256 !== null) {
      throw new TypeError("OPEN human interrupt continuity is invalid");
    }
  } else {
    if (revision !== 1 || record.resolution === null) throw new TypeError("RESOLVED human interrupt revision/resolution is invalid");
    if (!record.continuity.previousRecordSha256 || !SHA256_PATTERN.test(record.continuity.previousRecordSha256)) {
      throw new TypeError("RESOLVED human interrupt previousRecordSha256 is invalid");
    }
    const resolution = record.resolution;
    boundedString(resolution.responderId, "resolution.responderId", MAX_RESPONDER_CHARS);
    const resolvedAt = canonicalIso(resolution.resolvedAt, "resolution.resolvedAt");
    if (Date.parse(resolvedAt) < Date.parse(createdAt)) throw new RangeError("resolution.resolvedAt is earlier than createdAt");
    const response = validateHumanInterruptResponse(resolution.response, responseSchema);
    if (!SHA256_PATTERN.test(resolution.responseSha256) || resolution.responseSha256 !== sha256(response)) {
      throw new Error("human interrupt response integrity mismatch");
    }
  }
  return freezeRecord({ ...record, interruptId, revision, createdAt, updatedAt, reason, prompt, responseSchema, runBinding: Object.freeze({ ...runBinding }) });
}

export function sealHumanInterruptRecord(record: HumanInterruptRecord): HumanInterruptEnvelope {
  const normalized = validateHumanInterruptRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.human-interrupt-envelope.v1",
    record: normalized,
    recordSha256: humanInterruptRecordSha256(normalized),
  });
}

export function createHumanInterrupt(
  input: CreateHumanInterruptInput,
  runState: RunStateCapsule,
  authority: CapabilityAuthorityDecision,
): HumanInterruptEnvelope {
  assertAuthority(authority, "interrupt:create");
  const createdAt = canonicalIso(input.createdAt, "createdAt");
  return sealHumanInterruptRecord({
    schemaVersion: "toadaid.human-interrupt.v1",
    interruptId: assertId(input.interruptId ?? randomUUID(), "interruptId"),
    revision: 0,
    status: "OPEN",
    createdAt,
    updatedAt: createdAt,
    reason: normalizeReason(input.reason),
    prompt: boundedString(input.prompt, "prompt", MAX_PROMPT_CHARS),
    responseSchema: normalizeHumanInterruptResponseSchema(input.responseSchema),
    runBinding: bindRunState(runState),
    resolution: null,
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

function assertRunBinding(binding: HumanInterruptRunBinding, runState: RunStateCapsule): void {
  const current = bindRunState(runState);
  if (binding.runId !== current.runId || binding.runRevision !== current.runRevision || binding.runStateSha256 !== current.runStateSha256) {
    throw new Error("human interrupt run-state binding mismatch");
  }
}

export function resolveHumanInterrupt(
  envelope: HumanInterruptEnvelope,
  input: ResolveHumanInterruptInput,
  currentRunState: RunStateCapsule,
  authority: CapabilityAuthorityDecision,
): HumanInterruptEnvelope {
  assertAuthority(authority, "interrupt:resolve");
  const validated = validateHumanInterruptEnvelope(envelope);
  const previous = validated.record;
  if (previous.status !== "OPEN" || previous.resolution !== null) throw new Error("human interrupt is already resolved");
  assertRunBinding(previous.runBinding, currentRunState);
  const resolvedAt = canonicalIso(input.resolvedAt, "resolvedAt");
  if (Date.parse(resolvedAt) < Date.parse(previous.createdAt)) throw new RangeError("resolvedAt must not be earlier than createdAt");
  const response = validateHumanInterruptResponse(input.response, previous.responseSchema);
  const resolution: HumanInterruptResolution = Object.freeze({
    responderId: boundedString(input.responderId, "responderId", MAX_RESPONDER_CHARS),
    resolvedAt,
    response,
    responseSha256: sha256(response),
  });
  return sealHumanInterruptRecord({
    ...previous,
    revision: previous.revision + 1,
    status: "RESOLVED",
    updatedAt: resolvedAt,
    resolution,
    continuity: Object.freeze({ previousRecordSha256: validated.recordSha256 }),
  });
}

export function createHumanInterruptResumeProof(
  envelope: HumanInterruptEnvelope,
  currentRunState: RunStateCapsule,
  verifiedAt: string,
): HumanInterruptResumeProof {
  const validated = validateHumanInterruptEnvelope(envelope);
  if (validated.record.status !== "RESOLVED" || validated.record.resolution === null) {
    throw new Error("human interrupt must be resolved before resume proof can be created");
  }
  assertRunBinding(validated.record.runBinding, currentRunState);
  return Object.freeze({
    schemaVersion: "toadaid.human-interrupt-resume-proof.v1",
    interruptId: validated.record.interruptId,
    interruptRecordSha256: validated.recordSha256,
    runId: validated.record.runBinding.runId,
    runRevision: validated.record.runBinding.runRevision,
    runStateSha256: validated.record.runBinding.runStateSha256,
    responderId: validated.record.resolution.responderId,
    responseSha256: validated.record.resolution.responseSha256,
    verifiedAt: canonicalIso(verifiedAt, "verifiedAt"),
  });
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

export function validateHumanInterruptEnvelope(value: HumanInterruptEnvelope): HumanInterruptEnvelope {
  const envelope = objectValue(value, "human interrupt envelope");
  if (envelope.schemaVersion !== "toadaid.human-interrupt-envelope.v1") throw new TypeError("unsupported human interrupt envelope schemaVersion");
  if (typeof envelope.recordSha256 !== "string" || !SHA256_PATTERN.test(envelope.recordSha256)) throw new TypeError("human interrupt recordSha256 is invalid");
  const record = validateHumanInterruptRecord(envelope.record as HumanInterruptRecord);
  if (humanInterruptRecordSha256(record) !== envelope.recordSha256) throw new Error("human interrupt record integrity mismatch");
  return Object.freeze({ schemaVersion: "toadaid.human-interrupt-envelope.v1", record, recordSha256: envelope.recordSha256 });
}

export function serializeHumanInterrupt(envelope: HumanInterruptEnvelope): string {
  const serialized = JSON.stringify(validateHumanInterruptEnvelope(envelope));
  if (Buffer.byteLength(serialized, "utf8") > MAX_SERIALIZED_BYTES) throw new RangeError(`human interrupt envelope exceeds ${MAX_SERIALIZED_BYTES} bytes`);
  return serialized;
}

export function parseHumanInterrupt(serialized: string): HumanInterruptEnvelope {
  if (typeof serialized !== "string") throw new TypeError("human interrupt serialized value must be a string");
  if (Buffer.byteLength(serialized, "utf8") > MAX_SERIALIZED_BYTES) throw new RangeError(`human interrupt envelope exceeds ${MAX_SERIALIZED_BYTES} bytes`);
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new TypeError("human interrupt envelope must be valid JSON"); }
  return validateHumanInterruptEnvelope(parsed as HumanInterruptEnvelope);
}
