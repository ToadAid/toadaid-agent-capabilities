import { createHash } from "node:crypto";

import type { CapabilityAuthorityDecision, CapabilityEffectiveDecision } from "./capabilityPolicy.js";

export type RunObjectiveStatus = "ACTIVE" | "BLOCKED" | "COMPLETE" | "SUPERSEDED";
export type RunContinuityReason = "INITIAL" | "CHECKPOINT" | "COMPACTION" | "RESTART" | "MANUAL";

export interface RunObjectiveState {
  summary: string;
  status: RunObjectiveStatus;
}

export interface RunWorkItem {
  id: string;
  summary: string;
}

export interface RunEvidenceReference {
  id: string;
  locator: string;
  sha256?: string;
}

export interface RunArtifactReference {
  id: string;
  locator: string;
  sha256?: string;
}

export interface RunAuthoritySnapshot {
  capturedAt: string;
  decisions: readonly CapabilityAuthorityDecision[];
}

export interface RunStateContinuity {
  generation: number;
  reason: RunContinuityReason;
  previousCapsuleSha256: string | null;
}

export interface RunStateCapsule {
  schemaVersion: "toadaid.run-state-capsule.v1";
  runId: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  objective: RunObjectiveState;
  phase: string;
  authoritySnapshot: RunAuthoritySnapshot;
  evidenceRefs: readonly RunEvidenceReference[];
  artifactRefs: readonly RunArtifactReference[];
  work: {
    completed: readonly RunWorkItem[];
    pending: readonly RunWorkItem[];
    blocked: readonly RunWorkItem[];
  };
  continuity: RunStateContinuity;
}

export interface RunStateCapsuleEnvelope {
  schemaVersion: "toadaid.run-state-envelope.v1";
  capsule: RunStateCapsule;
  capsuleSha256: string;
}

export interface CreateRunStateCapsuleInput {
  runId: string;
  createdAt: string;
  objective: RunObjectiveState;
  phase: string;
  authoritySnapshot: RunAuthoritySnapshot;
  evidenceRefs?: readonly RunEvidenceReference[];
  artifactRefs?: readonly RunArtifactReference[];
  work?: Partial<RunStateCapsule["work"]>;
}

export interface RunStateCheckpointUpdate {
  updatedAt: string;
  reason: Exclude<RunContinuityReason, "INITIAL" | "RESTART">;
  objective?: RunObjectiveState;
  phase?: string;
  evidenceRefs?: readonly RunEvidenceReference[];
  artifactRefs?: readonly RunArtifactReference[];
  work?: Partial<RunStateCapsule["work"]>;
}

export type RunResumeAuthorityReason =
  | "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY"
  | "BLOCKED_IN_SNAPSHOT"
  | "BLOCKED_BY_CURRENT_POLICY"
  | "UNKNOWN_IN_SNAPSHOT"
  | "UNKNOWN_IN_CURRENT_POLICY";

export interface RunResumeAuthorityDecision {
  schemaVersion: "toadaid.run-resume-authority.v1";
  capabilityId: string;
  decision: CapabilityEffectiveDecision;
  reason: RunResumeAuthorityReason;
  snapshotDecision: CapabilityEffectiveDecision | null;
  currentDecision: CapabilityEffectiveDecision | null;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const MAX_OBJECTIVE_CHARS = 2_000;
const MAX_PHASE_CHARS = 256;
const MAX_ITEM_SUMMARY_CHARS = 1_000;
const MAX_LOCATOR_CHARS = 2_048;
const MAX_ITEMS_PER_BUCKET = 500;
const MAX_REFERENCES = 1_000;

function assertBoundedString(value: string, label: string, maximum: number): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${label} must not be empty`);
  if (normalized.length > maximum) throw new RangeError(`${label} must be at most ${maximum} characters`);
  return normalized;
}

function assertId(value: string, label: string): string {
  if (!ID_PATTERN.test(value)) throw new TypeError(`${label} must match ${ID_PATTERN.source}`);
  return value;
}

function assertIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must not be empty`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function normalizeSha256(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (!SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256 hex digest`);
  return value;
}

function normalizeObjective(objective: RunObjectiveState): RunObjectiveState {
  const allowed: readonly RunObjectiveStatus[] = ["ACTIVE", "BLOCKED", "COMPLETE", "SUPERSEDED"];
  if (!allowed.includes(objective.status)) throw new TypeError(`invalid objective status: ${String(objective.status)}`);
  return Object.freeze({
    summary: assertBoundedString(objective.summary, "objective.summary", MAX_OBJECTIVE_CHARS),
    status: objective.status,
  });
}

function normalizeWorkItems(items: readonly RunWorkItem[] | undefined, label: string): readonly RunWorkItem[] {
  const resolved = items ?? [];
  if (resolved.length > MAX_ITEMS_PER_BUCKET) throw new RangeError(`${label} exceeds ${MAX_ITEMS_PER_BUCKET} items`);
  return Object.freeze(
    resolved
      .map((item, index) =>
        Object.freeze({
          id: assertId(item.id, `${label}[${index}].id`),
          summary: assertBoundedString(item.summary, `${label}[${index}].summary`, MAX_ITEM_SUMMARY_CHARS),
        }),
      )
      .sort((a, b) => a.id.localeCompare(b.id)),
  );
}

function normalizeReference<T extends RunEvidenceReference | RunArtifactReference>(
  reference: T,
  label: string,
): T {
  const sha256 = normalizeSha256(reference.sha256, `${label}.sha256`);
  const base = {
    id: assertId(reference.id, `${label}.id`),
    locator: assertBoundedString(reference.locator, `${label}.locator`, MAX_LOCATOR_CHARS),
    ...(sha256 === undefined ? {} : { sha256 }),
  };
  return Object.freeze(base) as T;
}

function normalizeReferences<T extends RunEvidenceReference | RunArtifactReference>(
  references: readonly T[] | undefined,
  label: string,
): readonly T[] {
  const resolved = references ?? [];
  if (resolved.length > MAX_REFERENCES) throw new RangeError(`${label} exceeds ${MAX_REFERENCES} references`);
  const seen = new Set<string>();
  const normalized = resolved.map((reference, index) => {
    const value = normalizeReference(reference, `${label}[${index}]`);
    if (seen.has(value.id)) throw new TypeError(`duplicate ${label} id: ${value.id}`);
    seen.add(value.id);
    return value;
  });
  return Object.freeze(normalized.sort((a, b) => a.id.localeCompare(b.id)));
}

function cloneAuthorityDecision(decision: CapabilityAuthorityDecision): CapabilityAuthorityDecision {
  if (decision.schemaVersion !== "toadaid.capability-authority-decision.v1") {
    throw new TypeError(`invalid authority decision schema for ${decision.capabilityId}`);
  }
  if (!CAPABILITY_ID_PATTERN.test(decision.capabilityId)) {
    throw new TypeError(`invalid authority capability id: ${decision.capabilityId}`);
  }
  if (typeof decision.installed !== "boolean") {
    throw new TypeError(`authority installed flag must be boolean: ${decision.capabilityId}`);
  }
  if (decision.decision !== "ALLOW" && decision.decision !== "BLOCK") {
    throw new TypeError(`invalid authority decision for ${decision.capabilityId}`);
  }
  const allowedReasons = new Set([
    "AUTHORIZED_BY_POLICY",
    "BLOCKED_BY_POLICY",
    "MANIFEST_DEFAULT",
    "UNKNOWN_CAPABILITY",
  ]);
  if (!allowedReasons.has(decision.reason)) {
    throw new TypeError(`invalid authority reason for ${decision.capabilityId}`);
  }
  if (!Array.isArray(decision.trace)) {
    throw new TypeError(`authority trace must be an array: ${decision.capabilityId}`);
  }
  return Object.freeze({
    ...decision,
    trace: Object.freeze(decision.trace.map((entry) => Object.freeze({ ...entry }))),
  });
}

function normalizeAuthoritySnapshot(snapshot: RunAuthoritySnapshot): RunAuthoritySnapshot {
  const capturedAt = assertIsoTimestamp(snapshot.capturedAt, "authoritySnapshot.capturedAt");
  const seen = new Set<string>();
  const decisions = snapshot.decisions.map((decision) => {
    if (seen.has(decision.capabilityId)) throw new TypeError(`duplicate authority capability: ${decision.capabilityId}`);
    seen.add(decision.capabilityId);
    return cloneAuthorityDecision(decision);
  });
  decisions.sort((a, b) => a.capabilityId.localeCompare(b.capabilityId));
  return Object.freeze({ capturedAt, decisions: Object.freeze(decisions) });
}

function validateWorkUniqueness(work: RunStateCapsule["work"]): void {
  const seen = new Map<string, string>();
  for (const [bucket, items] of Object.entries(work) as Array<[keyof RunStateCapsule["work"], readonly RunWorkItem[]]>) {
    for (const item of items) {
      const previous = seen.get(item.id);
      if (previous) throw new TypeError(`work item ${item.id} appears in both ${previous} and ${bucket}`);
      seen.set(item.id, bucket);
    }
  }
}

function normalizeWork(
  work: Partial<RunStateCapsule["work"]> | undefined,
  fallback?: RunStateCapsule["work"],
): RunStateCapsule["work"] {
  const normalized = Object.freeze({
    completed: normalizeWorkItems(work?.completed ?? fallback?.completed, "work.completed"),
    pending: normalizeWorkItems(work?.pending ?? fallback?.pending, "work.pending"),
    blocked: normalizeWorkItems(work?.blocked ?? fallback?.blocked, "work.blocked"),
  });
  validateWorkUniqueness(normalized);
  return normalized;
}

function freezeCapsule(capsule: RunStateCapsule): RunStateCapsule {
  return Object.freeze({
    ...capsule,
    objective: Object.freeze({ ...capsule.objective }),
    authoritySnapshot: Object.freeze({
      ...capsule.authoritySnapshot,
      decisions: Object.freeze([...capsule.authoritySnapshot.decisions]),
    }),
    evidenceRefs: Object.freeze([...capsule.evidenceRefs]),
    artifactRefs: Object.freeze([...capsule.artifactRefs]),
    work: Object.freeze({
      completed: Object.freeze([...capsule.work.completed]),
      pending: Object.freeze([...capsule.work.pending]),
      blocked: Object.freeze([...capsule.work.blocked]),
    }),
    continuity: Object.freeze({ ...capsule.continuity }),
  });
}

export function createRunStateCapsule(input: CreateRunStateCapsuleInput): RunStateCapsule {
  const createdAt = assertIsoTimestamp(input.createdAt, "createdAt");
  return freezeCapsule({
    schemaVersion: "toadaid.run-state-capsule.v1",
    runId: assertId(input.runId, "runId"),
    revision: 0,
    createdAt,
    updatedAt: createdAt,
    objective: normalizeObjective(input.objective),
    phase: assertBoundedString(input.phase, "phase", MAX_PHASE_CHARS),
    authoritySnapshot: normalizeAuthoritySnapshot(input.authoritySnapshot),
    evidenceRefs: normalizeReferences(input.evidenceRefs, "evidenceRefs"),
    artifactRefs: normalizeReferences(input.artifactRefs, "artifactRefs"),
    work: normalizeWork(input.work),
    continuity: Object.freeze({
      generation: 0,
      reason: "INITIAL",
      previousCapsuleSha256: null,
    }),
  });
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("run-state capsule contains a non-serializable value");
}

export function canonicalRunStateCapsule(capsule: RunStateCapsule): string {
  return canonicalJson(capsule);
}

export function runStateCapsuleSha256(capsule: RunStateCapsule): string {
  return createHash("sha256").update(canonicalRunStateCapsule(capsule)).digest("hex");
}

export function sealRunStateCapsule(capsule: RunStateCapsule): RunStateCapsuleEnvelope {
  validateRunStateCapsule(capsule);
  return Object.freeze({
    schemaVersion: "toadaid.run-state-envelope.v1",
    capsule,
    capsuleSha256: runStateCapsuleSha256(capsule),
  });
}

export function serializeRunStateCapsule(capsule: RunStateCapsule): string {
  return JSON.stringify(sealRunStateCapsule(capsule));
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

export function parseRunStateCapsule(serialized: string): RunStateCapsule {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("run-state envelope must be valid JSON");
  }
  const envelope = objectValue(parsed, "run-state envelope");
  if (envelope.schemaVersion !== "toadaid.run-state-envelope.v1") throw new TypeError("invalid run-state envelope schema");
  if (typeof envelope.capsuleSha256 !== "string" || !SHA256_PATTERN.test(envelope.capsuleSha256)) {
    throw new TypeError("run-state envelope capsuleSha256 is invalid");
  }
  const capsule = normalizeParsedCapsule(envelope.capsule);
  const actual = runStateCapsuleSha256(capsule);
  if (actual !== envelope.capsuleSha256) throw new Error("run-state capsule integrity mismatch");
  return capsule;
}

function normalizeParsedCapsule(value: unknown): RunStateCapsule {
  const raw = objectValue(value, "run-state capsule") as unknown as RunStateCapsule;
  if (raw.schemaVersion !== "toadaid.run-state-capsule.v1") throw new TypeError("invalid run-state capsule schema");
  if (!Number.isInteger(raw.revision) || raw.revision < 0) throw new TypeError("run-state revision must be a non-negative integer");
  if (!raw.continuity || !Number.isInteger(raw.continuity.generation) || raw.continuity.generation < 0) {
    throw new TypeError("run-state continuity generation must be a non-negative integer");
  }
  if (raw.continuity.generation !== raw.revision) throw new TypeError("run-state continuity generation must equal revision");
  const continuityReasons: readonly RunContinuityReason[] = ["INITIAL", "CHECKPOINT", "COMPACTION", "RESTART", "MANUAL"];
  if (!continuityReasons.includes(raw.continuity.reason)) throw new TypeError("invalid run-state continuity reason");
  if (raw.continuity.reason === "INITIAL" && raw.revision !== 0) throw new TypeError("INITIAL continuity is only valid at revision 0");
  if (raw.revision === 0 && raw.continuity.previousCapsuleSha256 !== null) throw new TypeError("initial capsule cannot have a predecessor digest");
  if (raw.revision > 0 && (typeof raw.continuity.previousCapsuleSha256 !== "string" || !SHA256_PATTERN.test(raw.continuity.previousCapsuleSha256))) {
    throw new TypeError("non-initial capsule requires previousCapsuleSha256");
  }

  const createdAt = assertIsoTimestamp(raw.createdAt, "createdAt");
  const updatedAt = assertIsoTimestamp(raw.updatedAt, "updatedAt");
  if (new Date(updatedAt).getTime() < new Date(createdAt).getTime()) throw new TypeError("updatedAt cannot precede createdAt");

  return freezeCapsule({
    schemaVersion: "toadaid.run-state-capsule.v1",
    runId: assertId(raw.runId, "runId"),
    revision: raw.revision,
    createdAt,
    updatedAt,
    objective: normalizeObjective(raw.objective),
    phase: assertBoundedString(raw.phase, "phase", MAX_PHASE_CHARS),
    authoritySnapshot: normalizeAuthoritySnapshot(raw.authoritySnapshot),
    evidenceRefs: normalizeReferences(raw.evidenceRefs, "evidenceRefs"),
    artifactRefs: normalizeReferences(raw.artifactRefs, "artifactRefs"),
    work: normalizeWork(raw.work),
    continuity: Object.freeze({ ...raw.continuity }),
  });
}

export function validateRunStateCapsule(capsule: RunStateCapsule): RunStateCapsule {
  return normalizeParsedCapsule(capsule);
}

export function checkpointRunStateCapsule(
  previous: RunStateCapsule,
  update: RunStateCheckpointUpdate,
): RunStateCapsule {
  const canonicalPrevious = validateRunStateCapsule(previous);
  const updatedAt = assertIsoTimestamp(update.updatedAt, "updatedAt");
  if (new Date(updatedAt).getTime() < new Date(canonicalPrevious.updatedAt).getTime()) {
    throw new TypeError("checkpoint updatedAt cannot move backwards");
  }
  if (update.reason !== "CHECKPOINT" && update.reason !== "COMPACTION" && update.reason !== "MANUAL") {
    throw new TypeError(`invalid checkpoint reason: ${String(update.reason)}`);
  }

  return freezeCapsule({
    ...canonicalPrevious,
    revision: canonicalPrevious.revision + 1,
    updatedAt,
    objective: update.objective ? normalizeObjective(update.objective) : canonicalPrevious.objective,
    phase: update.phase ? assertBoundedString(update.phase, "phase", MAX_PHASE_CHARS) : canonicalPrevious.phase,
    evidenceRefs: update.evidenceRefs ? normalizeReferences(update.evidenceRefs, "evidenceRefs") : canonicalPrevious.evidenceRefs,
    artifactRefs: update.artifactRefs ? normalizeReferences(update.artifactRefs, "artifactRefs") : canonicalPrevious.artifactRefs,
    work: normalizeWork(update.work, canonicalPrevious.work),
    authoritySnapshot: canonicalPrevious.authoritySnapshot,
    continuity: Object.freeze({
      generation: canonicalPrevious.continuity.generation + 1,
      reason: update.reason,
      previousCapsuleSha256: runStateCapsuleSha256(canonicalPrevious),
    }),
  });
}

export function resumeRunStateCapsule(serialized: string, resumedAt: string): RunStateCapsule {
  const previous = parseRunStateCapsule(serialized);
  const updatedAt = assertIsoTimestamp(resumedAt, "resumedAt");
  if (new Date(updatedAt).getTime() < new Date(previous.updatedAt).getTime()) {
    throw new TypeError("resumedAt cannot move backwards");
  }
  return freezeCapsule({
    ...previous,
    revision: previous.revision + 1,
    updatedAt,
    authoritySnapshot: previous.authoritySnapshot,
    continuity: Object.freeze({
      generation: previous.continuity.generation + 1,
      reason: "RESTART",
      previousCapsuleSha256: runStateCapsuleSha256(previous),
    }),
  });
}

export function resolveResumeCapabilityAuthority(
  capabilityId: string,
  capsule: RunStateCapsule,
  currentAuthority: readonly CapabilityAuthorityDecision[],
): RunResumeAuthorityDecision {
  if (!CAPABILITY_ID_PATTERN.test(capabilityId)) throw new TypeError(`invalid capabilityId: ${capabilityId}`);
  const canonical = validateRunStateCapsule(capsule);
  const currentSeen = new Set<string>();
  const currentNormalized = currentAuthority.map((authority) => {
    if (currentSeen.has(authority.capabilityId)) throw new TypeError(`duplicate current authority capability: ${authority.capabilityId}`);
    currentSeen.add(authority.capabilityId);
    return cloneAuthorityDecision(authority);
  });
  const snapshot = canonical.authoritySnapshot.decisions.find((decision) => decision.capabilityId === capabilityId);
  const current = currentNormalized.find((decision) => decision.capabilityId === capabilityId);

  let decision: CapabilityEffectiveDecision = "BLOCK";
  let reason: RunResumeAuthorityReason;
  if (!snapshot) {
    reason = "UNKNOWN_IN_SNAPSHOT";
  } else if (!current) {
    reason = "UNKNOWN_IN_CURRENT_POLICY";
  } else if (snapshot.decision !== "ALLOW") {
    reason = "BLOCKED_IN_SNAPSHOT";
  } else if (current.decision !== "ALLOW") {
    reason = "BLOCKED_BY_CURRENT_POLICY";
  } else {
    decision = "ALLOW";
    reason = "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY";
  }

  return Object.freeze({
    schemaVersion: "toadaid.run-resume-authority.v1",
    capabilityId,
    decision,
    reason,
    snapshotDecision: snapshot?.decision ?? null,
    currentDecision: current?.decision ?? null,
  });
}

export function assertRunStatePredecessor(
  previous: RunStateCapsule,
  next: RunStateCapsule,
): void {
  const canonicalPrevious = validateRunStateCapsule(previous);
  const canonicalNext = validateRunStateCapsule(next);
  if (canonicalNext.runId !== canonicalPrevious.runId) throw new Error("run-state predecessor runId mismatch");
  if (canonicalNext.createdAt !== canonicalPrevious.createdAt) throw new Error("run-state predecessor createdAt mismatch");
  if (canonicalNext.revision !== canonicalPrevious.revision + 1) throw new Error("run-state revision is not contiguous");
  if (canonicalNext.continuity.generation !== canonicalPrevious.continuity.generation + 1) {
    throw new Error("run-state continuity generation is not contiguous");
  }
  if (canonicalNext.continuity.previousCapsuleSha256 !== runStateCapsuleSha256(canonicalPrevious)) {
    throw new Error("run-state predecessor digest mismatch");
  }
  if (canonicalJson(canonicalNext.authoritySnapshot) !== canonicalJson(canonicalPrevious.authoritySnapshot)) {
    throw new Error("run-state automatic continuity cannot rewrite authority snapshot");
  }
}
