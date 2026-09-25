import { randomUUID } from "node:crypto";
import { validateCapabilityInvocationEnvelope } from "./capabilityInvocationRecord.js";
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";
import {
  boundedId,
  canonicalIso,
  deterministicIdempotencyKey,
  normalizeBinding,
  normalizeEvidenceRefs,
  normalizeGuarantee,
  reasonCode,
  sha,
  sha256,
  SHA256_PATTERN,
} from "./replayFenceSchema.js";
import type {
  CreateReplayFenceInput,
  OpenReplayReconciliationInput,
  ReplayFenceBinding,
  ReplayFenceEnvelope,
  ReplayFenceRecord,
  ReplayFenceRuntime,
  ReplayReconciliationEnvelope,
  ReplayReconciliationRecord,
  ReplayRetryAuthorization,
  ResolveReplayReconciliationInput,
} from "./replayFenceTypes.js";

export type * from "./replayFenceTypes.js";
export { deterministicIdempotencyKey, createContractBoundIdempotencyGuarantee } from "./replayFenceSchema.js";

function nowIso(value: string | undefined, runtime?: ReplayFenceRuntime, label = "time"): string {
  return canonicalIso(value, label, runtime?.now ?? (() => new Date()));
}

function bindingFromInvocation(invocation: CapabilityInvocationEnvelope): ReplayFenceBinding {
  const current = validateCapabilityInvocationEnvelope(invocation);
  return normalizeBinding({
    runId: current.record.runId,
    invocationId: current.record.invocationId,
    capabilityId: current.record.capabilityId,
    intentSha256: current.record.request.intentSha256,
  });
}

function assertBinding(fence: ReplayFenceEnvelope, invocation: CapabilityInvocationEnvelope): void {
  const binding = bindingFromInvocation(invocation);
  if (sha256(binding) !== sha256(fence.record.binding)) throw new Error("replay fence does not match capability invocation");
}

export function replayFenceRecordSha256(record: ReplayFenceRecord): string { return sha256(record); }

export function validateReplayFenceRecord(record: ReplayFenceRecord): ReplayFenceRecord {
  if (record.schemaVersion !== "toadaid.replay-fence.v1") throw new TypeError("unsupported replay fence schemaVersion");
  const binding = normalizeBinding(record.binding);
  if (!new Set(["SAFE_READ", "IDEMPOTENT_WRITE", "NON_REPLAYABLE"]).has(record.replayClass)) throw new TypeError("replayClass is invalid");
  const guarantee = normalizeGuarantee(record.guarantee);
  if (record.replayClass === "IDEMPOTENT_WRITE" && !guarantee) throw new TypeError("IDEMPOTENT_WRITE requires an explicit idempotency guarantee");
  if (record.replayClass !== "IDEMPOTENT_WRITE" && guarantee) throw new TypeError("idempotency guarantee is valid only for IDEMPOTENT_WRITE");
  if (guarantee && (guarantee.invocationId !== binding.invocationId || guarantee.capabilityId !== binding.capabilityId)) throw new Error("idempotency guarantee does not match invocation binding");
  const key = sha(record.idempotencyKey, "idempotencyKey")!;
  if (key !== deterministicIdempotencyKey(binding)) throw new Error("replay fence idempotency key mismatch");
  const createdAt = canonicalIso(record.createdAt, "createdAt");
  return Object.freeze({ ...record, binding, guarantee, idempotencyKey: key, createdAt });
}

export function sealReplayFence(record: ReplayFenceRecord): ReplayFenceEnvelope {
  const normalized = validateReplayFenceRecord(record);
  return Object.freeze({ schemaVersion: "toadaid.replay-fence-envelope.v1", record: normalized, recordSha256: replayFenceRecordSha256(normalized) });
}

export function validateReplayFenceEnvelope(envelope: ReplayFenceEnvelope): ReplayFenceEnvelope {
  if (envelope.schemaVersion !== "toadaid.replay-fence-envelope.v1") throw new TypeError("unsupported replay fence envelope schemaVersion");
  const record = validateReplayFenceRecord(envelope.record);
  if (!SHA256_PATTERN.test(envelope.recordSha256) || replayFenceRecordSha256(record) !== envelope.recordSha256) throw new Error("replay fence integrity mismatch");
  return Object.freeze({ ...envelope, record });
}

export function createReplayFence(
  invocation: CapabilityInvocationEnvelope,
  input: CreateReplayFenceInput,
  runtime?: ReplayFenceRuntime,
): ReplayFenceEnvelope {
  const current = validateCapabilityInvocationEnvelope(invocation);
  if (current.record.status !== "REQUESTED" && current.record.status !== "AUTHORIZED") throw new Error("replay fence must be created before invocation start");
  const binding = bindingFromInvocation(current);
  return sealReplayFence({
    schemaVersion: "toadaid.replay-fence.v1",
    binding,
    replayClass: input.replayClass,
    idempotencyKey: deterministicIdempotencyKey(binding),
    guarantee: normalizeGuarantee(input.guarantee),
    createdAt: nowIso(input.createdAt, runtime, "createdAt"),
  });
}

function reconciliationCore(record: ReplayReconciliationRecord): Omit<ReplayReconciliationRecord, "continuity"> & { continuity: { previousRecordSha256: string | null } } {
  return record;
}

export function replayReconciliationRecordSha256(record: ReplayReconciliationRecord): string { return sha256(reconciliationCore(record)); }

export function validateReplayReconciliationRecord(record: ReplayReconciliationRecord): ReplayReconciliationRecord {
  if (record.schemaVersion !== "toadaid.replay-reconciliation.v1") throw new TypeError("unsupported replay reconciliation schemaVersion");
  boundedId(record.reconciliationId, "reconciliationId");
  if (!Number.isSafeInteger(record.revision) || record.revision < 0 || record.revision > 1) throw new RangeError("reconciliation revision is invalid");
  if (record.status !== "OPEN" && record.status !== "RESOLVED") throw new TypeError("reconciliation status is invalid");
  sha(record.replayFenceSha256, "replayFenceSha256");
  sha(record.invocationRecordSha256, "invocationRecordSha256");
  const binding = normalizeBinding(record.binding);
  if (!new Set(["SAFE_READ", "IDEMPOTENT_WRITE", "NON_REPLAYABLE"]).has(record.replayClass)) throw new TypeError("replayClass is invalid");
  if (sha(record.idempotencyKey, "idempotencyKey") !== deterministicIdempotencyKey(binding)) throw new Error("reconciliation idempotency key mismatch");
  const openedAt = canonicalIso(record.openedAt, "openedAt");
  reasonCode(record.reasonCode);
  const evidenceRefs = normalizeEvidenceRefs(record.evidenceRefs);
  const proofRefs = normalizeEvidenceRefs(record.proofRefs);
  if (record.revision === 0) {
    if (record.status !== "OPEN" || record.finding !== null || record.proofSha256 !== null || record.resolvedAt !== null || record.continuity.previousRecordSha256 !== null) throw new TypeError("initial reconciliation shape is invalid");
    if (record.disposition !== "BLOCKED_PENDING_RECONCILIATION") throw new TypeError("open reconciliation must block replay");
  } else {
    if (record.status !== "RESOLVED" || record.finding === null || record.resolvedAt === null || !record.continuity.previousRecordSha256) throw new TypeError("resolved reconciliation shape is invalid");
    sha(record.continuity.previousRecordSha256, "continuity.previousRecordSha256");
    canonicalIso(record.resolvedAt, "resolvedAt");
    if (Date.parse(record.resolvedAt) < Date.parse(openedAt)) throw new RangeError("resolvedAt is earlier than openedAt");
    if (record.finding !== "STILL_UNKNOWN" && record.proofSha256 === null) throw new TypeError("confirmed reconciliation finding requires proofSha256");
    if (record.proofSha256 !== null) sha(record.proofSha256, "proofSha256");
  }
  return Object.freeze({ ...record, binding, evidenceRefs, proofRefs });
}

export function sealReplayReconciliation(record: ReplayReconciliationRecord): ReplayReconciliationEnvelope {
  const normalized = validateReplayReconciliationRecord(record);
  return Object.freeze({ schemaVersion: "toadaid.replay-reconciliation-envelope.v1", record: normalized, recordSha256: replayReconciliationRecordSha256(normalized) });
}

export function validateReplayReconciliationEnvelope(envelope: ReplayReconciliationEnvelope): ReplayReconciliationEnvelope {
  if (envelope.schemaVersion !== "toadaid.replay-reconciliation-envelope.v1") throw new TypeError("unsupported replay reconciliation envelope schemaVersion");
  const record = validateReplayReconciliationRecord(envelope.record);
  if (!SHA256_PATTERN.test(envelope.recordSha256) || replayReconciliationRecordSha256(record) !== envelope.recordSha256) throw new Error("replay reconciliation integrity mismatch");
  return Object.freeze({ ...envelope, record });
}

export function openReplayReconciliation(
  fenceInput: ReplayFenceEnvelope,
  invocation: CapabilityInvocationEnvelope,
  input: OpenReplayReconciliationInput,
  runtime?: ReplayFenceRuntime,
): ReplayReconciliationEnvelope {
  const fence = validateReplayFenceEnvelope(fenceInput);
  const current = validateCapabilityInvocationEnvelope(invocation);
  assertBinding(fence, current);
  if (current.record.status !== "STARTED" && current.record.status !== "CANCEL_REQUESTED") {
    throw new Error("reconciliation requires an active invocation with an uncertain external outcome");
  }
  const openedAt = nowIso(input.openedAt, runtime, "openedAt");
  return sealReplayReconciliation({
    schemaVersion: "toadaid.replay-reconciliation.v1",
    reconciliationId: boundedId(input.reconciliationId ?? runtime?.randomId?.() ?? randomUUID(), "reconciliationId"),
    revision: 0,
    status: "OPEN",
    replayFenceSha256: fence.recordSha256,
    invocationRecordSha256: current.recordSha256,
    binding: fence.record.binding,
    replayClass: fence.record.replayClass,
    idempotencyKey: fence.record.idempotencyKey,
    openedAt,
    reasonCode: reasonCode(input.reasonCode),
    evidenceRefs: normalizeEvidenceRefs(input.evidenceRefs),
    finding: null,
    proofSha256: null,
    proofRefs: Object.freeze([]),
    disposition: "BLOCKED_PENDING_RECONCILIATION",
    resolvedAt: null,
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

function resolvedDisposition(record: ReplayReconciliationRecord, input: ResolveReplayReconciliationInput): ReplayReconciliationRecord["disposition"] {
  if (input.finding === "CONFIRMED_EXECUTED") return "DO_NOT_RETRY";
  if (record.replayClass === "NON_REPLAYABLE") return input.finding === "CONFIRMED_NOT_EXECUTED" ? "NEW_INVOCATION_REQUIRED" : "DO_NOT_RETRY";
  if (record.replayClass === "SAFE_READ") return "RETRY_ALLOWED";
  if (input.finding === "CONFIRMED_NOT_EXECUTED" && input.proofSha256) return "RETRY_ALLOWED";
  return "BLOCKED_PENDING_RECONCILIATION";
}

export function resolveReplayReconciliation(
  envelope: ReplayReconciliationEnvelope,
  input: ResolveReplayReconciliationInput,
  runtime?: ReplayFenceRuntime,
): ReplayReconciliationEnvelope {
  const current = validateReplayReconciliationEnvelope(envelope);
  if (current.record.status !== "OPEN") throw new Error("replay reconciliation is already resolved");
  const resolvedAt = nowIso(input.resolvedAt, runtime, "resolvedAt");
  const proof = input.proofSha256 == null ? null : sha(input.proofSha256, "proofSha256");
  const next = {
    ...current.record,
    revision: 1,
    status: "RESOLVED" as const,
    finding: input.finding,
    proofSha256: proof,
    proofRefs: normalizeEvidenceRefs(input.proofRefs),
    disposition: resolvedDisposition(current.record, { ...input, proofSha256: proof }),
    resolvedAt,
    continuity: Object.freeze({ previousRecordSha256: current.recordSha256 }),
  };
  return sealReplayReconciliation(next);
}

export function createReplayRetryAuthorization(
  fenceInput: ReplayFenceEnvelope,
  reconciliationInput: ReplayReconciliationEnvelope,
  invocation: CapabilityInvocationEnvelope,
  runtime?: ReplayFenceRuntime,
): ReplayRetryAuthorization {
  const fence = validateReplayFenceEnvelope(fenceInput);
  const reconciliation = validateReplayReconciliationEnvelope(reconciliationInput);
  const current = validateCapabilityInvocationEnvelope(invocation);
  assertBinding(fence, current);
  if (current.recordSha256 !== reconciliation.record.invocationRecordSha256) throw new Error("invocation record changed since reconciliation opened");
  if (reconciliation.record.replayFenceSha256 !== fence.recordSha256) throw new Error("reconciliation is not bound to replay fence");
  if (reconciliation.record.status !== "RESOLVED" || reconciliation.record.disposition !== "RETRY_ALLOWED") throw new Error("reconciliation does not authorize replay");
  if (reconciliation.record.idempotencyKey !== fence.record.idempotencyKey) throw new Error("replay idempotency key changed");
  if (fence.record.replayClass === "NON_REPLAYABLE") throw new Error("NON_REPLAYABLE invocation can never receive replay authorization");
  if (fence.record.replayClass === "IDEMPOTENT_WRITE") {
    if (!fence.record.guarantee) throw new Error("idempotent write is missing guarantee");
    if (reconciliation.record.finding !== "CONFIRMED_NOT_EXECUTED" || reconciliation.record.proofSha256 === null) throw new Error("idempotent write replay requires confirmed-not-executed proof");
  }
  return Object.freeze({
    schemaVersion: "toadaid.replay-retry-authorization.v1",
    reconciliationId: reconciliation.record.reconciliationId,
    replayFenceSha256: fence.recordSha256,
    reconciliationSha256: reconciliation.recordSha256,
    invocationId: fence.record.binding.invocationId,
    replayClass: fence.record.replayClass,
    disposition: reconciliation.record.disposition,
    idempotencyKey: fence.record.idempotencyKey,
    authorizedAt: nowIso(undefined, runtime, "authorizedAt"),
  });
}

export function serializeReplayFence(envelope: ReplayFenceEnvelope): string { return JSON.stringify(validateReplayFenceEnvelope(envelope)); }
export function parseReplayFence(serialized: string): ReplayFenceEnvelope {
  let parsed: unknown; try { parsed = JSON.parse(serialized); } catch { throw new TypeError("replay fence must be valid JSON"); }
  return validateReplayFenceEnvelope(parsed as ReplayFenceEnvelope);
}
export function serializeReplayReconciliation(envelope: ReplayReconciliationEnvelope): string { return JSON.stringify(validateReplayReconciliationEnvelope(envelope)); }
export function parseReplayReconciliation(serialized: string): ReplayReconciliationEnvelope {
  let parsed: unknown; try { parsed = JSON.parse(serialized); } catch { throw new TypeError("replay reconciliation must be valid JSON"); }
  return validateReplayReconciliationEnvelope(parsed as ReplayReconciliationEnvelope);
}
