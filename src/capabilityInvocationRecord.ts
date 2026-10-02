import { randomUUID } from "node:crypto";

import { resolveCapabilityAuthority, type CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import {
  CAPABILITY_ID_PATTERN,
  SHA256_PATTERN,
  boundedId,
  canonicalIso,
  capabilityId,
  freezeInvocationRecord,
  managerId,
  normalizeEvidenceRefs,
  phaseName,
  reasonCode,
  sha,
  sha256,
  toolName,
} from "./invocationSchema.js";
import type {
  CapabilityInvocationEnvelope,
  CapabilityInvocationPolicyContext,
  CapabilityInvocationProgressReceipt,
  CapabilityInvocationRecord,
  CapabilityInvocationResumeAssessment,
  CapabilityInvocationTransitionRuntime,
  CreateCapabilityInvocationInput,
} from "./invocationTypes.js";

export type {
  CapabilityInvocationAuthorityEvidence,
  CapabilityInvocationCancellationEvidence,
  CapabilityInvocationCompletedOutcome,
  CapabilityInvocationContinuity,
  CapabilityInvocationEnvelope,
  CapabilityInvocationEvidenceReference,
  CapabilityInvocationFailedOutcome,
  CapabilityInvocationExecutionTruth,
  CapabilityInvocationOutcome,
  CapabilityInvocationReconciledOutcome,
  CapabilityInvocationReconciliationBinding,
  CapabilityInvocationReconciliationFinding,
  CapabilityInvocationReplayDisposition,
  CapabilityInvocationPolicyContext,
  CapabilityInvocationProgressReceipt,
  CapabilityInvocationRecord,
  CapabilityInvocationRequestEvidence,
  CapabilityInvocationResumeAssessment,
  CapabilityInvocationResumeDecision,
  CapabilityInvocationStartEvidence,
  CapabilityInvocationStatus,
  CapabilityInvocationTransitionRuntime,
  CreateCapabilityInvocationInput,
} from "./invocationTypes.js";

function nowIso(runtime?: CapabilityInvocationTransitionRuntime): string {
  return canonicalIso(undefined, "now", runtime?.now ?? (() => new Date()));
}

function authorityEvidence(decision: CapabilityAuthorityDecision, checkedAt: string) {
  return Object.freeze({
    checkedAt,
    decision: decision.decision,
    reason: decision.reason,
    decisionSha256: sha256(decision),
  });
}

export function transitionCapabilityInvocation(previous: CapabilityInvocationEnvelope, next: Omit<CapabilityInvocationRecord, "revision" | "continuity">): CapabilityInvocationEnvelope {
  const prior = validateCapabilityInvocationEnvelope(previous);
  return sealCapabilityInvocationRecord({
    ...next,
    revision: prior.record.revision + 1,
    continuity: Object.freeze({ previousRecordSha256: prior.recordSha256 }),
  });
}

export function capabilityInvocationRecordSha256(record: CapabilityInvocationRecord): string {
  return sha256(record);
}

export function validateCapabilityInvocationRecord(record: CapabilityInvocationRecord): CapabilityInvocationRecord {
  if (record.schemaVersion !== "toadaid.capability-invocation.v1") throw new TypeError("unsupported capability invocation schemaVersion");
  boundedId(record.invocationId, "invocationId");
  boundedId(record.runId, "runId");
  if (record.childTaskId !== null) boundedId(record.childTaskId, "childTaskId");
  capabilityId(record.capabilityId);
  toolName(record.toolName);
  if (record.externalToolCallId !== null) boundedId(record.externalToolCallId, "externalToolCallId");
  if (!Number.isSafeInteger(record.revision) || record.revision < 0 || record.revision > 32) throw new RangeError("revision is invalid");
  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) throw new RangeError("updatedAt is earlier than createdAt");
  sha(record.request.intentSha256, "request.intentSha256");
  sha(record.request.argumentsSha256, "request.argumentsSha256", true);
  const statuses = new Set([
    "REQUESTED",
    "AUTHORIZED",
    "REFUSED",
    "STARTED",
    "CANCEL_REQUESTED",
    "RECONCILIATION_REQUIRED",
    "COMPLETED",
    "FAILED",
    "RECONCILED",
  ]);
  if (!statuses.has(record.status)) throw new TypeError("invalid capability invocation status");

  if (record.revision === 0) {
    if (record.status !== "REQUESTED" || record.continuity.previousRecordSha256 !== null) throw new TypeError("initial invocation continuity is invalid");
  } else if (!record.continuity.previousRecordSha256 || !SHA256_PATTERN.test(record.continuity.previousRecordSha256)) {
    throw new TypeError("invocation predecessor SHA is invalid");
  }

  if (record.authorization) {
    canonicalIso(record.authorization.checkedAt, "authorization.checkedAt");
    if (record.authorization.decision !== "ALLOW" && record.authorization.decision !== "BLOCK") throw new TypeError("authorization decision is invalid");
    if (!new Set(["AUTHORIZED_BY_POLICY", "BLOCKED_BY_POLICY", "MANIFEST_DEFAULT", "UNKNOWN_CAPABILITY"]).has(record.authorization.reason)) throw new TypeError("authorization reason is invalid");
    sha(record.authorization.decisionSha256, "authorization.decisionSha256");
  }
  if (record.start) {
    canonicalIso(record.start.startedAt, "start.startedAt");
    managerId(record.start.managerId);
  }
  if (record.cancellation) {
    canonicalIso(record.cancellation.requestedAt, "cancellation.requestedAt");
    managerId(record.cancellation.managerId);
    reasonCode(record.cancellation.reasonCode);
  }
  if (record.reconciliation) {
    boundedId(record.reconciliation.reconciliationId, "reconciliation.reconciliationId");
    sha(record.reconciliation.replayFenceSha256, "reconciliation.replayFenceSha256");
    sha(record.reconciliation.openReconciliationSha256, "reconciliation.openReconciliationSha256");
    sha(record.reconciliation.invocationRecordSha256, "reconciliation.invocationRecordSha256");
    canonicalIso(record.reconciliation.openedAt, "reconciliation.openedAt");
  }
  if (record.outcome) {
    managerId(record.outcome.managerId);
    normalizeEvidenceRefs(record.outcome.evidenceRefs);
    if (record.outcome.kind === "COMPLETED") {
      canonicalIso(record.outcome.completedAt, "outcome.completedAt");
      sha(record.outcome.resultSha256, "outcome.resultSha256");
    } else if (record.outcome.kind === "FAILED") {
      canonicalIso(record.outcome.failedAt, "outcome.failedAt");
      if (record.outcome.errorClass.length < 1 || record.outcome.errorClass.length > 128) throw new TypeError("outcome.errorClass is invalid");
      sha(record.outcome.errorFingerprint, "outcome.errorFingerprint");
    } else {
      canonicalIso(record.outcome.reconciledAt, "outcome.reconciledAt");
      boundedId(record.outcome.reconciliationId, "outcome.reconciliationId");
      sha(record.outcome.reconciliationSha256, "outcome.reconciliationSha256");
      sha(record.outcome.replayFenceSha256, "outcome.replayFenceSha256");
      if (!new Set(["CONFIRMED_NOT_EXECUTED", "CONFIRMED_EXECUTED", "STILL_UNKNOWN"]).has(record.outcome.finding)) {
        throw new TypeError("outcome.finding is invalid");
      }
      if (!new Set(["RETRY_ALLOWED", "DO_NOT_RETRY", "NEW_INVOCATION_REQUIRED", "BLOCKED_PENDING_RECONCILIATION"]).has(record.outcome.disposition)) {
        throw new TypeError("outcome.disposition is invalid");
      }
      if (!new Set(["EXECUTED", "NOT_EXECUTED", "UNKNOWN"]).has(record.outcome.executionTruth)) {
        throw new TypeError("outcome.executionTruth is invalid");
      }
      const expectedTruth =
        record.outcome.finding === "CONFIRMED_EXECUTED"
          ? "EXECUTED"
          : record.outcome.finding === "CONFIRMED_NOT_EXECUTED"
            ? "NOT_EXECUTED"
            : "UNKNOWN";
      if (record.outcome.executionTruth !== expectedTruth) {
        throw new Error("reconciled execution truth contradicts reconciliation finding");
      }
      if (record.outcome.proofSha256 !== null) {
        sha(record.outcome.proofSha256, "outcome.proofSha256");
      }
      if (record.outcome.finding !== "STILL_UNKNOWN" && record.outcome.proofSha256 === null) {
        throw new TypeError("confirmed reconciled outcome requires proofSha256");
      }
    }
  }

  const hasReconciliation =
    record.reconciliation !== undefined &&
    record.reconciliation !== null;

  if (
    record.status === "RECONCILIATION_REQUIRED" &&
    record.reconciliation
  ) {
    if (
      record.reconciliation.invocationRecordSha256 !==
      record.continuity.previousRecordSha256
    ) {
      throw new Error(
        "H1 reconciliation lock predecessor SHA mismatch",
      );
    }
    if (record.reconciliation.openedAt !== updatedAt) {
      throw new Error(
        "H1 reconciliation lock openedAt must equal updatedAt",
      );
    }
  }

  if (
    record.status === "RECONCILED" &&
    record.reconciliation &&
    record.outcome?.kind === "RECONCILED"
  ) {
    if (
      record.outcome.reconciliationId !==
        record.reconciliation.reconciliationId ||
      record.outcome.replayFenceSha256 !==
        record.reconciliation.replayFenceSha256
    ) {
      throw new Error(
        "reconciled H1 outcome contradicts H1/X1 lock identity",
      );
    }
    if (record.outcome.reconciledAt !== updatedAt) {
      throw new Error(
        "reconciled H1 outcome time must equal updatedAt",
      );
    }
    if (
      Date.parse(record.outcome.reconciledAt) <
      Date.parse(record.reconciliation.openedAt)
    ) {
      throw new RangeError(
        "reconciled H1 outcome predates X1 open time",
      );
    }
  }

  const shapeError = (() => {
    switch (record.status) {
      case "REQUESTED": return record.authorization || record.start || record.cancellation || hasReconciliation || record.outcome ? "REQUESTED contains later lifecycle data" : null;
      case "AUTHORIZED": return !record.authorization || record.authorization.decision !== "ALLOW" || record.start || hasReconciliation || record.outcome ? "AUTHORIZED shape is invalid" : null;
      case "REFUSED": return !record.authorization || record.authorization.decision !== "BLOCK" || record.start || hasReconciliation || record.outcome ? "REFUSED shape is invalid" : null;
      case "STARTED": return !record.authorization || record.authorization.decision !== "ALLOW" || !record.start || record.cancellation || hasReconciliation || record.outcome ? "STARTED shape is invalid" : null;
      case "CANCEL_REQUESTED": return !record.start || !record.cancellation || hasReconciliation || record.outcome ? "CANCEL_REQUESTED shape is invalid" : null;
      case "RECONCILIATION_REQUIRED": return !record.start || !hasReconciliation || record.outcome ? "RECONCILIATION_REQUIRED shape is invalid" : null;
      case "COMPLETED": return !record.start || hasReconciliation || !record.outcome || record.outcome.kind !== "COMPLETED" ? "COMPLETED shape is invalid" : null;
      case "FAILED": return !record.start || hasReconciliation || !record.outcome || record.outcome.kind !== "FAILED" ? "FAILED shape is invalid" : null;
      case "RECONCILED": return !record.start || !hasReconciliation || !record.outcome || record.outcome.kind !== "RECONCILED" ? "RECONCILED shape is invalid" : null;
    }
  })();
  if (shapeError) throw new TypeError(shapeError);
  return freezeInvocationRecord(record);
}

export function sealCapabilityInvocationRecord(record: CapabilityInvocationRecord): CapabilityInvocationEnvelope {
  const normalized = validateCapabilityInvocationRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.capability-invocation-envelope.v1",
    record: normalized,
    recordSha256: capabilityInvocationRecordSha256(normalized),
  });
}

export function validateCapabilityInvocationEnvelope(envelope: CapabilityInvocationEnvelope): CapabilityInvocationEnvelope {
  if (envelope.schemaVersion !== "toadaid.capability-invocation-envelope.v1") throw new TypeError("unsupported capability invocation envelope schemaVersion");
  const record = validateCapabilityInvocationRecord(envelope.record);
  if (!SHA256_PATTERN.test(envelope.recordSha256) || capabilityInvocationRecordSha256(record) !== envelope.recordSha256) {
    throw new Error("capability invocation integrity mismatch");
  }
  return Object.freeze({ ...envelope, record });
}

export function createCapabilityInvocation(input: CreateCapabilityInvocationInput): CapabilityInvocationEnvelope {
  const createdAt = canonicalIso(input.createdAt, "createdAt");
  return sealCapabilityInvocationRecord({
    schemaVersion: "toadaid.capability-invocation.v1",
    invocationId: boundedId(input.invocationId ?? randomUUID(), "invocationId"),
    revision: 0,
    status: "REQUESTED",
    runId: boundedId(input.runId, "runId"),
    childTaskId: input.childTaskId == null ? null : boundedId(input.childTaskId, "childTaskId"),
    capabilityId: capabilityId(input.capabilityId),
    toolName: toolName(input.toolName),
    externalToolCallId: input.externalToolCallId == null ? null : boundedId(input.externalToolCallId, "externalToolCallId"),
    createdAt,
    updatedAt: createdAt,
    request: Object.freeze({
      intentSha256: sha(input.intentSha256, "intentSha256")!,
      argumentsSha256: sha(input.argumentsSha256, "argumentsSha256", true),
    }),
    authorization: null,
    start: null,
    cancellation: null,
    outcome: null,
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

