import { resolveCapabilityAuthority } from "./capabilityPolicy.js";
import {
  canonicalIso,
  managerId,
  normalizeEvidenceRefs,
  phaseName,
  reasonCode,
  sha,
  sha256,
} from "./invocationSchema.js";
import {
  transitionCapabilityInvocation,
  validateCapabilityInvocationEnvelope,
} from "./capabilityInvocationRecord.js";
import type {
  CapabilityInvocationEnvelope,
  CapabilityInvocationPolicyContext,
  CapabilityInvocationProgressReceipt,
  CapabilityInvocationResumeAssessment,
  CapabilityInvocationTransitionRuntime,
} from "./invocationTypes.js";

function nowIso(runtime?: CapabilityInvocationTransitionRuntime): string {
  return canonicalIso(undefined, "now", runtime?.now ?? (() => new Date()));
}

function authorityEvidence(decision: ReturnType<typeof resolveCapabilityAuthority>, checkedAt: string) {
  return Object.freeze({
    checkedAt,
    decision: decision.decision,
    reason: decision.reason,
    decisionSha256: sha256(decision),
  });
}
export {
  capabilityInvocationRecordSha256,
  createCapabilityInvocation,
  sealCapabilityInvocationRecord,
  validateCapabilityInvocationEnvelope,
  validateCapabilityInvocationRecord,
} from "./capabilityInvocationRecord.js";
export {
  beginCapabilityInvocationReconciliation,
  closeCapabilityInvocationReconciliation,
} from "./invocationReconciliation.js";
export type {
  OpenCapabilityInvocationReconciliationResult,
} from "./invocationReconciliation.js";
export type * from "./invocationTypes.js";

export function authorizeCapabilityInvocation(
  envelope: CapabilityInvocationEnvelope,
  policy: CapabilityInvocationPolicyContext,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "REQUESTED") throw new Error("only REQUESTED invocation may be authorized");
  const checkedAt = nowIso(runtime);
  const decision = resolveCapabilityAuthority(current.record.capabilityId, policy.manifest, policy.policyLayers);
  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: decision.decision === "ALLOW" ? "AUTHORIZED" : "REFUSED",
    updatedAt: checkedAt,
    authorization: authorityEvidence(decision, checkedAt),
  });
}

export function startCapabilityInvocation(
  envelope: CapabilityInvocationEnvelope,
  manager: string,
  policy: CapabilityInvocationPolicyContext,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "AUTHORIZED") throw new Error("only AUTHORIZED invocation may start");
  const checkedAt = nowIso(runtime);
  const decision = resolveCapabilityAuthority(current.record.capabilityId, policy.manifest, policy.policyLayers);
  if (decision.decision !== "ALLOW") {
    return transitionCapabilityInvocation(current, {
      ...current.record,
      status: "REFUSED",
      updatedAt: checkedAt,
      authorization: authorityEvidence(decision, checkedAt),
    });
  }
  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: "STARTED",
    updatedAt: checkedAt,
    authorization: authorityEvidence(decision, checkedAt),
    start: Object.freeze({ startedAt: checkedAt, managerId: managerId(manager) }),
  });
}

export function requestCapabilityInvocationCancellation(
  envelope: CapabilityInvocationEnvelope,
  manager: string,
  cancellationReasonCode: string,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "STARTED") throw new Error("only STARTED invocation may receive a cancellation request");
  const requestedAt = nowIso(runtime);
  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: "CANCEL_REQUESTED",
    updatedAt: requestedAt,
    cancellation: Object.freeze({ requestedAt, managerId: managerId(manager), reasonCode: reasonCode(cancellationReasonCode) }),
  });
}

export function completeCapabilityInvocation(
  envelope: CapabilityInvocationEnvelope,
  manager: string,
  resultSha256: string,
  evidenceRefs?: readonly { id: string; sha256?: string }[],
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "STARTED" && current.record.status !== "CANCEL_REQUESTED") throw new Error("only started invocation may complete");
  const completedAt = nowIso(runtime);
  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: "COMPLETED",
    updatedAt: completedAt,
    outcome: Object.freeze({
      kind: "COMPLETED",
      completedAt,
      managerId: managerId(manager),
      resultSha256: sha(resultSha256, "resultSha256")!,
      evidenceRefs: normalizeEvidenceRefs(evidenceRefs),
    }),
  });
}

export function failCapabilityInvocation(
  envelope: CapabilityInvocationEnvelope,
  manager: string,
  errorClass: string,
  errorFingerprint: string,
  evidenceRefs?: readonly { id: string; sha256?: string }[],
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "STARTED" && current.record.status !== "CANCEL_REQUESTED") throw new Error("only started invocation may fail");
  if (typeof errorClass !== "string" || errorClass.length < 1 || errorClass.length > 128) throw new TypeError("errorClass is invalid");
  const failedAt = nowIso(runtime);
  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: "FAILED",
    updatedAt: failedAt,
    outcome: Object.freeze({
      kind: "FAILED",
      failedAt,
      managerId: managerId(manager),
      errorClass,
      errorFingerprint: sha(errorFingerprint, "errorFingerprint")!,
      evidenceRefs: normalizeEvidenceRefs(evidenceRefs),
    }),
  });
}

export function createCapabilityInvocationProgressReceipt(
  envelope: CapabilityInvocationEnvelope,
  sequence: number,
  phase: string,
  manager: string,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationProgressReceipt {
  const current = validateCapabilityInvocationEnvelope(envelope);
  if (current.record.status !== "STARTED" && current.record.status !== "CANCEL_REQUESTED") throw new Error("progress requires an active invocation");
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > 1_000_000) throw new RangeError("progress sequence is invalid");
  return Object.freeze({
    schemaVersion: "toadaid.capability-invocation-progress.v1",
    invocationId: current.record.invocationId,
    recordSha256: current.recordSha256,
    sequence,
    observedAt: nowIso(runtime),
    managerId: managerId(manager),
    phase: phaseName(phase),
  });
}

export function assessCapabilityInvocationResume(
  envelope: CapabilityInvocationEnvelope,
  policy: CapabilityInvocationPolicyContext,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationResumeAssessment {
  const current = validateCapabilityInvocationEnvelope(envelope);
  const checkedAt = nowIso(runtime);
  let decision: CapabilityInvocationResumeAssessment["decision"];
  let currentCapabilityDecision: "ALLOW" | "BLOCK" | null = null;
  if (current.record.status === "REQUESTED") {
    decision = "REAUTHORIZE";
  } else if (current.record.status === "AUTHORIZED") {
    const authority = resolveCapabilityAuthority(current.record.capabilityId, policy.manifest, policy.policyLayers);
    currentCapabilityDecision = authority.decision;
    decision = authority.decision === "ALLOW" ? "READY_TO_START" : "BLOCKED_BY_REVOCATION";
  } else if (
    current.record.status === "STARTED" ||
    current.record.status === "CANCEL_REQUESTED" ||
    current.record.status === "RECONCILIATION_REQUIRED"
  ) {
    decision = "RECONCILIATION_REQUIRED";
  } else {
    decision = "TERMINAL";
  }
  return Object.freeze({
    schemaVersion: "toadaid.capability-invocation-resume-assessment.v1",
    invocationId: current.record.invocationId,
    recordSha256: current.recordSha256,
    decision,
    currentCapabilityDecision,
    checkedAt,
  });
}

export function serializeCapabilityInvocation(envelope: CapabilityInvocationEnvelope): string {
  return JSON.stringify(validateCapabilityInvocationEnvelope(envelope));
}

export function parseCapabilityInvocation(serialized: string): CapabilityInvocationEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new TypeError("capability invocation envelope must be valid JSON"); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new TypeError("capability invocation envelope must be an object");
  return validateCapabilityInvocationEnvelope(parsed as CapabilityInvocationEnvelope);
}
