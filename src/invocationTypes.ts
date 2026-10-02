import type { CapabilityManifest, CapabilityPolicyLayer } from "./capabilityPolicy.js";

export type CapabilityInvocationStatus =
  | "REQUESTED"
  | "AUTHORIZED"
  | "REFUSED"
  | "STARTED"
  | "CANCEL_REQUESTED"
  | "RECONCILIATION_REQUIRED"
  | "COMPLETED"
  | "FAILED"
  | "RECONCILED";

export interface CapabilityInvocationRequestEvidence {
  intentSha256: string;
  argumentsSha256: string | null;
}

export interface CapabilityInvocationAuthorityEvidence {
  checkedAt: string;
  decision: "ALLOW" | "BLOCK";
  reason: "AUTHORIZED_BY_POLICY" | "BLOCKED_BY_POLICY" | "MANIFEST_DEFAULT" | "UNKNOWN_CAPABILITY";
  decisionSha256: string;
}

export interface CapabilityInvocationStartEvidence {
  startedAt: string;
  managerId: string;
}

export interface CapabilityInvocationCancellationEvidence {
  requestedAt: string;
  managerId: string;
  reasonCode: string;
}

export interface CapabilityInvocationEvidenceReference {
  id: string;
  sha256?: string;
}

export interface CapabilityInvocationCompletedOutcome {
  kind: "COMPLETED";
  completedAt: string;
  managerId: string;
  resultSha256: string;
  evidenceRefs: readonly CapabilityInvocationEvidenceReference[];
}

export interface CapabilityInvocationFailedOutcome {
  kind: "FAILED";
  failedAt: string;
  managerId: string;
  errorClass: string;
  errorFingerprint: string;
  evidenceRefs: readonly CapabilityInvocationEvidenceReference[];
}

export type CapabilityInvocationReconciliationFinding =
  | "CONFIRMED_NOT_EXECUTED"
  | "CONFIRMED_EXECUTED"
  | "STILL_UNKNOWN";

export type CapabilityInvocationReplayDisposition =
  | "RETRY_ALLOWED"
  | "DO_NOT_RETRY"
  | "NEW_INVOCATION_REQUIRED"
  | "BLOCKED_PENDING_RECONCILIATION";

export type CapabilityInvocationExecutionTruth =
  | "EXECUTED"
  | "NOT_EXECUTED"
  | "UNKNOWN";

export interface CapabilityInvocationReconciliationBinding {
  readonly reconciliationId: string;
  readonly replayFenceSha256: string;
  readonly openReconciliationSha256: string;
  readonly invocationRecordSha256: string;
  readonly openedAt: string;
}

export interface CapabilityInvocationReconciledOutcome {
  readonly kind: "RECONCILED";
  readonly reconciledAt: string;
  readonly managerId: string;
  readonly reconciliationId: string;
  readonly reconciliationSha256: string;
  readonly replayFenceSha256: string;
  readonly finding: CapabilityInvocationReconciliationFinding;
  readonly disposition: CapabilityInvocationReplayDisposition;
  readonly executionTruth: CapabilityInvocationExecutionTruth;
  readonly proofSha256: string | null;
  readonly evidenceRefs: readonly CapabilityInvocationEvidenceReference[];
}

export type CapabilityInvocationOutcome =
  | CapabilityInvocationCompletedOutcome
  | CapabilityInvocationFailedOutcome
  | CapabilityInvocationReconciledOutcome;

export interface CapabilityInvocationContinuity {
  previousRecordSha256: string | null;
}

export interface CapabilityInvocationRecord {
  schemaVersion: "toadaid.capability-invocation.v1";
  invocationId: string;
  revision: number;
  status: CapabilityInvocationStatus;
  runId: string;
  childTaskId: string | null;
  capabilityId: string;
  toolName: string;
  externalToolCallId: string | null;
  createdAt: string;
  updatedAt: string;
  request: CapabilityInvocationRequestEvidence;
  authorization: CapabilityInvocationAuthorityEvidence | null;
  start: CapabilityInvocationStartEvidence | null;
  cancellation: CapabilityInvocationCancellationEvidence | null;
  reconciliation?: CapabilityInvocationReconciliationBinding | null;
  outcome: CapabilityInvocationOutcome | null;
  continuity: CapabilityInvocationContinuity;
}

export interface CapabilityInvocationEnvelope {
  schemaVersion: "toadaid.capability-invocation-envelope.v1";
  record: CapabilityInvocationRecord;
  recordSha256: string;
}

export interface CreateCapabilityInvocationInput {
  invocationId?: string;
  runId: string;
  childTaskId?: string | null;
  capabilityId: string;
  toolName: string;
  externalToolCallId?: string | null;
  intentSha256: string;
  argumentsSha256?: string | null;
  createdAt?: string;
}

export interface CapabilityInvocationPolicyContext {
  manifest: CapabilityManifest;
  policyLayers: readonly CapabilityPolicyLayer[];
}

export interface CapabilityInvocationTransitionRuntime {
  now?: () => Date;
}

export type CapabilityInvocationResumeDecision =
  | "REAUTHORIZE"
  | "READY_TO_START"
  | "BLOCKED_BY_REVOCATION"
  | "RECONCILIATION_REQUIRED"
  | "TERMINAL";

export interface CapabilityInvocationResumeAssessment {
  schemaVersion: "toadaid.capability-invocation-resume-assessment.v1";
  invocationId: string;
  recordSha256: string;
  decision: CapabilityInvocationResumeDecision;
  currentCapabilityDecision: "ALLOW" | "BLOCK" | null;
  checkedAt: string;
}

export interface CapabilityInvocationProgressReceipt {
  schemaVersion: "toadaid.capability-invocation-progress.v1";
  invocationId: string;
  recordSha256: string;
  sequence: number;
  observedAt: string;
  managerId: string;
  phase: string;
}
