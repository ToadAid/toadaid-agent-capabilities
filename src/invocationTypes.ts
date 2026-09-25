import type { CapabilityManifest, CapabilityPolicyLayer } from "./capabilityPolicy.js";

export type CapabilityInvocationStatus =
  | "REQUESTED"
  | "AUTHORIZED"
  | "REFUSED"
  | "STARTED"
  | "CANCEL_REQUESTED"
  | "COMPLETED"
  | "FAILED";

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

export type CapabilityInvocationOutcome = CapabilityInvocationCompletedOutcome | CapabilityInvocationFailedOutcome;

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
