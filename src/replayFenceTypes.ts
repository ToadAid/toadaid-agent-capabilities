import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";

export type ReplayClass = "SAFE_READ" | "IDEMPOTENT_WRITE" | "NON_REPLAYABLE";
export type IdempotencyMechanism = "PROVIDER_KEY" | "COMPARE_AND_SET" | "EXTERNAL_DEDUPLICATION";
export type ReconciliationFinding = "CONFIRMED_NOT_EXECUTED" | "CONFIRMED_EXECUTED" | "STILL_UNKNOWN";
export type ReplayDisposition = "RETRY_ALLOWED" | "DO_NOT_RETRY" | "NEW_INVOCATION_REQUIRED" | "BLOCKED_PENDING_RECONCILIATION";

export interface ReplayEvidenceReference { readonly id: string; readonly sha256?: string; }

export interface IdempotencyGuarantee {
  readonly mechanism: IdempotencyMechanism;
  readonly feature: string;
  readonly invocationId: string;
  readonly capabilityId: string;
  readonly contractBindingSha256: string;
  readonly contractDescriptorSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly guaranteeSha256: string;
}

export interface ReplayFenceBinding {
  readonly runId: string;
  readonly invocationId: string;
  readonly capabilityId: string;
  readonly intentSha256: string;
}

export interface ReplayFenceRecord {
  readonly schemaVersion: "toadaid.replay-fence.v1";
  readonly binding: ReplayFenceBinding;
  readonly replayClass: ReplayClass;
  readonly idempotencyKey: string;
  readonly guarantee: IdempotencyGuarantee | null;
  readonly createdAt: string;
}

export interface ReplayFenceEnvelope {
  readonly schemaVersion: "toadaid.replay-fence-envelope.v1";
  readonly record: ReplayFenceRecord;
  readonly recordSha256: string;
}

export interface CreateReplayFenceInput {
  readonly replayClass: ReplayClass;
  readonly guarantee?: IdempotencyGuarantee | null;
  readonly createdAt?: string;
}

export interface ReplayReconciliationRecord {
  readonly schemaVersion: "toadaid.replay-reconciliation.v1";
  readonly reconciliationId: string;
  readonly revision: number;
  readonly status: "OPEN" | "RESOLVED";
  readonly replayFenceSha256: string;
  readonly invocationRecordSha256: string;
  readonly binding: ReplayFenceBinding;
  readonly replayClass: ReplayClass;
  readonly idempotencyKey: string;
  readonly openedAt: string;
  readonly reasonCode: string;
  readonly evidenceRefs: readonly ReplayEvidenceReference[];
  readonly finding: ReconciliationFinding | null;
  readonly proofSha256: string | null;
  readonly proofRefs: readonly ReplayEvidenceReference[];
  readonly disposition: ReplayDisposition;
  readonly resolvedAt: string | null;
  readonly continuity: { readonly previousRecordSha256: string | null };
}

export interface ReplayReconciliationEnvelope {
  readonly schemaVersion: "toadaid.replay-reconciliation-envelope.v1";
  readonly record: ReplayReconciliationRecord;
  readonly recordSha256: string;
}

export interface OpenReplayReconciliationInput {
  readonly reconciliationId?: string;
  readonly reasonCode: string;
  readonly evidenceRefs?: readonly ReplayEvidenceReference[];
  readonly openedAt?: string;
}

export interface ResolveReplayReconciliationInput {
  readonly finding: ReconciliationFinding;
  readonly proofSha256?: string | null;
  readonly proofRefs?: readonly ReplayEvidenceReference[];
  readonly resolvedAt?: string;
}

export interface ReplayRetryAuthorization {
  readonly schemaVersion: "toadaid.replay-retry-authorization.v1";
  readonly reconciliationId: string;
  readonly replayFenceSha256: string;
  readonly reconciliationSha256: string;
  readonly invocationId: string;
  readonly replayClass: ReplayClass;
  readonly disposition: ReplayDisposition;
  readonly idempotencyKey: string;
  readonly authorizedAt: string;
}

export interface ReplayFenceRuntime { readonly now?: () => Date; readonly randomId?: () => string; }

export interface ReplayInvocationLike extends CapabilityInvocationEnvelope {}
