import type { ChildTaskEnvelope } from "./childTaskLifecycle.js";
import type {
  RunAuthoritySnapshot,
  RunResumeAuthorityDecision,
} from "./runStateCapsule.js";
import type {
  RunBudgetLedgerEnvelope,
  RunBudgetVector,
} from "./runBudgetTypes.js";
import type {
  SecurityEvidenceRef,
  SecurityFindingEnvelope,
  SecuritySourceLocation,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import type {
  SecurityCoverageLedgerEnvelope,
} from "./securityCoverageTypes.js";
import type {
  SecurityHunterCandidatePacketEnvelope,
  SecurityHunterSpawnReceipt,
} from "./securityHunterTypes.js";

export interface SecurityAuditRuntimeProvenance {
  readonly providerId: string;
  readonly modelId: string;
}

export interface SecurityValidatorSpawnInput {
  readonly threatModel: SecurityThreatModelEnvelope;
  readonly coverageLedger: SecurityCoverageLedgerEnvelope;
  readonly hunterSpawn: SecurityHunterSpawnReceipt;
  readonly candidatePacket: SecurityHunterCandidatePacketEnvelope;
  readonly validatorIdentitySha256: string;
  readonly runtimeProvenance?: SecurityAuditRuntimeProvenance;
  readonly parentAuthority: readonly RunResumeAuthorityDecision[];
  readonly childAuthoritySnapshot: RunAuthoritySnapshot;
  readonly parentBudget: RunBudgetLedgerEnvelope;
  readonly q1Limits: RunBudgetVector;
  readonly childTaskId?: string;
  readonly childBudgetId?: string;
  readonly allocationId?: string;
  readonly createdAt: string;
}

export interface SecurityValidatorSpawnReceipt {
  readonly schemaVersion: "toadaid.security-validator-spawn.v1";
  readonly validatorIdentitySha256: string;
  readonly validatorExecutionSha256: string;
  readonly hunterIdentitySha256: string;
  readonly candidatePacketSha256: string;
  readonly candidateFindingSha256: string;
  readonly sourceTreeSha256: string;
  readonly runtimeProvenance: SecurityAuditRuntimeProvenance | null;
  readonly delegatedCapabilities: readonly [
    "host:file-read",
    "host:session",
  ];
  readonly validationFinding: SecurityFindingEnvelope;
  readonly childTask: ChildTaskEnvelope;
  readonly parentBudget: RunBudgetLedgerEnvelope;
  readonly childBudget: RunBudgetLedgerEnvelope;
  readonly budgetAllocationSha256: string;
  readonly spawnedAt: string;
}

export type SecurityValidationDisposition =
  | "NEEDS_VALIDATION"
  | "CONFIRMED"
  | "REJECTED";

export type SecurityValidationDecisionInput =
  | {
      readonly disposition: "NEEDS_VALIDATION";
      readonly reason: string;
      readonly evidenceRefs?: readonly SecurityEvidenceRef[];
      readonly checkedSourceLocations?: readonly SecuritySourceLocation[];
      readonly decidedAt: string;
    }
  | {
      readonly disposition: "CONFIRMED";
      readonly proofEvidenceRefs: readonly SecurityEvidenceRef[];
      readonly reproducedSourceLocations: readonly SecuritySourceLocation[];
      readonly decidedAt: string;
    }
  | {
      readonly disposition: "REJECTED";
      readonly reason: string;
      readonly disproofEvidenceRefs: readonly SecurityEvidenceRef[];
      readonly checkedSourceLocations: readonly SecuritySourceLocation[];
      readonly decidedAt: string;
    };

export interface SecurityValidationDecisionRecord {
  readonly schemaVersion: "toadaid.security-validation-decision.v1";
  readonly disposition: SecurityValidationDisposition;
  readonly validatorIdentitySha256: string;
  readonly hunterIdentitySha256: string;
  readonly validatorExecutionSha256: string;
  readonly candidatePacketSha256: string;
  readonly predecessorFindingSha256: string;
  readonly sourceTreeSha256: string;
  readonly validationMode: "READ_ONLY_ADVERSARIAL_REVIEW";
  readonly validationEvidenceRefs: readonly SecurityEvidenceRef[];
  readonly checkedSourceLocations: readonly SecuritySourceLocation[];
  readonly resultFinding: SecurityFindingEnvelope;
  readonly decidedAt: string;
}

export interface SecurityValidationDecisionEnvelope {
  readonly schemaVersion:
    "toadaid.security-validation-decision-envelope.v1";
  readonly record: SecurityValidationDecisionRecord;
  readonly recordSha256: string;
}

export type SecurityReverificationDisposition =
  | "VERIFIED"
  | "NEEDS_REVIEW";

export interface SecurityReverificationInput {
  readonly reVerifierIdentitySha256: string;
  readonly runtimeProvenance?: SecurityAuditRuntimeProvenance;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly checkedSourceLocations: readonly SecuritySourceLocation[];
  readonly verified: boolean;
  readonly reason: string;
  readonly reviewedAt: string;
}

export interface SecurityReverificationRecord {
  readonly schemaVersion: "toadaid.security-reverification.v1";
  readonly disposition: SecurityReverificationDisposition;
  readonly reVerifierIdentitySha256: string;
  readonly validatorIdentitySha256: string;
  readonly hunterIdentitySha256: string;
  readonly validationDecisionSha256: string;
  readonly confirmedFindingSha256: string;
  readonly sourceTreeSha256: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly checkedSourceLocations: readonly SecuritySourceLocation[];
  readonly runtimeProvenance: SecurityAuditRuntimeProvenance | null;
  readonly reason: string;
  readonly reviewedAt: string;
}

export interface SecurityReverificationEnvelope {
  readonly schemaVersion:
    "toadaid.security-reverification-envelope.v1";
  readonly record: SecurityReverificationRecord;
  readonly recordSha256: string;
}
