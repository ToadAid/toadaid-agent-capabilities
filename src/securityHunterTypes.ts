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
  CreateSecurityFindingCandidateInput,
  SecurityAttackClass,
  SecurityEvidenceRef,
  SecurityFindingEnvelope,
  SecuritySourceLocation,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import type {
  SecurityCoverageLedgerEnvelope,
  SecurityHunterAssignment,
} from "./securityCoverageTypes.js";

export type SecurityHunterObservationPosition =
  | "SUPPORTS_CANDIDATE"
  | "CHALLENGES_CANDIDATE"
  | "UNCERTAIN";

export interface SecurityHunterProofStepInput {
  readonly stepId: string;
  readonly description: string;
  readonly expectedEvidenceRefs?: readonly SecurityEvidenceRef[];
}

export interface SecurityHunterProofStep {
  readonly stepId: string;
  readonly description: string;
  readonly expectedEvidenceRefs: readonly SecurityEvidenceRef[];
}

export interface SecurityHunterObservationInput {
  readonly observationId: string;
  readonly position: SecurityHunterObservationPosition;
  readonly summary: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly sourceLocations: readonly SecuritySourceLocation[];
}

export interface SecurityHunterObservation
  extends SecurityHunterObservationInput {}

export interface SecurityHunterSpawnInput {
  readonly assignment: SecurityHunterAssignment;
  readonly threatModel: SecurityThreatModelEnvelope;
  readonly coverageLedger: SecurityCoverageLedgerEnvelope;
  readonly parentAuthority: readonly RunResumeAuthorityDecision[];
  readonly childAuthoritySnapshot: RunAuthoritySnapshot;
  readonly parentBudget: RunBudgetLedgerEnvelope;
  readonly q1Limits: RunBudgetVector;
  readonly childTaskId?: string;
  readonly childBudgetId?: string;
  readonly allocationId?: string;
  readonly createdAt: string;
}

export interface SecurityHunterSpawnReceipt {
  readonly schemaVersion: "toadaid.security-hunter-spawn.v1";
  readonly assignment: SecurityHunterAssignment;
  readonly assignmentSha256: string;
  readonly hunterIdentitySha256: string;
  readonly attackClass: SecurityAttackClass;
  readonly sourceTreeSha256: string;
  readonly sourceScopePaths: readonly string[];
  readonly delegatedCapabilities: readonly [
    "host:file-read",
    "host:session",
  ];
  readonly childTask: ChildTaskEnvelope;
  readonly parentBudget: RunBudgetLedgerEnvelope;
  readonly childBudget: RunBudgetLedgerEnvelope;
  readonly budgetAllocationSha256: string;
  readonly spawnedAt: string;
}

export interface CreateSecurityHunterCandidatePacketInput
  extends Omit<CreateSecurityFindingCandidateInput, "attackClass"> {
  readonly proofPlan: readonly SecurityHunterProofStepInput[];
  readonly observations?: readonly SecurityHunterObservationInput[];
  readonly emittedAt: string;
}

export interface SecurityHunterCandidatePacketRecord {
  readonly schemaVersion: "toadaid.security-hunter-candidate-packet.v1";
  readonly hunterIdentitySha256: string;
  readonly assignmentSha256: string;
  readonly childTaskSha256: string;
  readonly childBudgetLedgerSha256: string;
  readonly sourceTreeSha256: string;
  readonly attackClass: SecurityAttackClass;
  readonly candidate: SecurityFindingEnvelope;
  readonly proofPlan: readonly SecurityHunterProofStep[];
  readonly observations: readonly SecurityHunterObservation[];
  readonly emittedAt: string;
}

export interface SecurityHunterCandidatePacketEnvelope {
  readonly schemaVersion:
    "toadaid.security-hunter-candidate-packet-envelope.v1";
  readonly record: SecurityHunterCandidatePacketRecord;
  readonly recordSha256: string;
}
