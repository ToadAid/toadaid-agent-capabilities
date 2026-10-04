import type {
  GovernedRecipeDefinition,
  GovernedRecipePlan,
} from "./recipeTypes.js";
import type {
  SecurityEvidenceRef,
} from "./securityAuditTypes.js";
import type {
  SecurityCanonicalFindingsEnvelope,
} from "./securityReportTypes.js";
import type {
  WorkspaceDiffReceipt,
  WorkspaceSnapshot,
} from "./workspaceHistoryTypes.js";

export type SecuritySpecialistMode =
  | "REPOSITORY_PREFLIGHT"
  | "TARGETED_AUDIT"
  | "GAP_FILL_AUDIT"
  | "VALIDATION_ONLY"
  | "REVERIFICATION";

export interface SecuritySpecialistCompiledPlan {
  readonly schemaVersion:
    "toadaid.security-specialist-plan.v1";
  readonly mode: SecuritySpecialistMode;
  readonly recipe: GovernedRecipeDefinition;
  readonly recipePlan: GovernedRecipePlan;
  readonly inspectionOnly: true;
  readonly repairAuthorityIncluded: false;
  readonly fileMutationAuthorityIncluded: false;
  readonly gitAuthorityIncluded: false;
  readonly prAuthorityIncluded: false;
  readonly mergeAuthorityIncluded: false;
}

export interface CreateSecurityRepairProposalInput {
  readonly proposalId: string;
  readonly findingId: string;
  readonly finderIdentitySha256: string;
  readonly createdAt: string;
}

export interface SecurityRepairProposalRecord {
  readonly schemaVersion:
    "toadaid.security-repair-proposal.v1";
  readonly proposalId: string;
  readonly canonicalFindingsRecordSha256: string;
  readonly auditId: string;
  readonly findingId: string;
  readonly findingRecordSha256: string;
  readonly affectedRevision: string;
  readonly affectedSourceTreeSha256: string;
  readonly proofEvidenceRefs:
    readonly SecurityEvidenceRef[];
  readonly finderIdentitySha256: string;
  readonly validatorIdentitySha256: string;
  readonly createdAt: string;
  readonly requiredIndependentCapabilities:
    readonly [
      "review:fix",
      "workspace:snapshot",
      "workspace:diff",
    ];
  readonly authorityIncluded: false;
  readonly fileMutationAuthorityIncluded: false;
  readonly gitAuthorityIncluded: false;
  readonly prAuthorityIncluded: false;
  readonly mergeAuthorityIncluded: false;
}

export interface SecurityRepairProposalEnvelope {
  readonly schemaVersion:
    "toadaid.security-repair-proposal-envelope.v1";
  readonly record: SecurityRepairProposalRecord;
  readonly recordSha256: string;
}

export interface BindSecurityRepairPreMutationSnapshotInput {
  readonly canonicalFindings:
    SecurityCanonicalFindingsEnvelope;
  readonly proposal: SecurityRepairProposalEnvelope;
  readonly snapshot: WorkspaceSnapshot;
  readonly boundAt: string;
}

export interface SecurityRepairPreMutationBindingRecord {
  readonly schemaVersion:
    "toadaid.security-repair-pre-mutation-binding.v1";
  readonly proposalRecordSha256: string;
  readonly findingRecordSha256: string;
  readonly workspaceId: string;
  readonly beforeSnapshotId: string;
  readonly beforeSnapshotSha256: string;
  readonly snapshotCreatedAt: string;
  readonly boundAt: string;
  readonly authorityIncluded: false;
}

export interface SecurityRepairPreMutationBindingEnvelope {
  readonly schemaVersion:
    "toadaid.security-repair-pre-mutation-binding-envelope.v1";
  readonly record:
    SecurityRepairPreMutationBindingRecord;
  readonly recordSha256: string;
}

export interface CreateSecurityRepairVerificationPackageInput {
  readonly canonicalFindings:
    SecurityCanonicalFindingsEnvelope;
  readonly proposal: SecurityRepairProposalEnvelope;
  readonly preMutation:
    SecurityRepairPreMutationBindingEnvelope;
  readonly beforeSnapshot: WorkspaceSnapshot;
  readonly afterSnapshot: WorkspaceSnapshot;
  readonly diff: WorkspaceDiffReceipt;
  readonly testEvidenceRefs:
    readonly SecurityEvidenceRef[];
  readonly verifiedAt: string;
}

export interface SecurityRepairVerificationRecord {
  readonly schemaVersion:
    "toadaid.security-repair-verification.v1";
  readonly proposalRecordSha256: string;
  readonly findingId: string;
  readonly findingRecordSha256: string;
  readonly beforeSnapshotId: string;
  readonly beforeSnapshotSha256: string;
  readonly afterSnapshotId: string;
  readonly afterSnapshotSha256: string;
  readonly diffSha256: string;
  readonly changedPaths: readonly string[];
  readonly testEvidenceRefs:
    readonly SecurityEvidenceRef[];
  readonly verifiedAt: string;
  readonly findingStatusMutationIncluded: false;
  readonly authorityIncluded: false;
  readonly gitAuthorityIncluded: false;
  readonly prAuthorityIncluded: false;
  readonly mergeAuthorityIncluded: false;
}

export interface SecurityRepairVerificationEnvelope {
  readonly schemaVersion:
    "toadaid.security-repair-verification-envelope.v1";
  readonly record: SecurityRepairVerificationRecord;
  readonly recordSha256: string;
}

export interface SecurityRepairMergeSeparationReceipt {
  readonly schemaVersion:
    "toadaid.security-repair-merge-separation.v1";
  readonly proposalRecordSha256: string;
  readonly mergeActorIdentitySha256: string;
  readonly separatedFromFinder: true;
  readonly separatedFromValidator: true;
  readonly mergeAuthorityGranted: false;
}

export interface SecurityRepairProposalSource {
  readonly canonicalFindings:
    SecurityCanonicalFindingsEnvelope;
}
