import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import type {
  ChildTaskRecord,
} from "./childTaskLifecycle.js";
import type {
  RunAuthoritySnapshot,
  RunStateCapsule,
} from "./runStateCapsule.js";
import type {
  SecurityFindingEnvelope,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import type {
  SecurityCoverageAreaInput,
  SecurityCoverageLedgerEnvelope,
} from "./securityCoverageTypes.js";

export type SecurityAuditStateStatus =
  | "ACTIVE"
  | "BLOCKED"
  | "COMPLETE";

export type SecurityAuditStateTransition =
  | "INITIAL"
  | "CHECKPOINT"
  | "RESUME"
  | "SOURCE_REBASE"
  | "PROVIDER_CHANGE";

export type SecurityFindingSourceDisposition =
  | "CURRENT_REVISION"
  | "CARRIED_UNCHANGED"
  | "INVALIDATED_SOURCE_CHANGE";

export interface SecurityAuditFindingEntry {
  readonly finding: SecurityFindingEnvelope;
  readonly sourceDisposition:
    SecurityFindingSourceDisposition;
  readonly sourceChangeSha256: string | null;
}

export type SecurityAuditChildRole =
  | "HUNTER"
  | "VALIDATOR"
  | "REVERIFIER";

export type SecurityAuditChildSourceDisposition =
  | "CURRENT_SOURCE"
  | "HISTORICAL_SOURCE";

export interface SecurityAuditChildLineageEntry {
  readonly role: SecurityAuditChildRole;
  readonly sourceTreeSha256: string;
  readonly sourceDisposition:
    SecurityAuditChildSourceDisposition;
  readonly task: ChildTaskRecord;
  readonly taskSha256: string;
}

export interface SecurityAuditStateRuntimeProvenance {
  readonly providerIdentitySha256: string | null;
  readonly modelIdentitySha256: string | null;
}

export interface SecurityAuditStateContinuity {
  readonly previousStateRecordSha256: string | null;
  readonly transition: SecurityAuditStateTransition;
  readonly sourceChangeSha256: string | null;
  readonly providerChangeSha256: string | null;
}

export interface SecurityAuditStateRecord {
  readonly schemaVersion:
    "toadaid.security-audit-state.v1";
  readonly auditId: string;
  readonly revision: number;
  readonly status: SecurityAuditStateStatus;
  readonly threatModels:
    readonly SecurityThreatModelEnvelope[];
  readonly currentThreatModelRecordSha256: string;
  readonly coverageLedger:
    SecurityCoverageLedgerEnvelope;
  readonly findings:
    readonly SecurityAuditFindingEntry[];
  readonly childTasks:
    readonly SecurityAuditChildLineageEntry[];
  readonly runtimeProvenance:
    SecurityAuditStateRuntimeProvenance;
  readonly runState: RunStateCapsule;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly continuity:
    SecurityAuditStateContinuity;
}

export interface SecurityAuditStateEnvelope {
  readonly schemaVersion:
    "toadaid.security-audit-state-envelope.v1";
  readonly record: SecurityAuditStateRecord;
  readonly recordSha256: string;
}

export interface CreateSecurityAuditStateInput {
  readonly threatModel:
    SecurityThreatModelEnvelope;
  readonly coverageLedger:
    SecurityCoverageLedgerEnvelope;
  readonly findings?:
    readonly SecurityAuditFindingEntry[];
  readonly childTasks?:
    readonly SecurityAuditChildLineageEntry[];
  readonly authoritySnapshot:
    RunAuthoritySnapshot;
  readonly runtimeProvenance?:
    SecurityAuditStateRuntimeProvenance;
  readonly createdAt: string;
}

export interface CheckpointSecurityAuditStateInput {
  readonly updatedAt: string;
  readonly status?: SecurityAuditStateStatus;
  readonly findings?:
    readonly SecurityAuditFindingEntry[];
  readonly childTasks?:
    readonly SecurityAuditChildLineageEntry[];
  readonly runtimeProvenance?:
    SecurityAuditStateRuntimeProvenance;
}

export interface ResumeSecurityAuditStateInput {
  readonly resumedAt: string;
  readonly repositoryIdentitySha256: string;
  readonly sourceRevision: string;
  readonly sourceTreeSha256: string;
  readonly configurationSha256: string;
  readonly ruleSetSha256: string;
  readonly currentAuthority:
    readonly CapabilityAuthorityDecision[];
  readonly runtimeProvenance?:
    SecurityAuditStateRuntimeProvenance;
}

export interface RebaseSecurityAuditStateInput {
  readonly nextThreatModel:
    SecurityThreatModelEnvelope;
  readonly areas:
    readonly SecurityCoverageAreaInput[];
  readonly changedPaths: readonly string[];
  readonly rebasedAt: string;
  readonly currentAuthority:
    readonly CapabilityAuthorityDecision[];
  readonly runtimeProvenance?:
    SecurityAuditStateRuntimeProvenance;
}

export interface SecurityAuditResumeOutcome {
  readonly state: SecurityAuditStateEnvelope;
  readonly resumeAuthority:
    readonly CapabilityAuthorityDecision[];
}
