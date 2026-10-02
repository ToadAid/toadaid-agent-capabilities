import type {
  SecurityAttackClass,
  SecurityEvidenceRef,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";

export type SecurityCoverageDisposition =
  | "UNEXPLORED"
  | "THIN"
  | "COVERED";

export interface SecurityCoverageAreaInput {
  readonly areaId: string;
  readonly label: string;
  readonly paths: readonly string[];
}

export interface SecurityCoverageArea extends SecurityCoverageAreaInput {
  readonly areaSha256: string;
}

export interface SecurityCoverageCell {
  readonly cellId: string;
  readonly areaId: string;
  readonly areaSha256: string;
  readonly attackClass: SecurityAttackClass;
  readonly disposition: SecurityCoverageDisposition;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly inspectionCount: number;
  readonly lastInspectedAt: string | null;
}

export interface SecurityCoverageContinuity {
  readonly previousLedgerRecordSha256: string | null;
  readonly sourceChangeSha256: string | null;
  readonly invalidatedCellIds: readonly string[];
}

export interface SecurityCoverageLedgerRecord {
  readonly schemaVersion: "toadaid.security-coverage-ledger.v1";
  readonly ledgerId: string;
  readonly revision: number;
  readonly threatModelRecordSha256: string;
  readonly repositoryIdentitySha256: string;
  readonly sourceRevision: string;
  readonly sourceTreeSha256: string;
  readonly areas: readonly SecurityCoverageArea[];
  readonly cells: readonly SecurityCoverageCell[];
  readonly inspectionBreadthPercent: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly continuity: SecurityCoverageContinuity;
}

export interface SecurityCoverageLedgerEnvelope {
  readonly schemaVersion: "toadaid.security-coverage-ledger-envelope.v1";
  readonly record: SecurityCoverageLedgerRecord;
  readonly recordSha256: string;
}

export interface CreateSecurityCoverageLedgerInput {
  readonly ledgerId?: string;
  readonly areas: readonly SecurityCoverageAreaInput[];
  readonly createdAt?: string;
}

export interface RecordSecurityCoverageInput {
  readonly areaId: string;
  readonly attackClass: SecurityAttackClass;
  readonly disposition: "THIN" | "COVERED";
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly inspectedAt?: string;
}

export interface RebaseSecurityCoverageLedgerInput {
  readonly ledgerId?: string;
  readonly areas: readonly SecurityCoverageAreaInput[];
  readonly changedPaths: readonly string[];
  readonly rebasedAt?: string;
}

export interface SecurityHunterBudget {
  readonly modelTokens: number;
  readonly toolCalls: number;
  readonly networkRequests: number;
  readonly wallClockMs: number;
}

export interface SecurityHunterAssignment {
  readonly schemaVersion: "toadaid.security-hunter-assignment.v1";
  readonly assignmentId: string;
  readonly threatModelRecordSha256: string;
  readonly coverageLedgerRecordSha256: string;
  readonly predecessorCoverageDisposition: SecurityCoverageDisposition;
  readonly predecessorInspectionCount: number;
  readonly repositoryIdentitySha256: string;
  readonly sourceRevision: string;
  readonly sourceTreeSha256: string;
  readonly areaId: string;
  readonly areaSha256: string;
  readonly scopePaths: readonly string[];
  readonly scopeSha256: string;
  readonly attackClass: SecurityAttackClass;
  readonly budget: SecurityHunterBudget;
  readonly budgetSha256: string;
  readonly plannedAt: string;
}

export interface PlanSecurityHunterAssignmentInput {
  readonly assignmentId?: string;
  readonly budget: SecurityHunterBudget;
  readonly plannedAt?: string;
}

export interface SecurityCoverageGap {
  readonly cellId: string;
  readonly areaId: string;
  readonly attackClass: SecurityAttackClass;
  readonly disposition: "UNEXPLORED" | "THIN";
  readonly inspectionCount: number;
}

export interface SecurityCoverageSummary {
  readonly totalCells: number;
  readonly unexploredCells: number;
  readonly thinCells: number;
  readonly coveredCells: number;
  readonly inspectionBreadthPercent: number;
  readonly gaps: readonly SecurityCoverageGap[];
}

export interface SecurityCoverageRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export interface SecurityCoverageContext {
  readonly model: SecurityThreatModelEnvelope;
  readonly ledger: SecurityCoverageLedgerEnvelope;
}
