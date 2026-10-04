import type {
  SecurityAttackClass,
  SecurityEvidenceRef,
  SecurityFindingState,
  SecuritySourceLocation,
} from "./securityAuditTypes.js";
import type {
  SecurityCoverageSummary,
} from "./securityCoverageTypes.js";
import type {
  SecurityFindingSourceDisposition,
} from "./securityAuditStateTypes.js";

export type SecurityReportSeverity = "UNASSESSED";

export type SecurityReportRiskStatus =
  | "POTENTIAL"
  | "NEEDS_VALIDATION"
  | "VERIFIED"
  | "DISPROVEN"
  | "STALE_SOURCE";

export interface SecurityCanonicalValidatorProvenance {
  readonly level: "NONE" | "IDENTITY_ONLY";
  readonly validatorIdentitySha256: string | null;
}

export interface SecurityCanonicalFinding {
  readonly schemaVersion: "toadaid.security-canonical-finding.v1";
  readonly findingId: string;
  readonly findingRecordSha256: string;
  readonly findingRevision: number;
  readonly title: string;
  readonly severity: SecurityReportSeverity;
  readonly riskStatus: SecurityReportRiskStatus;
  readonly attackClass: SecurityAttackClass;
  readonly proofStatus: SecurityFindingState;
  readonly sourceDisposition: SecurityFindingSourceDisposition;
  readonly sourceChangeSha256: string | null;
  readonly affectedRevision: string;
  readonly affectedSourceTreeSha256: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly proofEvidenceRefs: readonly SecurityEvidenceRef[];
  readonly disproofEvidenceRefs: readonly SecurityEvidenceRef[];
  readonly sourceLocations: readonly SecuritySourceLocation[];
  readonly validatorProvenance: SecurityCanonicalValidatorProvenance;
  readonly updatedAt: string;
}

export interface SecurityCanonicalFindingsRecord {
  readonly schemaVersion: "toadaid.security-canonical-findings.v1";
  readonly auditId: string;
  readonly auditStateRevision: number;
  readonly auditStateRecordSha256: string;
  readonly repositoryIdentitySha256: string;
  readonly currentSourceRevision: string;
  readonly currentSourceTreeSha256: string;
  readonly currentThreatModelRecordSha256: string;
  readonly generatedFromStateUpdatedAt: string;
  readonly runtimeProvenance: {
    readonly providerIdentitySha256: string | null;
    readonly modelIdentitySha256: string | null;
  };
  readonly coverageSummary: SecurityCoverageSummary;
  readonly findings: readonly SecurityCanonicalFinding[];
  readonly candidateFindingIds: readonly string[];
  readonly needsValidationFindingIds: readonly string[];
  readonly confirmedFindingIds: readonly string[];
  readonly rejectedFindingIds: readonly string[];
  readonly staleSourceFindingIds: readonly string[];
}

export interface SecurityCanonicalFindingsEnvelope {
  readonly schemaVersion: "toadaid.security-canonical-findings-envelope.v1";
  readonly record: SecurityCanonicalFindingsRecord;
  readonly recordSha256: string;
}

export interface SecurityFindingMarkdownView {
  readonly findingId: string;
  readonly markdown: string;
}

export interface SecurityReportBundle {
  readonly schemaVersion: "toadaid.security-report-bundle.v1";
  readonly canonicalFindings: SecurityCanonicalFindingsEnvelope;
  readonly findingsJson: string;
  readonly reportMarkdown: string;
  readonly needsValidationMarkdown: string;
  readonly detailedFindings: readonly SecurityFindingMarkdownView[];
  readonly findingsJsonSha256: string;
  readonly reportMarkdownSha256: string;
}

export type SecurityReportComparisonStatus =
  | "NEW"
  | "FIXED"
  | "RESOLVED"
  | "REGRESSED"
  | "STILL_OPEN"
  | "STILL_CLOSED"
  | "STALE_SOURCE";

export interface SecurityReportFindingComparison {
  readonly findingId: string;
  readonly status: SecurityReportComparisonStatus;
  readonly previousProofStatus: SecurityFindingState | null;
  readonly currentProofStatus: SecurityFindingState;
  readonly previousFindingRecordSha256: string | null;
  readonly currentFindingRecordSha256: string;
}

export interface SecurityReportComparison {
  readonly schemaVersion: "toadaid.security-report-comparison.v1";
  readonly auditId: string;
  readonly repositoryIdentitySha256: string;
  readonly fromAuditStateRevision: number;
  readonly toAuditStateRevision: number;
  readonly fromSourceRevision: string;
  readonly toSourceRevision: string;
  readonly findings: readonly SecurityReportFindingComparison[];
}
