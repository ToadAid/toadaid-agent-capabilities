export type SecurityAuditRiskSignal =
  | "UNTRUSTED_INPUT"
  | "NETWORK_ACCESS"
  | "FILESYSTEM_ACCESS"
  | "PROCESS_EXECUTION"
  | "SECRET_MATERIAL"
  | "AUTHORITY_BOUNDARY"
  | "PERSISTENT_STATE"
  | "BROWSER_AUTOMATION"
  | "EXTERNAL_DEPENDENCY"
  | "SERIALIZATION_BOUNDARY";

export type SecurityAttackClass =
  | "AUTHORIZATION_BYPASS"
  | "COMMAND_EXECUTION_INJECTION"
  | "DESERIALIZATION_OR_INTEGRITY"
  | "INPUT_INJECTION"
  | "ORIGIN_OR_BROWSER_BOUNDARY"
  | "PATH_TRAVERSAL"
  | "SECRET_EXPOSURE"
  | "SSRF_OR_NETWORK_PIVOT"
  | "STATE_TAMPERING"
  | "SUPPLY_CHAIN";

export type SecurityArchitectureComponentKind =
  | "MODULE"
  | "PROCESS"
  | "DATA_STORE"
  | "NETWORK_SERVICE"
  | "BROWSER"
  | "EXTERNAL_SYSTEM"
  | "SECURITY_CONTROL";

export interface SecurityAuditScope {
  readonly includePaths: readonly string[];
  readonly excludePaths: readonly string[];
}

export interface SecurityArchitectureComponentInput {
  readonly componentId: string;
  readonly kind: SecurityArchitectureComponentKind;
  readonly label: string;
  readonly sourcePaths: readonly string[];
  readonly riskSignals: readonly SecurityAuditRiskSignal[];
}

export interface SecurityArchitectureComponent
  extends SecurityArchitectureComponentInput {}

export interface SecurityTrustBoundaryInput {
  readonly boundaryId: string;
  readonly fromComponentId: string;
  readonly toComponentId: string;
  readonly channel: string;
  readonly riskSignals: readonly SecurityAuditRiskSignal[];
}

export interface SecurityTrustBoundary
  extends SecurityTrustBoundaryInput {}

export interface SecurityArchitectureSnapshotInput {
  readonly components: readonly SecurityArchitectureComponentInput[];
  readonly trustBoundaries: readonly SecurityTrustBoundaryInput[];
}

export interface SecurityArchitectureSnapshot {
  readonly schemaVersion: "toadaid.security-architecture-snapshot.v1";
  readonly components: readonly SecurityArchitectureComponent[];
  readonly trustBoundaries: readonly SecurityTrustBoundary[];
}

export interface SecurityAttackClassPlan {
  readonly attackClass: SecurityAttackClass;
  readonly derivedFromSignals: readonly SecurityAuditRiskSignal[];
  readonly componentIds: readonly string[];
  readonly boundaryIds: readonly string[];
}

export interface SecurityAuditBinding {
  readonly repositoryIdentitySha256: string;
  readonly sourceRevision: string;
  readonly sourceTreeSha256: string;
  readonly scopeSha256: string;
  readonly configurationSha256: string;
  readonly ruleSetSha256: string;
  readonly runId: string;
}

export interface SecurityThreatModelRecord {
  readonly schemaVersion: "toadaid.security-threat-model.v1";
  readonly auditId: string;
  readonly binding: SecurityAuditBinding;
  readonly scope: SecurityAuditScope;
  readonly architecture: SecurityArchitectureSnapshot;
  readonly architectureSha256: string;
  readonly attackClasses: readonly SecurityAttackClassPlan[];
  readonly createdAt: string;
}

export interface SecurityThreatModelEnvelope {
  readonly schemaVersion: "toadaid.security-threat-model-envelope.v1";
  readonly record: SecurityThreatModelRecord;
  readonly recordSha256: string;
}

export interface CreateSecurityThreatModelInput {
  readonly auditId?: string;
  readonly runId: string;
  readonly repositoryIdentitySha256: string;
  readonly sourceRevision: string;
  readonly sourceTreeSha256: string;
  readonly scope: SecurityAuditScope;
  readonly configurationSha256: string;
  readonly ruleSetSha256: string;
  readonly architecture: SecurityArchitectureSnapshotInput;
  readonly createdAt?: string;
}

export interface SecurityEvidenceRef {
  readonly id: string;
  readonly sha256: string;
}

export interface SecuritySourceLocation {
  readonly path: string;
  readonly startLine: number;
  readonly endLine: number;
}

export type SecurityFindingState =
  | "CANDIDATE"
  | "CONFIRMED"
  | "NEEDS_VALIDATION"
  | "REJECTED";

export type SecurityFindingStateEvidence =
  | {
      readonly state: "CANDIDATE";
      readonly rationale: string;
    }
  | {
      readonly state: "NEEDS_VALIDATION";
      readonly reason: string;
    }
  | {
      readonly state: "CONFIRMED";
      readonly validatorIdentitySha256: string;
      readonly proofEvidenceRefs: readonly SecurityEvidenceRef[];
    }
  | {
      readonly state: "REJECTED";
      readonly reason: string;
      readonly disproofEvidenceRefs: readonly SecurityEvidenceRef[];
    };

export interface SecurityFindingRecord {
  readonly schemaVersion: "toadaid.security-finding.v1";
  readonly findingId: string;
  readonly revision: number;
  readonly threatModelRecordSha256: string;
  readonly attackClass: SecurityAttackClass;
  readonly title: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly sourceLocations: readonly SecuritySourceLocation[];
  readonly state: SecurityFindingState;
  readonly stateEvidence: SecurityFindingStateEvidence;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly continuity: {
    readonly previousRecordSha256: string | null;
  };
}

export interface SecurityFindingEnvelope {
  readonly schemaVersion: "toadaid.security-finding-envelope.v1";
  readonly record: SecurityFindingRecord;
  readonly recordSha256: string;
}

export interface CreateSecurityFindingCandidateInput {
  readonly findingId?: string;
  readonly attackClass: SecurityAttackClass;
  readonly title: string;
  readonly rationale: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
  readonly sourceLocations: readonly SecuritySourceLocation[];
  readonly createdAt?: string;
}

export interface SecurityAuditRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}
