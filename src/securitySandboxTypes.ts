import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import type {
  RunBudgetLedgerEnvelope,
} from "./runBudgetTypes.js";
import type {
  SecurityEvidenceRef,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import type {
  SecurityCoverageLedgerEnvelope,
} from "./securityCoverageTypes.js";
import type {
  SecurityHunterCandidatePacketEnvelope,
  SecurityHunterSpawnReceipt,
} from "./securityHunterTypes.js";
import type {
  SecurityValidationDecisionEnvelope,
  SecurityValidatorSpawnReceipt,
} from "./securityValidatorTypes.js";

export type SecuritySandboxGuarantee =
  | "NETWORK_DISABLED"
  | "SOURCE_READ_ONLY"
  | "SCRATCH_ONLY_WRITABLE"
  | "EMPTY_ENVIRONMENT"
  | "HOME_UNAVAILABLE"
  | "NO_SHELL"
  | "NO_STDIN"
  | "PROCESS_TREE_CONTAINED"
  | "CPU_LIMIT_ENFORCED"
  | "MEMORY_LIMIT_ENFORCED"
  | "PROCESS_LIMIT_ENFORCED"
  | "WALL_CLOCK_LIMIT_ENFORCED"
  | "ARTIFACTS_CONTENT_ADDRESSED";

export interface SecuritySandboxAdapterRegistration {
  readonly schemaVersion:
    "toadaid.security-sandbox-adapter-registration.v1";
  readonly adapterId: string;
  readonly providerDescriptorSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly sandboxKind: string;
  readonly guarantees: readonly SecuritySandboxGuarantee[];
}

export interface SecuritySandboxResourceLimits {
  readonly cpuTimeMs: number;
  readonly memoryBytes: number;
  readonly maxProcesses: number;
  readonly wallClockMs: number;
  readonly maxOutputBytes: number;
  readonly maxArtifactBytes: number;
  readonly maxArtifacts: number;
}

export interface SecuritySandboxExecutionSpecInput {
  readonly proofAttemptId: string;
  readonly sourceRoot: string;
  readonly scratchRoot: string;
  readonly cwd: string;
  readonly executable: string;
  readonly executableSha256: string;
  readonly argv: readonly string[];
  readonly limits: SecuritySandboxResourceLimits;
}

export interface SecuritySandboxExecutionSpec {
  readonly schemaVersion:
    "toadaid.security-sandbox-execution-spec.v1";
  readonly proofAttemptId: string;
  readonly sourceRoot: string;
  readonly scratchRoot: string;
  readonly cwd: string;
  readonly executable: string;
  readonly executableSha256: string;
  readonly argv: readonly string[];
  readonly argvSha256: string;
  readonly limits: SecuritySandboxResourceLimits;
  readonly limitsSha256: string;
  readonly networkMode: "DISABLED";
  readonly environmentMode: "EMPTY";
  readonly homeMode: "UNAVAILABLE";
  readonly shell: false;
  readonly stdinMode: "DISABLED";
  readonly sourceFilesystem: "READ_ONLY";
  readonly scratchFilesystem: "READ_WRITE";
  readonly otherFilesystem: "UNMOUNTED";
  readonly specSha256: string;
}

export interface SecuritySandboxArtifactReference {
  readonly id: string;
  readonly kind: string;
  readonly sha256: string;
  readonly byteLength: number;
}

export interface SecuritySandboxAttestation {
  readonly networkDisabled: true;
  readonly sourceReadOnly: true;
  readonly scratchOnlyWritable: true;
  readonly environmentEmpty: true;
  readonly homeUnavailable: true;
  readonly shellUsed: false;
  readonly stdinUsed: false;
  readonly processTreeContained: true;
  readonly cpuLimitEnforced: true;
  readonly memoryLimitEnforced: true;
  readonly processLimitEnforced: true;
  readonly wallClockLimitEnforced: true;
  readonly artifactsContentAddressed: true;
  readonly sourceTreeSha256: string;
  readonly specSha256: string;
  readonly limitsSha256: string;
}

export interface SecuritySandboxAdapterRequest {
  readonly schemaVersion:
    "toadaid.security-sandbox-adapter-request.v1";
  readonly operationId: string;
  readonly validationDecisionSha256: string;
  readonly sourceTreeSha256: string;
  readonly spec: SecuritySandboxExecutionSpec;
}

export type SecuritySandboxCompletionStatus =
  | "EXITED"
  | "TIMED_OUT"
  | "CRASHED"
  | "UNKNOWN";

export interface SecuritySandboxAdapterResult {
  readonly schemaVersion:
    "toadaid.security-sandbox-adapter-result.v1";
  readonly operationId: string;
  readonly status: SecuritySandboxCompletionStatus;
  readonly exitCode: number | null;
  readonly stdoutSha256: string;
  readonly stdoutBytes: number;
  readonly stderrSha256: string;
  readonly stderrBytes: number;
  readonly cpuTimeMs: number;
  readonly peakMemoryBytes: number;
  readonly processCount: number;
  readonly artifacts?: readonly SecuritySandboxArtifactReference[];
  readonly attestation: SecuritySandboxAttestation;
  readonly adapterEvidenceSha256: string;
}

export interface SecuritySandboxAdapter {
  readonly registration:
    SecuritySandboxAdapterRegistration;
  readonly invoke: (
    request: SecuritySandboxAdapterRequest,
  ) => Promise<SecuritySandboxAdapterResult>;
}

export interface SecuritySandboxInvocationInput {
  readonly threatModel: SecurityThreatModelEnvelope;
  readonly coverageLedger:
    SecurityCoverageLedgerEnvelope;
  readonly hunterSpawn: SecurityHunterSpawnReceipt;
  readonly candidatePacket:
    SecurityHunterCandidatePacketEnvelope;
  readonly validatorSpawn:
    SecurityValidatorSpawnReceipt;
  readonly validationDecision:
    SecurityValidationDecisionEnvelope;
  readonly sandboxAuthority:
    CapabilityAuthorityDecision;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly spec: SecuritySandboxExecutionSpecInput;
}

export interface SecuritySandboxRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export type SecuritySandboxReceiptStatus =
  | "PROOF_OBSERVED"
  | "NEEDS_VALIDATION";

export interface SecuritySandboxReceipt {
  readonly schemaVersion:
    "toadaid.security-sandbox-receipt.v1";
  readonly status: SecuritySandboxReceiptStatus;
  readonly operationId: string;
  readonly proofAttemptId: string;
  readonly validationDecisionSha256: string;
  readonly predecessorFindingSha256: string;
  readonly sourceTreeSha256: string;
  readonly sandboxAuthorityCapabilityId:
    "security:sandbox-exec";
  readonly adapterRegistrationSha256: string;
  readonly specSha256: string;
  readonly resultEvidenceSha256: string | null;
  readonly artifactSetSha256: string | null;
  readonly completionStatus:
    SecuritySandboxCompletionStatus | null;
  readonly replayDisposition:
    | "NO_REPLAY_NEEDED"
    | "NEW_ATTEMPT_REQUIRED";
  readonly invokedAt: string;
  readonly budgetLedgerSha256Before: string;
  readonly budgetLedgerSha256After: string;
  readonly errorClass: string | null;
  readonly errorFingerprint: string | null;
  readonly receiptSha256: string;
}

export interface SecuritySandboxOutcome {
  readonly receipt: SecuritySandboxReceipt;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly result: SecuritySandboxAdapterResult | null;
}

export interface SecuritySandboxProofEvidence {
  readonly receiptSha256: string;
  readonly evidenceRefs: readonly SecurityEvidenceRef[];
}
