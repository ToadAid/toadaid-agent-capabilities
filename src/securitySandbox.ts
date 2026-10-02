import path from "node:path";
import { randomUUID } from "node:crypto";

import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import {
  evaluateRunBudgetAvailability,
  recordRunBudgetUsage,
  validateRunBudgetLedgerEnvelope,
} from "./runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "./runBudgetTypes.js";
import type {
  SecurityEvidenceRef,
} from "./securityAuditTypes.js";
import {
  validateSecurityValidationDecisionAgainstLineage,
} from "./securityValidator.js";
import type {
  SecuritySandboxAdapter,
  SecuritySandboxAdapterRegistration,
  SecuritySandboxAdapterRequest,
  SecuritySandboxAdapterResult,
  SecuritySandboxArtifactReference,
  SecuritySandboxAttestation,
  SecuritySandboxExecutionSpec,
  SecuritySandboxExecutionSpecInput,
  SecuritySandboxInvocationInput,
  SecuritySandboxOutcome,
  SecuritySandboxProofEvidence,
  SecuritySandboxReceipt,
  SecuritySandboxResourceLimits,
  SecuritySandboxRuntime,
} from "./securitySandboxTypes.js";

export type * from "./securitySandboxTypes.js";

const SANDBOX_CAPABILITY =
  "security:sandbox-exec" as const;

const REQUIRED_GUARANTEES = Object.freeze([
  "NETWORK_DISABLED",
  "SOURCE_READ_ONLY",
  "SCRATCH_ONLY_WRITABLE",
  "EMPTY_ENVIRONMENT",
  "HOME_UNAVAILABLE",
  "NO_SHELL",
  "NO_STDIN",
  "PROCESS_TREE_CONTAINED",
  "CPU_LIMIT_ENFORCED",
  "MEMORY_LIMIT_ENFORCED",
  "PROCESS_LIMIT_ENFORCED",
  "WALL_CLOCK_LIMIT_ENFORCED",
  "ARTIFACTS_CONTENT_ADDRESSED",
] as const);

const MAX_ARGV = 64;
const MAX_ARG = 4_096;
const MAX_PATH = 4_096;
const MAX_TEXT = 4_000;

function exactText(
  value: string,
  label: string,
  maximum = MAX_TEXT,
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function nonNegative(
  value: number,
  maximum: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new RangeError(
      `${label} must be an integer in [0, ${maximum}]`,
    );
  }
  return value;
}

function positive(
  value: number,
  maximum: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    throw new RangeError(
      `${label} must be an integer in [1, ${maximum}]`,
    );
  }
  return value;
}

function windowsAbsolute(value: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(value);
}

function windowsNetworkOrDevicePath(
  value: string,
): boolean {
  return value.startsWith("\\\\");
}

function absolutePath(
  value: string,
  label: string,
): string {
  const raw = exactText(value, label, MAX_PATH);
  if (windowsNetworkOrDevicePath(raw)) {
    throw new Error(
      `${label} refuses UNC/device paths`,
    );
  }
  if (windowsAbsolute(raw)) {
    return path.win32.normalize(raw);
  }
  if (path.posix.isAbsolute(raw)) {
    return path.posix.normalize(raw);
  }
  throw new Error(`${label} must be absolute`);
}

function samePathStyle(
  a: string,
  b: string,
): boolean {
  return windowsAbsolute(a) === windowsAbsolute(b);
}

function pathWithinOrEqual(
  candidate: string,
  root: string,
): boolean {
  if (!samePathStyle(candidate, root)) {
    return false;
  }
  const api =
    windowsAbsolute(root) ? path.win32 : path.posix;
  const relative = api.relative(root, candidate);
  return (
    relative === "" ||
    relative === "." ||
    (
      !api.isAbsolute(relative) &&
      relative !== ".." &&
      !relative.startsWith(`..${api.sep}`)
    )
  );
}

function pathsOverlap(
  a: string,
  b: string,
): boolean {
  return (
    pathWithinOrEqual(a, b) ||
    pathWithinOrEqual(b, a)
  );
}

function normalizeArgv(
  values: readonly string[],
): readonly string[] {
  if (
    !Array.isArray(values) ||
    values.length > MAX_ARGV
  ) {
    throw new RangeError(
      `sandbox argv exceeds ${MAX_ARGV} entries`,
    );
  }
  return Object.freeze(
    values.map((value, index) =>
      exactText(
        value,
        `argv[${index}]`,
        MAX_ARG,
      ),
    ),
  );
}

function normalizeLimits(
  limits: SecuritySandboxResourceLimits,
): SecuritySandboxResourceLimits {
  return Object.freeze({
    cpuTimeMs: positive(
      limits.cpuTimeMs,
      120_000,
      "limits.cpuTimeMs",
    ),
    memoryBytes: positive(
      limits.memoryBytes,
      2 * 1024 * 1024 * 1024,
      "limits.memoryBytes",
    ),
    maxProcesses: positive(
      limits.maxProcesses,
      16,
      "limits.maxProcesses",
    ),
    wallClockMs: positive(
      limits.wallClockMs,
      120_000,
      "limits.wallClockMs",
    ),
    maxOutputBytes: positive(
      limits.maxOutputBytes,
      4 * 1024 * 1024,
      "limits.maxOutputBytes",
    ),
    maxArtifactBytes: positive(
      limits.maxArtifactBytes,
      16 * 1024 * 1024,
      "limits.maxArtifactBytes",
    ),
    maxArtifacts: nonNegative(
      limits.maxArtifacts,
      32,
      "limits.maxArtifacts",
    ),
  });
}

export function normalizeSecuritySandboxExecutionSpec(
  input: SecuritySandboxExecutionSpecInput,
): SecuritySandboxExecutionSpec {
  const sourceRoot = absolutePath(
    input.sourceRoot,
    "sourceRoot",
  );
  const scratchRoot = absolutePath(
    input.scratchRoot,
    "scratchRoot",
  );
  const cwd = absolutePath(
    input.cwd,
    "cwd",
  );
  if (!samePathStyle(sourceRoot, scratchRoot)) {
    throw new Error(
      "sandbox source and scratch roots must use the same path style",
    );
  }
  if (pathsOverlap(sourceRoot, scratchRoot)) {
    throw new Error(
      "sandbox source and scratch roots must be disjoint",
    );
  }
  if (!pathWithinOrEqual(cwd, scratchRoot)) {
    throw new Error(
      "sandbox cwd must be inside the scratch root",
    );
  }

  const executable = absolutePath(
    input.executable,
    "executable",
  );
  const argv = normalizeArgv(input.argv);
  const limits = normalizeLimits(input.limits);
  const limitsSha256 = sha256(limits);
  const core = Object.freeze({
    schemaVersion:
      "toadaid.security-sandbox-execution-spec.v1" as const,
    proofAttemptId: boundedId(
      input.proofAttemptId,
      "proofAttemptId",
    ),
    sourceRoot,
    scratchRoot,
    cwd,
    executable,
    executableSha256: sha(
      input.executableSha256,
      "executableSha256",
    )!,
    argv,
    argvSha256: sha256(argv),
    limits,
    limitsSha256,
    networkMode: "DISABLED" as const,
    environmentMode: "EMPTY" as const,
    homeMode: "UNAVAILABLE" as const,
    shell: false as const,
    stdinMode: "DISABLED" as const,
    sourceFilesystem: "READ_ONLY" as const,
    scratchFilesystem: "READ_WRITE" as const,
    otherFilesystem: "UNMOUNTED" as const,
  });
  return Object.freeze({
    ...core,
    specSha256: sha256(core),
  });
}

export function normalizeSecuritySandboxAdapterRegistration(
  value: SecuritySandboxAdapterRegistration,
): SecuritySandboxAdapterRegistration {
  if (
    value.schemaVersion !==
    "toadaid.security-sandbox-adapter-registration.v1"
  ) {
    throw new TypeError(
      "unsupported security sandbox adapter registration schemaVersion",
    );
  }
  if (!Array.isArray(value.guarantees)) {
    throw new TypeError(
      "sandbox adapter guarantees must be an array",
    );
  }
  const guarantees = [
    ...new Set(value.guarantees),
  ].sort();
  if (
    guarantees.length !==
    value.guarantees.length
  ) {
    throw new Error(
      "sandbox adapter guarantees contain duplicates",
    );
  }
  for (const required of REQUIRED_GUARANTEES) {
    if (!guarantees.includes(required)) {
      throw new Error(
        `sandbox adapter missing required guarantee: ${required}`,
      );
    }
  }
  if (
    guarantees.length !==
    REQUIRED_GUARANTEES.length
  ) {
    throw new Error(
      "sandbox adapter declares unsupported ambient guarantees",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-sandbox-adapter-registration.v1",
    adapterId: boundedId(
      value.adapterId,
      "adapterId",
    ),
    providerDescriptorSha256: sha(
      value.providerDescriptorSha256,
      "providerDescriptorSha256",
    )!,
    implementationFingerprintSha256: sha(
      value.implementationFingerprintSha256,
      "implementationFingerprintSha256",
    )!,
    sandboxKind: exactText(
      value.sandboxKind,
      "sandboxKind",
      128,
    ),
    guarantees: Object.freeze(
      guarantees as typeof value.guarantees,
    ),
  });
}

export function securitySandboxAdapterRegistrationSha256(
  value: SecuritySandboxAdapterRegistration,
): string {
  return sha256(
    normalizeSecuritySandboxAdapterRegistration(
      value,
    ),
  );
}

function assertSandboxAuthority(
  authority: CapabilityAuthorityDecision,
): void {
  if (
    authority.schemaVersion !==
      "toadaid.capability-authority-decision.v1" ||
    authority.capabilityId !==
      SANDBOX_CAPABILITY ||
    authority.installed !== true ||
    authority.decision !== "ALLOW"
  ) {
    throw new Error(
      "SEC5 active proof execution requires separate ALLOW authority for security:sandbox-exec",
    );
  }
}

function zeroCost(): RunBudgetVector {
  return {
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 0,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 0,
    childTasks: 0,
  };
}

function errorClass(error: unknown): string {
  return (
    error instanceof Error && error.name
      ? error.name
      : "SecuritySandboxError"
  ).slice(0, 128);
}

function errorFingerprint(
  error: unknown,
): string {
  return sha256({
    errorClass: errorClass(error),
    message:
      error instanceof Error
        ? error.message.slice(0, 1_024)
        : String(error).slice(0, 1_024),
  });
}

function normalizeArtifacts(
  value:
    | readonly SecuritySandboxArtifactReference[]
    | undefined,
  limits: SecuritySandboxResourceLimits,
): readonly SecuritySandboxArtifactReference[] {
  const input = value ?? [];
  if (
    !Array.isArray(input) ||
    input.length > limits.maxArtifacts
  ) {
    throw new RangeError(
      "sandbox artifact count exceeds configured limit",
    );
  }
  const ids = new Set<string>();
  let total = 0;
  const normalized = input.map(
    (artifact, index) => {
      const allowed = new Set([
        "id",
        "kind",
        "sha256",
        "byteLength",
      ]);
      for (const key of Object.keys(artifact)) {
        if (!allowed.has(key)) {
          throw new Error(
            "sandbox artifacts may expose metadata references only",
          );
        }
      }
      const id = boundedId(
        artifact.id,
        `artifacts[${index}].id`,
      );
      if (ids.has(id)) {
        throw new Error(
          "sandbox artifact ids must be unique",
        );
      }
      ids.add(id);
      const byteLength = nonNegative(
        artifact.byteLength,
        limits.maxArtifactBytes,
        `artifacts[${index}].byteLength`,
      );
      total += byteLength;
      if (
        !Number.isSafeInteger(total) ||
        total > limits.maxArtifactBytes
      ) {
        throw new RangeError(
          "sandbox artifact bytes exceed configured limit",
        );
      }
      return Object.freeze({
        id,
        kind: exactText(
          artifact.kind,
          `artifacts[${index}].kind`,
          128,
        ),
        sha256: sha(
          artifact.sha256,
          `artifacts[${index}].sha256`,
        )!,
        byteLength,
      });
    },
  );
  return Object.freeze(
    normalized.sort(
      (a, b) => a.id.localeCompare(b.id),
    ),
  );
}

function validateAttestation(
  value: SecuritySandboxAttestation,
  spec: SecuritySandboxExecutionSpec,
  sourceTreeSha256: string,
): SecuritySandboxAttestation {
  const booleanChecks = [
    ["networkDisabled", value.networkDisabled],
    ["sourceReadOnly", value.sourceReadOnly],
    ["scratchOnlyWritable", value.scratchOnlyWritable],
    ["environmentEmpty", value.environmentEmpty],
    ["homeUnavailable", value.homeUnavailable],
    ["processTreeContained", value.processTreeContained],
    ["cpuLimitEnforced", value.cpuLimitEnforced],
    ["memoryLimitEnforced", value.memoryLimitEnforced],
    ["processLimitEnforced", value.processLimitEnforced],
    ["wallClockLimitEnforced", value.wallClockLimitEnforced],
    ["artifactsContentAddressed", value.artifactsContentAddressed],
  ] as const;
  for (const [label, actual] of booleanChecks) {
    if (actual !== true) {
      throw new Error(
        `sandbox attestation guarantee failed: ${label}`,
      );
    }
  }
  if (value.shellUsed !== false) {
    throw new Error(
      "sandbox attestation reports shell usage",
    );
  }
  if (value.stdinUsed !== false) {
    throw new Error(
      "sandbox attestation reports stdin usage",
    );
  }
  if (
    sha(
      value.sourceTreeSha256,
      "attestation.sourceTreeSha256",
    ) !== sourceTreeSha256 ||
    sha(
      value.specSha256,
      "attestation.specSha256",
    ) !== spec.specSha256 ||
    sha(
      value.limitsSha256,
      "attestation.limitsSha256",
    ) !== spec.limitsSha256
  ) {
    throw new Error(
      "sandbox attestation lineage mismatch",
    );
  }
  return Object.freeze({
    ...value,
    sourceTreeSha256,
    specSha256: spec.specSha256,
    limitsSha256: spec.limitsSha256,
  });
}

function normalizeAdapterResult(
  value: SecuritySandboxAdapterResult,
  request: SecuritySandboxAdapterRequest,
): SecuritySandboxAdapterResult {
  if (
    value.schemaVersion !==
    "toadaid.security-sandbox-adapter-result.v1"
  ) {
    throw new TypeError(
      "unsupported security sandbox adapter result schemaVersion",
    );
  }
  if (
    boundedId(
      value.operationId,
      "operationId",
    ) !== request.operationId
  ) {
    throw new Error(
      "sandbox adapter result operation identity mismatch",
    );
  }
  if (
    ![
      "EXITED",
      "TIMED_OUT",
      "CRASHED",
      "UNKNOWN",
    ].includes(value.status)
  ) {
    throw new TypeError(
      "sandbox completion status is unsupported",
    );
  }
  const exitCode =
    value.exitCode === null
      ? null
      : nonNegative(
          value.exitCode,
          255,
          "exitCode",
        );
  if (
    value.status === "EXITED" &&
    exitCode === null
  ) {
    throw new Error(
      "normally exited sandbox proof requires an exit code",
    );
  }
  if (
    value.status !== "EXITED" &&
    exitCode !== null
  ) {
    throw new Error(
      "non-exited sandbox proof cannot carry an exit code",
    );
  }

  const limits = request.spec.limits;
  const stdoutBytes = nonNegative(
    value.stdoutBytes,
    limits.maxOutputBytes,
    "stdoutBytes",
  );
  const stderrBytes = nonNegative(
    value.stderrBytes,
    limits.maxOutputBytes,
    "stderrBytes",
  );
  if (
    stdoutBytes + stderrBytes >
    limits.maxOutputBytes
  ) {
    throw new RangeError(
      "sandbox combined output exceeds configured limit",
    );
  }

  const cpuTimeMs = nonNegative(
    value.cpuTimeMs,
    limits.cpuTimeMs,
    "cpuTimeMs",
  );
  const peakMemoryBytes = nonNegative(
    value.peakMemoryBytes,
    limits.memoryBytes,
    "peakMemoryBytes",
  );
  const processCount = nonNegative(
    value.processCount,
    limits.maxProcesses,
    "processCount",
  );
  const artifacts = normalizeArtifacts(
    value.artifacts,
    limits,
  );
  const attestation = validateAttestation(
    value.attestation,
    request.spec,
    request.sourceTreeSha256,
  );

  return Object.freeze({
    schemaVersion:
      "toadaid.security-sandbox-adapter-result.v1",
    operationId: request.operationId,
    status: value.status,
    exitCode,
    stdoutSha256: sha(
      value.stdoutSha256,
      "stdoutSha256",
    )!,
    stdoutBytes,
    stderrSha256: sha(
      value.stderrSha256,
      "stderrSha256",
    )!,
    stderrBytes,
    cpuTimeMs,
    peakMemoryBytes,
    processCount,
    ...(artifacts.length === 0
      ? {}
      : { artifacts }),
    attestation,
    adapterEvidenceSha256: sha(
      value.adapterEvidenceSha256,
      "adapterEvidenceSha256",
    )!,
  });
}

function receiptSha256(
  receipt: Omit<
    SecuritySandboxReceipt,
    "receiptSha256"
  >,
): string {
  return sha256(receipt);
}

function resultEvidenceSha256(
  result: SecuritySandboxAdapterResult,
  request: SecuritySandboxAdapterRequest,
  registrationSha256: string,
): string {
  return sha256({
    adapterEvidenceSha256:
      result.adapterEvidenceSha256,
    operationId: result.operationId,
    validationDecisionSha256:
      request.validationDecisionSha256,
    sourceTreeSha256:
      request.sourceTreeSha256,
    specSha256: request.spec.specSha256,
    adapterRegistrationSha256:
      registrationSha256,
    status: result.status,
    exitCode: result.exitCode,
    stdoutSha256: result.stdoutSha256,
    stderrSha256: result.stderrSha256,
    cpuTimeMs: result.cpuTimeMs,
    peakMemoryBytes:
      result.peakMemoryBytes,
    processCount: result.processCount,
    artifacts: result.artifacts ?? [],
    attestation: result.attestation,
  });
}

export async function invokeSecuritySandboxProof(
  adapter: SecuritySandboxAdapter,
  input: SecuritySandboxInvocationInput,
  runtime: SecuritySandboxRuntime = {},
): Promise<SecuritySandboxOutcome> {
  assertSandboxAuthority(
    input.sandboxAuthority,
  );
  const registration =
    normalizeSecuritySandboxAdapterRegistration(
      adapter.registration,
    );
  const registrationSha256 =
    securitySandboxAdapterRegistrationSha256(
      registration,
    );

  const decision =
    validateSecurityValidationDecisionAgainstLineage(
      input.threatModel,
      input.coverageLedger,
      input.hunterSpawn,
      input.candidatePacket,
      input.validatorSpawn,
      input.validationDecision,
    );
  if (
    decision.record.disposition !==
      "NEEDS_VALIDATION" ||
    decision.record.resultFinding.record.state !==
      "NEEDS_VALIDATION"
  ) {
    throw new Error(
      "SEC5 sandbox execution is allowed only for authoritative NEEDS_VALIDATION findings",
    );
  }

  const spec =
    normalizeSecuritySandboxExecutionSpec(
      input.spec,
    );
  const budgetBefore =
    validateRunBudgetLedgerEnvelope(
      input.budget,
    );
  const cost = Object.freeze({
    ...zeroCost(),
    toolCalls: 1,
    wallClockMs: spec.limits.wallClockMs,
  });
  const availability =
    evaluateRunBudgetAvailability(
      budgetBefore,
      cost,
    );
  if (!availability.allowed) {
    throw new RangeError(
      `SEC5 sandbox Q1 budget exceeded: ${availability.exceededMetrics.join(",")}`,
    );
  }

  const now =
    (runtime.now ?? (() => new Date()))();
  if (
    !(now instanceof Date) ||
    Number.isNaN(now.getTime())
  ) {
    throw new TypeError(
      "security sandbox runtime now is invalid",
    );
  }
  const invokedAt = canonicalIso(
    now.toISOString(),
    "invokedAt",
  );
  if (
    Date.parse(invokedAt) <
    Date.parse(decision.record.decidedAt)
  ) {
    throw new RangeError(
      "SEC5 sandbox execution cannot predate NEEDS_VALIDATION decision",
    );
  }

  const operationId = boundedId(
    (runtime.randomId ?? randomUUID)(),
    "operationId",
  );
  const request: SecuritySandboxAdapterRequest =
    Object.freeze({
      schemaVersion:
        "toadaid.security-sandbox-adapter-request.v1",
      operationId,
      validationDecisionSha256:
        decision.recordSha256,
      sourceTreeSha256:
        decision.record.sourceTreeSha256,
      spec,
    });

  const budgetAfter =
    recordRunBudgetUsage(
      budgetBefore,
      {
        receiptId: boundedId(
          `security-sandbox-${sha256({
            operationId,
            specSha256: spec.specSha256,
          }).slice(0, 32)}`,
          "receiptId",
        ),
        kind: "TOOL",
        occurredAt: invokedAt,
        sourceSha256: spec.specSha256,
        delta: cost,
      },
      {
        ...(runtime.now
          ? { now: runtime.now }
          : {}),
        ...(runtime.randomId
          ? { randomId: runtime.randomId }
          : {}),
      },
    );

  try {
    const result =
      normalizeAdapterResult(
        await adapter.invoke(request),
        request,
      );
    const evidenceSha256 =
      resultEvidenceSha256(
        result,
        request,
        registrationSha256,
      );
    const artifacts =
      result.artifacts ?? [];
    const core = Object.freeze({
      schemaVersion:
        "toadaid.security-sandbox-receipt.v1" as const,
      status:
        result.status === "EXITED"
          ? "PROOF_OBSERVED" as const
          : "NEEDS_VALIDATION" as const,
      operationId,
      proofAttemptId:
        spec.proofAttemptId,
      validationDecisionSha256:
        decision.recordSha256,
      predecessorFindingSha256:
        decision.record.resultFinding.recordSha256,
      sourceTreeSha256:
        decision.record.sourceTreeSha256,
      sandboxAuthorityCapabilityId:
        SANDBOX_CAPABILITY,
      adapterRegistrationSha256:
        registrationSha256,
      specSha256: spec.specSha256,
      resultEvidenceSha256:
        evidenceSha256,
      artifactSetSha256:
        artifacts.length === 0
          ? null
          : sha256(artifacts),
      completionStatus: result.status,
      replayDisposition:
        result.status === "EXITED"
          ? "NO_REPLAY_NEEDED" as const
          : "NEW_ATTEMPT_REQUIRED" as const,
      invokedAt,
      budgetLedgerSha256Before:
        budgetBefore.recordSha256,
      budgetLedgerSha256After:
        budgetAfter.recordSha256,
      errorClass: null,
      errorFingerprint: null,
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256:
        receiptSha256(core),
    });
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result,
    });
  } catch (error) {
    const core = Object.freeze({
      schemaVersion:
        "toadaid.security-sandbox-receipt.v1" as const,
      status:
        "NEEDS_VALIDATION" as const,
      operationId,
      proofAttemptId:
        spec.proofAttemptId,
      validationDecisionSha256:
        decision.recordSha256,
      predecessorFindingSha256:
        decision.record.resultFinding.recordSha256,
      sourceTreeSha256:
        decision.record.sourceTreeSha256,
      sandboxAuthorityCapabilityId:
        SANDBOX_CAPABILITY,
      adapterRegistrationSha256:
        registrationSha256,
      specSha256: spec.specSha256,
      resultEvidenceSha256: null,
      artifactSetSha256: null,
      completionStatus: null,
      replayDisposition:
        "NEW_ATTEMPT_REQUIRED" as const,
      invokedAt,
      budgetLedgerSha256Before:
        budgetBefore.recordSha256,
      budgetLedgerSha256After:
        budgetAfter.recordSha256,
      errorClass: errorClass(error),
      errorFingerprint:
        errorFingerprint(error),
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256:
        receiptSha256(core),
    });
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result: null,
    });
  }
}


export function validateSecuritySandboxReceipt(
  receipt: SecuritySandboxReceipt,
): SecuritySandboxReceipt {
  if (
    receipt.schemaVersion !==
    "toadaid.security-sandbox-receipt.v1"
  ) {
    throw new TypeError(
      "unsupported security sandbox receipt schemaVersion",
    );
  }

  const {
    receiptSha256: suppliedReceiptSha256,
    ...receiptCore
  } = receipt;
  const expectedReceiptSha256 =
    receiptSha256(receiptCore);
  const normalizedReceiptSha256 = sha(
    suppliedReceiptSha256,
    "receiptSha256",
  )!;
  if (
    normalizedReceiptSha256 !==
    expectedReceiptSha256
  ) {
    throw new Error(
      "security sandbox receipt integrity mismatch",
    );
  }

  if (
    receipt.status !== "PROOF_OBSERVED" &&
    receipt.status !== "NEEDS_VALIDATION"
  ) {
    throw new TypeError(
      "unsupported security sandbox receipt status",
    );
  }
  if (
    receipt.sandboxAuthorityCapabilityId !==
    SANDBOX_CAPABILITY
  ) {
    throw new Error(
      "security sandbox receipt authority binding mismatch",
    );
  }

  const completionStatuses = new Set([
    "EXITED",
    "TIMED_OUT",
    "CRASHED",
    "UNKNOWN",
  ]);
  if (
    receipt.completionStatus !== null &&
    !completionStatuses.has(receipt.completionStatus)
  ) {
    throw new TypeError(
      "unsupported security sandbox completion status",
    );
  }
  if (
    receipt.replayDisposition !==
      "NO_REPLAY_NEEDED" &&
    receipt.replayDisposition !==
      "NEW_ATTEMPT_REQUIRED"
  ) {
    throw new TypeError(
      "unsupported security sandbox replay disposition",
    );
  }

  const operationId = boundedId(
    receipt.operationId,
    "receipt.operationId",
  );
  const proofAttemptId = boundedId(
    receipt.proofAttemptId,
    "receipt.proofAttemptId",
  );
  const validationDecisionSha256 = sha(
    receipt.validationDecisionSha256,
    "receipt.validationDecisionSha256",
  )!;
  const predecessorFindingSha256 = sha(
    receipt.predecessorFindingSha256,
    "receipt.predecessorFindingSha256",
  )!;
  const sourceTreeSha256 = sha(
    receipt.sourceTreeSha256,
    "receipt.sourceTreeSha256",
  )!;
  const adapterRegistrationSha256 = sha(
    receipt.adapterRegistrationSha256,
    "receipt.adapterRegistrationSha256",
  )!;
  const specSha256 = sha(
    receipt.specSha256,
    "receipt.specSha256",
  )!;
  const resultEvidenceSha256 =
    receipt.resultEvidenceSha256 === null
      ? null
      : sha(
          receipt.resultEvidenceSha256,
          "receipt.resultEvidenceSha256",
        )!;
  const artifactSetSha256 =
    receipt.artifactSetSha256 === null
      ? null
      : sha(
          receipt.artifactSetSha256,
          "receipt.artifactSetSha256",
        )!;
  const budgetLedgerSha256Before = sha(
    receipt.budgetLedgerSha256Before,
    "receipt.budgetLedgerSha256Before",
  )!;
  const budgetLedgerSha256After = sha(
    receipt.budgetLedgerSha256After,
    "receipt.budgetLedgerSha256After",
  )!;
  const invokedAt = canonicalIso(
    receipt.invokedAt,
    "receipt.invokedAt",
  );

  const hasErrorClass =
    receipt.errorClass !== null;
  const hasErrorFingerprint =
    receipt.errorFingerprint !== null;
  if (hasErrorClass !== hasErrorFingerprint) {
    throw new Error(
      "security sandbox receipt error truth is incomplete",
    );
  }
  const errorClassValue =
    receipt.errorClass === null
      ? null
      : exactText(
          receipt.errorClass,
          "receipt.errorClass",
          128,
        );
  const errorFingerprint =
    receipt.errorFingerprint === null
      ? null
      : sha(
          receipt.errorFingerprint,
          "receipt.errorFingerprint",
        )!;

  if (receipt.status === "PROOF_OBSERVED") {
    if (
      receipt.completionStatus !== "EXITED" ||
      receipt.replayDisposition !==
        "NO_REPLAY_NEEDED" ||
      resultEvidenceSha256 === null ||
      errorClassValue !== null ||
      errorFingerprint !== null
    ) {
      throw new Error(
        "security sandbox PROOF_OBSERVED receipt carries impossible terminal truth",
      );
    }
  } else if (
    receipt.replayDisposition !==
    "NEW_ATTEMPT_REQUIRED"
  ) {
    throw new Error(
      "security sandbox NEEDS_VALIDATION receipt must require a new attempt",
    );
  }

  return Object.freeze({
    ...receipt,
    operationId,
    proofAttemptId,
    validationDecisionSha256,
    predecessorFindingSha256,
    sourceTreeSha256,
    adapterRegistrationSha256,
    specSha256,
    resultEvidenceSha256,
    artifactSetSha256,
    budgetLedgerSha256Before,
    budgetLedgerSha256After,
    invokedAt,
    errorClass: errorClassValue,
    errorFingerprint,
    receiptSha256:
      normalizedReceiptSha256,
  });
}

export function validateSecuritySandboxReceiptAgainstLineage(
  adapter: SecuritySandboxAdapter,
  input: SecuritySandboxInvocationInput,
  receiptInput: SecuritySandboxReceipt,
): Readonly<{
  receipt: SecuritySandboxReceipt;
  registration:
    SecuritySandboxAdapterRegistration;
  spec: SecuritySandboxExecutionSpec;
  decisionSha256: string;
  sourceTreeSha256: string;
}> {
  assertSandboxAuthority(
    input.sandboxAuthority,
  );
  const decision =
    validateSecurityValidationDecisionAgainstLineage(
      input.threatModel,
      input.coverageLedger,
      input.hunterSpawn,
      input.candidatePacket,
      input.validatorSpawn,
      input.validationDecision,
    );
  if (
    decision.record.disposition !==
      "NEEDS_VALIDATION" ||
    decision.record.resultFinding.record.state !==
      "NEEDS_VALIDATION"
  ) {
    throw new Error(
      "SEC5 proof publication requires authoritative NEEDS_VALIDATION lineage",
    );
  }

  const registration =
    normalizeSecuritySandboxAdapterRegistration(
      adapter.registration,
    );
  const registrationSha256 =
    securitySandboxAdapterRegistrationSha256(
      registration,
    );
  const spec =
    normalizeSecuritySandboxExecutionSpec(
      input.spec,
    );
  const receipt =
    validateSecuritySandboxReceipt(
      receiptInput,
    );

  if (
    receipt.validationDecisionSha256 !==
      decision.recordSha256 ||
    receipt.predecessorFindingSha256 !==
      decision.record.resultFinding.recordSha256 ||
    receipt.sourceTreeSha256 !==
      decision.record.sourceTreeSha256 ||
    receipt.adapterRegistrationSha256 !==
      registrationSha256 ||
    receipt.specSha256 !==
      spec.specSha256 ||
    receipt.proofAttemptId !==
      spec.proofAttemptId
  ) {
    throw new Error(
      "security sandbox receipt authoritative lineage binding mismatch",
    );
  }
  if (
    Date.parse(receipt.invokedAt) <
    Date.parse(decision.record.decidedAt)
  ) {
    throw new RangeError(
      "security sandbox receipt predates authoritative NEEDS_VALIDATION decision",
    );
  }

  return Object.freeze({
    receipt,
    registration,
    spec,
    decisionSha256:
      decision.recordSha256,
    sourceTreeSha256:
      decision.record.sourceTreeSha256,
  });
}


export function securitySandboxProofEvidenceRefs(
  adapter: SecuritySandboxAdapter,
  input: SecuritySandboxInvocationInput,
  outcome: SecuritySandboxOutcome,
): SecuritySandboxProofEvidence {
  const lineage =
    validateSecuritySandboxReceiptAgainstLineage(
      adapter,
      input,
      outcome.receipt,
    );
  const receipt = lineage.receipt;

  if (
    receipt.status !== "PROOF_OBSERVED" ||
    receipt.completionStatus !== "EXITED" ||
    receipt.resultEvidenceSha256 === null ||
    receipt.replayDisposition !==
      "NO_REPLAY_NEEDED"
  ) {
    throw new Error(
      "SEC5 proof evidence is unavailable; finding remains NEEDS_VALIDATION",
    );
  }
  if (outcome.result === null) {
    throw new Error(
      "SEC5 proof publication requires the bound sandbox adapter result",
    );
  }

  const request: SecuritySandboxAdapterRequest =
    Object.freeze({
      schemaVersion:
        "toadaid.security-sandbox-adapter-request.v1",
      operationId:
        receipt.operationId,
      validationDecisionSha256:
        lineage.decisionSha256,
      sourceTreeSha256:
        lineage.sourceTreeSha256,
      spec: lineage.spec,
    });
  const result =
    normalizeAdapterResult(
      outcome.result,
      request,
    );
  if (result.status !== "EXITED") {
    throw new Error(
      "SEC5 proof publication requires an EXITED sandbox result",
    );
  }

  const registrationSha256 =
    securitySandboxAdapterRegistrationSha256(
      lineage.registration,
    );
  const expectedResultEvidenceSha256 =
    resultEvidenceSha256(
      result,
      request,
      registrationSha256,
    );
  if (
    receipt.resultEvidenceSha256 !==
    expectedResultEvidenceSha256
  ) {
    throw new Error(
      "security sandbox proof result evidence binding mismatch",
    );
  }

  const artifacts =
    result.artifacts ?? [];
  const expectedArtifactSetSha256 =
    artifacts.length === 0
      ? null
      : sha256(artifacts);
  if (
    receipt.artifactSetSha256 !==
    expectedArtifactSetSha256
  ) {
    throw new Error(
      "security sandbox proof artifact-set binding mismatch",
    );
  }

  const refs: readonly SecurityEvidenceRef[] =
    Object.freeze([
      Object.freeze({
        id: "sec5-sandbox-proof",
        sha256: receipt.receiptSha256,
      }),
      Object.freeze({
        id: "sec5-sandbox-result",
        sha256:
          receipt.resultEvidenceSha256,
      }),
    ]);
  return Object.freeze({
    receiptSha256:
      receipt.receiptSha256,
    evidenceRefs: refs,
  });
}
