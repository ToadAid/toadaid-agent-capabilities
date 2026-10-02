import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_CAPABILITY_MANIFEST,
} from "../src/capabilityPolicy.js";
import type {
  CapabilityAuthorityDecision,
} from "../src/capabilityPolicy.js";
import {
  createRunBudgetLedger,
} from "../src/runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "../src/runBudgetTypes.js";
import {
  createSecurityThreatModel,
} from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
  planNextSecurityHunterAssignment,
} from "../src/securityCoverage.js";
import {
  createSecurityHunterCandidatePacket,
  spawnSecurityHunterChild,
} from "../src/securityHunter.js";
import {
  resolveSecurityValidation,
  spawnSecurityValidatorChild,
} from "../src/securityValidator.js";
import {
  invokeSecuritySandboxProof,
  normalizeSecuritySandboxExecutionSpec,
  securitySandboxProofEvidenceRefs,
  validateSecuritySandboxReceipt,
  validateSecuritySandboxReceiptAgainstLineage,
} from "../src/securitySandbox.js";
import type {
  SecuritySandboxAdapter,
  SecuritySandboxAdapterRequest,
  SecuritySandboxAdapterResult,
} from "../src/securitySandboxTypes.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const EMPTY_SHA =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function allow(
  capabilityId: string,
): CapabilityAuthorityDecision {
  return {
    schemaVersion:
      "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: "ALLOW",
    reason: "AUTHORIZED_BY_POLICY",
    trace: [],
  };
}

function block(
  capabilityId: string,
): CapabilityAuthorityDecision {
  return {
    schemaVersion:
      "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: "BLOCK",
    reason: "BLOCKED_BY_POLICY",
    trace: [],
  };
}

function q1Limits(
  overrides: Partial<RunBudgetVector> = {},
): RunBudgetVector {
  return {
    modelRequests: 4,
    inputTokens: 4_000,
    outputTokens: 4_000,
    toolCalls: 10,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 60_000,
    childTasks: 0,
    ...overrides,
  };
}

function fixture() {
  const model = createSecurityThreatModel({
    auditId: "sec5-audit",
    runId: "sec5-root",
    repositoryIdentitySha256: H1,
    sourceRevision: "6032042",
    sourceTreeSha256: H2,
    scope: {
      includePaths: ["src"],
      excludePaths: [],
    },
    configurationSha256: H3,
    ruleSetSha256: H4,
    architecture: {
      components: [{
        componentId: "policy",
        kind: "SECURITY_CONTROL",
        label: "Policy",
        sourcePaths: [
          "src/policy/index.ts",
        ],
        riskSignals: [
          "AUTHORITY_BOUNDARY",
        ],
      }],
      trustBoundaries: [],
    },
    createdAt:
      "2026-10-02T20:00:00.000Z",
  });

  const ledger = createSecurityCoverageLedger(
    model,
    {
      ledgerId: "sec5-coverage",
      areas: [{
        areaId: "policy",
        label: "Policy",
        paths: ["src/policy"],
      }],
      createdAt:
        "2026-10-02T20:00:00.000Z",
    },
  );
  const assignment =
    planNextSecurityHunterAssignment(
      model,
      ledger,
      {
        assignmentId:
          "sec5-assignment",
        budget: {
          modelTokens: 12_000,
          toolCalls: 20,
          networkRequests: 0,
          wallClockMs: 120_000,
        },
        plannedAt:
          "2026-10-02T20:01:00.000Z",
      },
    );
  assert.ok(assignment);

  const budget = createRunBudgetLedger({
    budgetId: "sec5-root-budget",
    runId: "sec5-root",
    createdAt:
      "2026-10-02T20:00:00.000Z",
    limits: {
      modelRequests: 30,
      inputTokens: 100_000,
      outputTokens: 100_000,
      toolCalls: 200,
      networkRequests: 10,
      retries: 10,
      wallClockMs: 900_000,
      childTasks: 10,
    },
  });

  const hunter = spawnSecurityHunterChild({
    assignment,
    threatModel: model,
    coverageLedger: ledger,
    parentAuthority: [
      {
        schemaVersion:
          "toadaid.run-resume-authority.v1",
        capabilityId: "host:file-read",
        decision: "ALLOW",
        reason:
          "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY",
        snapshotDecision: "ALLOW",
        currentDecision: "ALLOW",
      },
      {
        schemaVersion:
          "toadaid.run-resume-authority.v1",
        capabilityId: "host:session",
        decision: "ALLOW",
        reason:
          "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY",
        snapshotDecision: "ALLOW",
        currentDecision: "ALLOW",
      },
    ],
    childAuthoritySnapshot: {
      capturedAt:
        "2026-10-02T20:02:00.000Z",
      decisions: [
        allow("host:file-read"),
        allow("host:session"),
      ],
    },
    parentBudget: budget,
    q1Limits: q1Limits(),
    childTaskId: "sec5-hunter",
    childBudgetId:
      "sec5-hunter-budget",
    allocationId:
      "sec5-hunter-allocation",
    createdAt:
      "2026-10-02T20:02:00.000Z",
  });

  const candidate =
    createSecurityHunterCandidatePacket(
      model,
      ledger,
      hunter,
      {
        findingId: "sec5-candidate",
        title:
          "Potential authority bypass",
        rationale:
          "Read-only review cannot establish runtime exploitability.",
        evidenceRefs: [{
          id: "hunter-trace",
          sha256: H3,
        }],
        sourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        proofPlan: [{
          stepId: "p1",
          description:
            "Execute a bounded proof in the governed sandbox.",
        }],
        emittedAt:
          "2026-10-02T20:03:00.000Z",
      },
    );

  const validator =
    spawnSecurityValidatorChild({
      threatModel: model,
      coverageLedger: ledger,
      hunterSpawn: hunter,
      candidatePacket: candidate,
      validatorIdentitySha256: H5,
      parentAuthority: [
        {
          schemaVersion:
            "toadaid.run-resume-authority.v1",
          capabilityId:
            "host:file-read",
          decision: "ALLOW",
          reason:
            "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY",
          snapshotDecision: "ALLOW",
          currentDecision: "ALLOW",
        },
        {
          schemaVersion:
            "toadaid.run-resume-authority.v1",
          capabilityId:
            "host:session",
          decision: "ALLOW",
          reason:
            "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY",
          snapshotDecision: "ALLOW",
          currentDecision: "ALLOW",
        },
      ],
      childAuthoritySnapshot: {
        capturedAt:
          "2026-10-02T20:04:00.000Z",
        decisions: [
          allow("host:file-read"),
          allow("host:session"),
        ],
      },
      parentBudget:
        hunter.parentBudget,
      q1Limits: q1Limits(),
      childTaskId:
        "sec5-validator",
      childBudgetId:
        "sec5-validator-budget",
      allocationId:
        "sec5-validator-allocation",
      createdAt:
        "2026-10-02T20:04:00.000Z",
    });

  const needsValidation =
    resolveSecurityValidation(
      model,
      ledger,
      hunter,
      candidate,
      validator,
      {
        disposition:
          "NEEDS_VALIDATION",
        reason:
          "Bounded sandbox proof execution is required.",
        decidedAt:
          "2026-10-02T20:05:00.000Z",
      },
    );

  return {
    model,
    ledger,
    hunter,
    candidate,
    validator,
    needsValidation,
  };
}

function spec() {
  return {
    proofAttemptId:
      "sec5-proof-attempt-1",
    sourceRoot: "/sandbox/source",
    scratchRoot: "/sandbox/scratch",
    cwd: "/sandbox/scratch/work",
    executable: "/usr/bin/node",
    executableSha256: H6,
    argv: [
      "/sandbox/source/proof.js",
    ],
    limits: {
      cpuTimeMs: 5_000,
      memoryBytes:
        256 * 1024 * 1024,
      maxProcesses: 2,
      wallClockMs: 10_000,
      maxOutputBytes:
        64 * 1024,
      maxArtifactBytes:
        1024 * 1024,
      maxArtifacts: 4,
    },
  } as const;
}

function goodResult(
  request: SecuritySandboxAdapterRequest,
): SecuritySandboxAdapterResult {
  return {
    schemaVersion:
      "toadaid.security-sandbox-adapter-result.v1",
    operationId:
      request.operationId,
    status: "EXITED",
    exitCode: 0,
    stdoutSha256: EMPTY_SHA,
    stdoutBytes: 0,
    stderrSha256: EMPTY_SHA,
    stderrBytes: 0,
    cpuTimeMs: 100,
    peakMemoryBytes: 1024 * 1024,
    processCount: 1,
    artifacts: [{
      id: "proof-json",
      kind: "application/json",
      sha256: H7,
      byteLength: 128,
    }],
    attestation: {
      networkDisabled: true,
      sourceReadOnly: true,
      scratchOnlyWritable: true,
      environmentEmpty: true,
      homeUnavailable: true,
      shellUsed: false,
      stdinUsed: false,
      processTreeContained: true,
      cpuLimitEnforced: true,
      memoryLimitEnforced: true,
      processLimitEnforced: true,
      wallClockLimitEnforced: true,
      artifactsContentAddressed: true,
      sourceTreeSha256:
        request.sourceTreeSha256,
      specSha256:
        request.spec.specSha256,
      limitsSha256:
        request.spec.limitsSha256,
    },
    adapterEvidenceSha256: H7,
  };
}

function adapter(
  invoke?: SecuritySandboxAdapter["invoke"],
): SecuritySandboxAdapter {
  return {
    registration: {
      schemaVersion:
        "toadaid.security-sandbox-adapter-registration.v1",
      adapterId:
        "sec5-test-adapter",
      providerDescriptorSha256: H6,
      implementationFingerprintSha256: H7,
      sandboxKind:
        "TEST_ISOLATED_SANDBOX",
      guarantees: [
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
      ],
    },
    invoke:
      invoke ??
      (async (request) =>
        goodResult(request)),
  };
}

function invocationInput() {
  const f = fixture();
  const budget =
    createRunBudgetLedger({
      budgetId:
        "sec5-sandbox-budget",
      runId:
        "sec5-sandbox-run",
      createdAt:
        "2026-10-02T20:05:00.000Z",
      limits: {
        modelRequests: 0,
        inputTokens: 0,
        outputTokens: 0,
        toolCalls: 4,
        networkRequests: 0,
        retries: 0,
        wallClockMs: 40_000,
        childTasks: 0,
      },
    });
  return {
    ...f,
    input: {
      threatModel: f.model,
      coverageLedger: f.ledger,
      hunterSpawn: f.hunter,
      candidatePacket: f.candidate,
      validatorSpawn: f.validator,
      validationDecision:
        f.needsValidation,
      sandboxAuthority:
        allow(
          "security:sandbox-exec",
        ),
      budget,
      spec: spec(),
    },
  };
}

test("SEC5 installs dedicated sandbox capability BLOCK by default", () => {
  const definition =
    CORE_CAPABILITY_MANIFEST.capabilities.find(
      (entry) =>
        entry.id ===
        "security:sandbox-exec",
    );
  assert.equal(
    definition?.defaultDecision,
    "BLOCK",
  );
});

test("SEC5 host command authority cannot substitute for dedicated sandbox authority", async () => {
  const { input } = invocationInput();
  await assert.rejects(
    () => invokeSecuritySandboxProof(
      adapter(),
      {
        ...input,
        sandboxAuthority:
          allow("host:command-exec"),
      },
    ),
    /requires separate ALLOW authority for security:sandbox-exec/,
  );
});

test("SEC5 blocked sandbox authority refuses before adapter dispatch", async () => {
  const { input } = invocationInput();
  let calls = 0;
  await assert.rejects(
    () => invokeSecuritySandboxProof(
      adapter(async (request) => {
        calls += 1;
        return goodResult(request);
      }),
      {
        ...input,
        sandboxAuthority:
          block(
            "security:sandbox-exec",
          ),
      },
    ),
    /requires separate ALLOW authority/,
  );
  assert.equal(calls, 0);
});

test("SEC5 sandbox accepts only authoritative NEEDS_VALIDATION lineage", async () => {
  const {
    model,
    ledger,
    hunter,
    candidate,
    validator,
    input,
  } = invocationInput();

  const confirmed =
    resolveSecurityValidation(
      model,
      ledger,
      hunter,
      candidate,
      validator,
      {
        disposition: "CONFIRMED",
        proofEvidenceRefs: [{
          id: "old-proof",
          sha256: H7,
        }],
        reproducedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        decidedAt:
          "2026-10-02T20:05:00.000Z",
      },
    );

  await assert.rejects(
    () => invokeSecuritySandboxProof(
      adapter(),
      {
        ...input,
        validationDecision:
          confirmed,
      },
    ),
    /allowed only for authoritative NEEDS_VALIDATION findings/,
  );
});

test("SEC5 execution spec hard-codes network env home shell stdin and scratch-only cwd", () => {
  const normalized =
    normalizeSecuritySandboxExecutionSpec(
      spec(),
    );
  assert.equal(
    normalized.networkMode,
    "DISABLED",
  );
  assert.equal(
    normalized.environmentMode,
    "EMPTY",
  );
  assert.equal(
    normalized.homeMode,
    "UNAVAILABLE",
  );
  assert.equal(
    normalized.shell,
    false,
  );
  assert.equal(
    normalized.stdinMode,
    "DISABLED",
  );
  assert.equal(
    normalized.sourceFilesystem,
    "READ_ONLY",
  );
  assert.equal(
    normalized.scratchFilesystem,
    "READ_WRITE",
  );
  assert.equal(
    normalized.otherFilesystem,
    "UNMOUNTED",
  );

  assert.throws(
    () =>
      normalizeSecuritySandboxExecutionSpec({
        ...spec(),
        cwd:
          "/sandbox/source",
      }),
    /cwd must be inside the scratch root/,
  );
  assert.throws(
    () =>
      normalizeSecuritySandboxExecutionSpec({
        ...spec(),
        scratchRoot:
          "/sandbox/source/tmp",
      }),
    /source and scratch roots must be disjoint/,
  );
});

test("SEC5 resource limits are explicit and bounded", () => {
  assert.throws(
    () =>
      normalizeSecuritySandboxExecutionSpec({
        ...spec(),
        limits: {
          ...spec().limits,
          maxProcesses: 17,
        },
      }),
    /maxProcesses/,
  );
  assert.throws(
    () =>
      normalizeSecuritySandboxExecutionSpec({
        ...spec(),
        limits: {
          ...spec().limits,
          wallClockMs: 120_001,
        },
      }),
    /wallClockMs/,
  );
});

test("SEC5 missing sandbox guarantee refuses before adapter dispatch", async () => {
  const { input } = invocationInput();
  const bad = adapter();
  const guarantees =
    bad.registration.guarantees.filter(
      (entry) =>
        entry !== "NETWORK_DISABLED",
    );
  let calls = 0;
  await assert.rejects(
    () => invokeSecuritySandboxProof(
      {
        registration: {
          ...bad.registration,
          guarantees,
        },
        invoke: async (request) => {
          calls += 1;
          return goodResult(request);
        },
      },
      input,
    ),
    /missing required guarantee: NETWORK_DISABLED/,
  );
  assert.equal(calls, 0);
});

test("SEC5 Q1 preflight blocks insufficient budget before adapter dispatch", async () => {
  const { input } = invocationInput();
  const budget =
    createRunBudgetLedger({
      budgetId: "too-small",
      runId: "sec5-small",
      createdAt:
        "2026-10-02T20:05:00.000Z",
      limits: {
        modelRequests: 0,
        inputTokens: 0,
        outputTokens: 0,
        toolCalls: 1,
        networkRequests: 0,
        retries: 0,
        wallClockMs: 1,
        childTasks: 0,
      },
    });
  let calls = 0;
  await assert.rejects(
    () => invokeSecuritySandboxProof(
      adapter(async (request) => {
        calls += 1;
        return goodResult(request);
      }),
      {
        ...input,
        budget,
      },
    ),
    /SEC5 sandbox Q1 budget exceeded/,
  );
  assert.equal(calls, 0);
});

test("SEC5 successful bounded execution spends Q1 and emits content-addressed proof only", async () => {
  const { input } = invocationInput();
  const sandboxAdapter = adapter();
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-success",
      },
    );

  assert.equal(
    outcome.receipt.status,
    "PROOF_OBSERVED",
  );
  assert.equal(
    outcome.receipt.completionStatus,
    "EXITED",
  );
  assert.equal(
    outcome.receipt.replayDisposition,
    "NO_REPLAY_NEEDED",
  );
  assert.notEqual(
    outcome.receipt
      .budgetLedgerSha256Before,
    outcome.receipt
      .budgetLedgerSha256After,
  );
  assert.equal(
    outcome.result?.artifacts?.[0]
      ?.sha256,
    H7,
  );
  const evidence =
    securitySandboxProofEvidenceRefs(
      sandboxAdapter,
      input,
      outcome,
    );
  assert.equal(
    evidence.evidenceRefs.length,
    2,
  );
  assert.equal(
    evidence.evidenceRefs[0]?.sha256,
    outcome.receipt.receiptSha256,
  );
});

test("SEC5 artifact metadata rejects raw payload fields", async () => {
  const { input } = invocationInput();
  const outcome =
    await invokeSecuritySandboxProof(
      adapter(async (request) => ({
        ...goodResult(request),
        artifacts: [{
          id: "proof-json",
          kind: "application/json",
          sha256: H7,
          byteLength: 128,
          bytes: "raw-secret-payload",
        } as never],
      })),
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-raw-artifact",
      },
    );
  assert.equal(
    outcome.receipt.status,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    outcome.result,
    null,
  );
  assert.equal(
    outcome.receipt.replayDisposition,
    "NEW_ATTEMPT_REQUIRED",
  );
});

test("SEC5 failed runtime attestation cannot become proof evidence", async () => {
  const { input } = invocationInput();
  const sandboxAdapter = adapter(async (request) => ({
    ...goodResult(request),
    attestation: {
      ...goodResult(request)
        .attestation,
      networkDisabled: false,
    } as never,
  }));
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-bad-attestation",
      },
    );
  assert.equal(
    outcome.receipt.status,
    "NEEDS_VALIDATION",
  );
  assert.throws(
    () =>
      securitySandboxProofEvidenceRefs(
        sandboxAdapter,
        input,
        outcome,
      ),
    /proof evidence is unavailable/,
  );
});

test("SEC5 timeout never blind-replays and remains NEEDS_VALIDATION", async () => {
  const { input } = invocationInput();
  let calls = 0;
  const sandboxAdapter = adapter(async (request) => {
    calls += 1;
    return {
      ...goodResult(request),
      status: "TIMED_OUT",
      exitCode: null,
    };
  });
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-timeout",
      },
    );
  assert.equal(calls, 1);
  assert.equal(
    outcome.receipt.status,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    outcome.receipt.replayDisposition,
    "NEW_ATTEMPT_REQUIRED",
  );
  assert.throws(
    () =>
      securitySandboxProofEvidenceRefs(
        sandboxAdapter,
        input,
        outcome,
      ),
    /proof evidence is unavailable/,
  );
});

test("SEC5 adapter crash returns NEEDS_VALIDATION receipt without automatic retry", async () => {
  const { input } = invocationInput();
  let calls = 0;
  const outcome =
    await invokeSecuritySandboxProof(
      adapter(async () => {
        calls += 1;
        throw new Error(
          "sandbox runtime crashed",
        );
      }),
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-crash",
      },
    );
  assert.equal(calls, 1);
  assert.equal(
    outcome.receipt.status,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    outcome.receipt.replayDisposition,
    "NEW_ATTEMPT_REQUIRED",
  );
  assert.equal(
    outcome.receipt.errorClass,
    "Error",
  );
});

test("SEC5 bounded runtime observations cannot exceed configured resource limits", async () => {
  const { input } = invocationInput();
  const outcome =
    await invokeSecuritySandboxProof(
      adapter(async (request) => ({
        ...goodResult(request),
        processCount:
          request.spec.limits
            .maxProcesses + 1,
      })),
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-over-limit",
      },
    );
  assert.equal(
    outcome.receipt.status,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    outcome.result,
    null,
  );
});

test("SEC5 proof evidence receipt cannot be forged by editing its SHA", async () => {
  const { input } = invocationInput();
  const sandboxAdapter = adapter();
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-integrity",
      },
    );
  assert.throws(
    () =>
      securitySandboxProofEvidenceRefs(
        sandboxAdapter,
        input,
        {
          ...outcome,
          receipt: {
            ...outcome.receipt,
            receiptSha256: H1,
          },
        },
      ),
    /receipt integrity mismatch/,
  );
});

test("SEC5 durable receipt parser refuses malformed result hash wrong authority and impossible proof/error truth", async () => {
  const { input } = invocationInput();
  const sandboxAdapter = adapter();
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-parser-regression",
      },
    );

  const crypto =
    await import("../src/invocationSchema.js");

  const reseal = (
    patch: Record<string, unknown>,
  ) => {
    const merged = {
      ...outcome.receipt,
      ...patch,
    };
    const {
      receiptSha256: _ignored,
      ...core
    } = merged;
    return {
      ...core,
      receiptSha256:
        crypto.sha256(core),
    } as typeof outcome.receipt;
  };

  assert.throws(
    () =>
      validateSecuritySandboxReceipt(
        reseal({
          resultEvidenceSha256:
            "not-a-sha256",
        }),
      ),
    /resultEvidenceSha256/,
  );

  assert.throws(
    () =>
      validateSecuritySandboxReceipt(
        reseal({
          sandboxAuthorityCapabilityId:
            "host:command-exec",
        }),
      ),
    /authority binding mismatch/,
  );

  assert.throws(
    () =>
      validateSecuritySandboxReceipt(
        reseal({
          errorClass: "Error",
          errorFingerprint: H1,
        }),
      ),
    /impossible terminal truth/,
  );
});

test("SEC5 proof publication refuses a self-consistent receipt not bound to the authoritative sandbox result", async () => {
  const { input } = invocationInput();
  const sandboxAdapter = adapter();
  const outcome =
    await invokeSecuritySandboxProof(
      sandboxAdapter,
      input,
      {
        now: () =>
          new Date(
            "2026-10-02T20:06:00.000Z",
          ),
        randomId: () =>
          "sec5-op-publication-lineage",
      },
    );
  assert.ok(outcome.result);

  const crypto =
    await import("../src/invocationSchema.js");
  const {
    receiptSha256: _ignored,
    ...core
  } = {
    ...outcome.receipt,
    resultEvidenceSha256: H1,
  };
  const forgedReceipt = {
    ...core,
    receiptSha256:
      crypto.sha256(core),
  } as typeof outcome.receipt;

  assert.doesNotThrow(
    () =>
      validateSecuritySandboxReceipt(
        forgedReceipt,
      ),
  );
  assert.doesNotThrow(
    () =>
      validateSecuritySandboxReceiptAgainstLineage(
        sandboxAdapter,
        input,
        forgedReceipt,
      ),
  );
  assert.throws(
    () =>
      securitySandboxProofEvidenceRefs(
        sandboxAdapter,
        input,
        {
          ...outcome,
          receipt: forgedReceipt,
        },
      ),
    /result evidence binding mismatch/,
  );
});
