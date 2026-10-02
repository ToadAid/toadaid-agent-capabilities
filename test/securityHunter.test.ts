import assert from "node:assert/strict";
import test from "node:test";

import type {
  CapabilityAuthorityDecision,
} from "../src/capabilityPolicy.js";
import {
  createRunBudgetLedger,
} from "../src/runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "../src/runBudgetTypes.js";
import type {
  RunResumeAuthorityDecision,
} from "../src/runStateCapsule.js";
import {
  createSecurityThreatModel,
} from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
  planNextSecurityHunterAssignment,
  recordSecurityCoverage,
} from "../src/securityCoverage.js";
import {
  assertSecurityHunterSourcePathAllowed,
  createSecurityHunterCandidatePacket,
  spawnSecurityHunterChild,
} from "../src/securityHunter.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const NOW = "2026-10-02T18:00:00.000Z";

const area = {
  areaId: "policy",
  label: "Policy core",
  paths: ["src/policy"],
} as const;

function threatModel() {
  return createSecurityThreatModel({
    auditId: "sec3-audit",
    runId: "sec3-root",
    repositoryIdentitySha256: H1,
    sourceRevision: "21ee1c9",
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
        sourcePaths: ["src/policy/index.ts"],
        riskSignals: ["AUTHORITY_BOUNDARY"],
      }],
      trustBoundaries: [],
    },
    createdAt: NOW,
  });
}

function assignmentFixture() {
  const model = threatModel();
  const ledger = createSecurityCoverageLedger(
    model,
    {
      ledgerId: "sec3-coverage",
      areas: [area],
      createdAt: NOW,
    },
  );
  const assignment = planNextSecurityHunterAssignment(
    model,
    ledger,
    {
      assignmentId: "sec3-assignment",
      budget: {
        modelTokens: 12_000,
        toolCalls: 20,
        networkRequests: 0,
        wallClockMs: 120_000,
      },
      plannedAt: "2026-10-02T18:01:00.000Z",
    },
  );
  assert.ok(assignment);
  return { model, ledger, assignment };
}

function allowDecision(
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

function blockDecision(
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

function parentAllow(
  capabilityId: string,
): RunResumeAuthorityDecision {
  return {
    schemaVersion:
      "toadaid.run-resume-authority.v1",
    capabilityId,
    decision: "ALLOW",
    reason:
      "ALLOWED_BY_SNAPSHOT_AND_CURRENT_POLICY",
    snapshotDecision: "ALLOW",
    currentDecision: "ALLOW",
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

function parentBudget() {
  return createRunBudgetLedger({
    budgetId: "sec3-parent-budget",
    runId: "sec3-root",
    createdAt: NOW,
    limits: {
      modelRequests: 20,
      inputTokens: 50_000,
      outputTokens: 50_000,
      toolCalls: 100,
      networkRequests: 10,
      retries: 10,
      wallClockMs: 600_000,
      childTasks: 10,
    },
  });
}

function spawnFixture(
  overrides: Partial<Parameters<
    typeof spawnSecurityHunterChild
  >[0]> = {},
) {
  const { model, ledger, assignment } =
    assignmentFixture();
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  return {
    model,
    ledger,
    assignment,
    spawn: spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: ledger,
      parentAuthority: [
        parentAllow("host:file-read"),
        parentAllow("host:session"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
          blockDecision("host:file-write"),
          blockDecision("host:command-execute"),
          blockDecision("secret:materialize"),
          blockDecision("review:fix"),
        ],
      },
      parentBudget: parentBudget(),
      q1Limits: q1Limits(),
      childTaskId: "sec3-hunter-1",
      childBudgetId: "sec3-child-budget",
      allocationId: "sec3-allocation",
      createdAt,
      ...overrides,
    }),
  };
}

test("SEC3 spawns a P5 child with only read-only source capabilities", () => {
  const { spawn } = spawnFixture();
  assert.deepEqual(
    spawn.delegatedCapabilities,
    ["host:file-read", "host:session"],
  );
  assert.deepEqual(
    spawn.childTask.task.delegatedCapabilities,
    ["host:file-read", "host:session"],
  );
  assert.equal(
    spawn.childTask.task.status,
    "CREATED",
  );
  assert.equal(
    spawn.childTask.task.runState.phase,
    "security-hunt",
  );
});

test("SEC3 refuses any extra ALLOW in the child authority snapshot", () => {
  const { model, ledger, assignment } =
    assignmentFixture();
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  assert.throws(
    () => spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: ledger,
      parentAuthority: [
        parentAllow("host:file-read"),
        parentAllow("host:session"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
          allowDecision("host:file-write"),
        ],
      },
      parentBudget: parentBudget(),
      q1Limits: q1Limits(),
      createdAt,
    }),
    /may ALLOW only host:file-read and host:session/,
  );
});

test("SEC3 parent authority must actually allow the read-only delegation", () => {
  const { model, ledger, assignment } =
    assignmentFixture();
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  assert.throws(
    () => spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: ledger,
      parentAuthority: [
        parentAllow("host:file-read"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
        ],
      },
      parentBudget: parentBudget(),
      q1Limits: q1Limits(),
      createdAt,
    }),
    /cannot delegate capability not allowed by parent: host:session/,
  );
});

test("SEC3 Q1 child allocation is real, child-bound, and non-nesting", () => {
  const { spawn } = spawnFixture();
  assert.equal(
    spawn.childBudget.record.childTaskId,
    spawn.childTask.task.childTaskId,
  );
  assert.equal(
    spawn.childBudget.record.runId,
    spawn.childTask.task.childTaskId,
  );
  assert.equal(
    spawn.childBudget.record.limits.childTasks,
    0,
  );
  assert.equal(
    spawn.childBudget.record.limits.networkRequests,
    0,
  );
  assert.equal(
    spawn.childBudget.record.limits.retries,
    0,
  );
  assert.equal(
    typeof spawn.budgetAllocationSha256,
    "string",
  );
});

test("SEC3 Q1 limits cannot exceed the SEC2 assignment budget", () => {
  const { model, ledger, assignment } =
    assignmentFixture();
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  assert.throws(
    () => spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: ledger,
      parentAuthority: [
        parentAllow("host:file-read"),
        parentAllow("host:session"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
        ],
      },
      parentBudget: parentBudget(),
      q1Limits: q1Limits({
        inputTokens: 8_000,
        outputTokens: 8_000,
      }),
      createdAt,
    }),
    /token limits exceed/,
  );
});

test("SEC3 isolated Hunters refuse network, retry, and nested-child budgets", () => {
  for (const [field, expected] of [
    ["networkRequests", /network budget must be zero/],
    ["retries", /retries must be zero/],
    ["childTasks", /cannot allocate nested child tasks/],
  ] as const) {
    const { model, ledger, assignment } =
      assignmentFixture();
    const createdAt =
      "2026-10-02T18:02:00.000Z";
    assert.throws(
      () => spawnSecurityHunterChild({
        assignment,
        threatModel: model,
        coverageLedger: ledger,
        parentAuthority: [
          parentAllow("host:file-read"),
          parentAllow("host:session"),
        ],
        childAuthoritySnapshot: {
          capturedAt: createdAt,
          decisions: [
            allowDecision("host:file-read"),
            allowDecision("host:session"),
          ],
        },
        parentBudget: parentBudget(),
        q1Limits: q1Limits({ [field]: 1 }),
        createdAt,
      }),
      expected,
    );
  }
});

test("SEC3 refuses a stale assignment after coverage predecessor changes", () => {
  const { model, ledger, assignment } =
    assignmentFixture();
  const advanced = recordSecurityCoverage(
    model,
    ledger,
    {
      areaId: assignment.areaId,
      attackClass: assignment.attackClass,
      disposition: "THIN",
      evidenceRefs: [
        { id: "new-evidence", sha256: H3 },
      ],
      inspectedAt:
        "2026-10-02T18:01:30.000Z",
    },
  );
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  assert.throws(
    () => spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: advanced,
      parentAuthority: [
        parentAllow("host:file-read"),
        parentAllow("host:session"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
        ],
      },
      parentBudget: parentBudget(),
      q1Limits: q1Limits(),
      createdAt,
    }),
    /coverage-ledger binding is stale/,
  );
});

test("SEC3 source reader guard allows only the assigned repository slice", () => {
  const { spawn } = spawnFixture();
  assert.equal(
    assertSecurityHunterSourcePathAllowed(
      spawn,
      "src/policy/check.ts",
    ),
    "src/policy/check.ts",
  );
  assert.throws(
    () => assertSecurityHunterSourcePathAllowed(
      spawn,
      "src/other/check.ts",
    ),
    /outside assignment scope/,
  );
  assert.throws(
    () => assertSecurityHunterSourcePathAllowed(
      spawn,
      "../secret.txt",
    ),
    /unsafe path segments/,
  );
});

test("SEC3 Hunter output can only create a CANDIDATE bound to its exact attack class", () => {
  const { model, ledger, spawn } = spawnFixture();
  const packet = createSecurityHunterCandidatePacket(
    model,
    ledger,
    spawn,
    {
      findingId: "candidate-1",
      title: "Possible policy bypass",
      rationale: "Observed an authority edge needing validation.",
      evidenceRefs: [
        { id: "trace", sha256: H3 },
      ],
      sourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      proofPlan: [{
        stepId: "p1",
        description:
          "Re-read the exact policy branch and attempt to disprove the bypass hypothesis.",
      }],
      emittedAt:
        "2026-10-02T18:03:00.000Z",
    },
  );
  assert.equal(
    packet.record.candidate.record.state,
    "CANDIDATE",
  );
  assert.equal(
    packet.record.candidate.record.attackClass,
    spawn.attackClass,
  );
  assert.equal(
    packet.record.hunterIdentitySha256,
    spawn.hunterIdentitySha256,
  );
});

test("SEC3 candidate source evidence cannot escape the assigned area", () => {
  const { model, ledger, spawn } = spawnFixture();
  assert.throws(
    () => createSecurityHunterCandidatePacket(
      model,
      ledger,
      spawn,
      {
        findingId: "candidate-outside",
        title: "Outside",
        rationale: "Outside scope.",
        evidenceRefs: [
          { id: "trace", sha256: H3 },
        ],
        sourceLocations: [{
          path: "src/unrelated.ts",
          startLine: 1,
          endLine: 2,
        }],
        proofPlan: [{
          stepId: "p1",
          description: "Disprove.",
        }],
        emittedAt:
          "2026-10-02T18:03:00.000Z",
      },
    ),
    /outside assignment scope/,
  );
});

test("SEC3 preserves supporting and challenging observations without collapsing a verdict", () => {
  const { model, ledger, spawn } = spawnFixture();
  const packet = createSecurityHunterCandidatePacket(
    model,
    ledger,
    spawn,
    {
      findingId: "candidate-disagreement",
      title: "Potential bypass",
      rationale: "Mixed evidence requires validator review.",
      evidenceRefs: [
        { id: "trace", sha256: H3 },
      ],
      sourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      proofPlan: [{
        stepId: "p1",
        description:
          "Try to falsify the candidate using exact source behavior.",
      }],
      observations: [
        {
          observationId: "support",
          position: "SUPPORTS_CANDIDATE",
          summary: "One branch appears to skip a guard.",
          evidenceRefs: [
            { id: "support-evidence", sha256: H3 },
          ],
          sourceLocations: [{
            path: "src/policy/check.ts",
            startLine: 12,
            endLine: 14,
          }],
        },
        {
          observationId: "challenge",
          position: "CHALLENGES_CANDIDATE",
          summary: "A caller may enforce the missing condition.",
          evidenceRefs: [
            { id: "challenge-evidence", sha256: H4 },
          ],
          sourceLocations: [{
            path: "src/policy/caller.ts",
            startLine: 30,
            endLine: 35,
          }],
        },
      ],
      emittedAt:
        "2026-10-02T18:03:00.000Z",
    },
  );

  assert.deepEqual(
    packet.record.observations.map(
      (entry) => entry.position,
    ),
    [
      "CHALLENGES_CANDIDATE",
      "SUPPORTS_CANDIDATE",
    ],
  );
  assert.equal(
    "verdict" in packet.record,
    false,
  );
});

test("SEC3 output binds exact source, assignment, child, budget, and evidence SHAs", () => {
  const { model, ledger, spawn } = spawnFixture();
  const packet = createSecurityHunterCandidatePacket(
    model,
    ledger,
    spawn,
    {
      findingId: "candidate-binding",
      title: "Binding proof",
      rationale: "Exact provenance.",
      evidenceRefs: [
        { id: "trace", sha256: H3 },
      ],
      sourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 1,
        endLine: 1,
      }],
      proofPlan: [{
        stepId: "p1",
        description: "Validate exact source.",
        expectedEvidenceRefs: [
          { id: "expected", sha256: H4 },
        ],
      }],
      emittedAt:
        "2026-10-02T18:03:00.000Z",
    },
  );

  assert.equal(
    packet.record.assignmentSha256,
    spawn.assignmentSha256,
  );
  assert.equal(
    packet.record.childTaskSha256,
    spawn.childTask.taskSha256,
  );
  assert.equal(
    packet.record.childBudgetLedgerSha256,
    spawn.childBudget.recordSha256,
  );
  assert.equal(
    packet.record.sourceTreeSha256,
    spawn.sourceTreeSha256,
  );
  assert.equal(
    packet.record.candidate.record.evidenceRefs[0]?.sha256,
    H3,
  );
  assert.equal(
    packet.record.proofPlan[0]
      ?.expectedEvidenceRefs[0]?.sha256,
    H4,
  );
});

test("SEC3 candidate packet refuses forged spawn provenance", () => {
  const { model, ledger, spawn } = spawnFixture();
  const fakeSha = "9".repeat(64);

  const candidateInput = (
    path = "src/policy/check.ts",
  ) => ({
    findingId: "candidate-forge-probe",
    title: "Forge probe",
    rationale: "Must fail before candidate emission.",
    evidenceRefs: [
      { id: "trace", sha256: H3 },
    ],
    sourceLocations: [{
      path,
      startLine: 1,
      endLine: 2,
    }],
    proofPlan: [{
      stepId: "p1",
      description: "Attempt to disprove.",
    }],
    emittedAt:
      "2026-10-02T18:03:00.000Z",
  });

  assert.throws(
    () => createSecurityHunterCandidatePacket(
      model,
      ledger,
      {
        ...spawn,
        sourceScopePaths: ["src"],
      },
      candidateInput("src/unrelated.ts"),
    ),
    /source scope differs from assignment/,
  );

  assert.throws(
    () => createSecurityHunterCandidatePacket(
      model,
      ledger,
      {
        ...spawn,
        hunterIdentitySha256: fakeSha,
      },
      candidateInput(),
    ),
    /identity digest mismatch/,
  );

  assert.throws(
    () => createSecurityHunterCandidatePacket(
      model,
      ledger,
      {
        ...spawn,
        childTask: {
          ...spawn.childTask,
          taskSha256: fakeSha,
        },
      },
      candidateInput(),
    ),
    /child-task integrity mismatch/,
  );

  assert.throws(
    () => createSecurityHunterCandidatePacket(
      model,
      ledger,
      {
        ...spawn,
        childBudget: {
          ...spawn.childBudget,
          recordSha256: fakeSha,
        },
      },
      candidateInput(),
    ),
    /run budget ledger integrity mismatch/,
  );
});

test("SEC3 real Q1 parent ledger can refuse an oversized child allocation", () => {
  const { model, ledger, assignment } =
    assignmentFixture();
  const createdAt =
    "2026-10-02T18:02:00.000Z";
  const tinyParent = createRunBudgetLedger({
    budgetId: "tiny-parent",
    runId: "sec3-root",
    createdAt: NOW,
    limits: {
      modelRequests: 1,
      inputTokens: 100,
      outputTokens: 100,
      toolCalls: 1,
      networkRequests: 0,
      retries: 0,
      wallClockMs: 1_000,
      childTasks: 1,
    },
  });

  assert.throws(
    () => spawnSecurityHunterChild({
      assignment,
      threatModel: model,
      coverageLedger: ledger,
      parentAuthority: [
        parentAllow("host:file-read"),
        parentAllow("host:session"),
      ],
      childAuthoritySnapshot: {
        capturedAt: createdAt,
        decisions: [
          allowDecision("host:file-read"),
          allowDecision("host:session"),
        ],
      },
      parentBudget: tinyParent,
      q1Limits: q1Limits(),
      createdAt,
    }),
    /child budget allocation exceeds parent remaining budget/,
  );
});
