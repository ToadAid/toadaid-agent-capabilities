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
} from "../src/securityCoverage.js";
import {
  createSecurityHunterCandidatePacket,
  spawnSecurityHunterChild,
} from "../src/securityHunter.js";
import {
  independentlyReverifyConfirmedFinding,
  resolveSecurityValidation,
  securityValidationDecisionRecordSha256,
  spawnSecurityValidatorChild,
  validateSecurityHunterCandidatePacketForValidation,
  validateSecurityValidationDecisionAgainstLineage,
  validateSecurityValidationDecisionEnvelope,
} from "../src/securityValidator.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const NOW = "2026-10-02T19:00:00.000Z";

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

function limits(
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
    auditId: "sec4-audit",
    runId: "sec4-root",
    repositoryIdentitySha256: H1,
    sourceRevision: "bc62c3d",
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

  const ledger = createSecurityCoverageLedger(
    model,
    {
      ledgerId: "sec4-coverage",
      areas: [{
        areaId: "policy",
        label: "Policy core",
        paths: ["src/policy"],
      }],
      createdAt: NOW,
    },
  );
  const assignment =
    planNextSecurityHunterAssignment(
      model,
      ledger,
      {
        assignmentId: "sec4-assignment",
        budget: {
          modelTokens: 12_000,
          toolCalls: 20,
          networkRequests: 0,
          wallClockMs: 120_000,
        },
        plannedAt:
          "2026-10-02T19:01:00.000Z",
      },
    );
  assert.ok(assignment);

  const rootBudget = createRunBudgetLedger({
    budgetId: "sec4-root-budget",
    runId: "sec4-root",
    createdAt: NOW,
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
      parentAllow("host:file-read"),
      parentAllow("host:session"),
    ],
    childAuthoritySnapshot: {
      capturedAt:
        "2026-10-02T19:02:00.000Z",
      decisions: [
        allowDecision("host:file-read"),
        allowDecision("host:session"),
      ],
    },
    parentBudget: rootBudget,
    q1Limits: limits(),
    childTaskId: "sec4-hunter",
    childBudgetId:
      "sec4-hunter-budget",
    allocationId:
      "sec4-hunter-allocation",
    createdAt:
      "2026-10-02T19:02:00.000Z",
  });

  const candidate =
    createSecurityHunterCandidatePacket(
      model,
      ledger,
      hunter,
      {
        findingId: "sec4-candidate",
        title: "Potential policy bypass",
        rationale:
          "One branch appears to skip an authority guard.",
        evidenceRefs: [
          { id: "hunter-trace", sha256: H3 },
        ],
        sourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        proofPlan: [{
          stepId: "p1",
          description:
            "Attempt to falsify the bypass using exact source flow.",
        }],
        emittedAt:
          "2026-10-02T19:03:00.000Z",
      },
    );

  return {
    model,
    ledger,
    hunter,
    candidate,
  };
}

function spawnFixture(
  overrides: Partial<Parameters<
    typeof spawnSecurityValidatorChild
  >[0]> = {},
) {
  const base = fixture();
  const createdAt =
    "2026-10-02T19:04:00.000Z";
  const spawn =
    spawnSecurityValidatorChild({
      threatModel: base.model,
      coverageLedger: base.ledger,
      hunterSpawn: base.hunter,
      candidatePacket: base.candidate,
      validatorIdentitySha256: H5,
      runtimeProvenance: {
        providerId: "provider-a",
        modelId: "validator-model",
      },
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
        ],
      },
      parentBudget:
        base.hunter.parentBudget,
      q1Limits: limits(),
      childTaskId: "sec4-validator",
      childBudgetId:
        "sec4-validator-budget",
      allocationId:
        "sec4-validator-allocation",
      createdAt,
      ...overrides,
    });
  return { ...base, spawn };
}

test("SEC4 validator starts in a fresh child with NEEDS_VALIDATION predecessor truth", () => {
  const { hunter, candidate, spawn } =
    spawnFixture();
  assert.notEqual(
    spawn.childTask.task.childTaskId,
    hunter.childTask.task.childTaskId,
  );
  assert.equal(
    spawn.childTask.task.runState.phase,
    "security-validation",
  );
  assert.match(
    spawn.childTask.task.runState.objective.summary,
    /disprove/i,
  );
  assert.equal(
    spawn.validationFinding.record.state,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    spawn.validationFinding.record.revision,
    candidate.record.candidate.record.revision + 1,
  );
  assert.equal(
    spawn.validationFinding.record.continuity
      .previousRecordSha256,
    candidate.record.candidate.recordSha256,
  );
});

test("SEC4 refuses Hunter self-validation identity", () => {
  const base = fixture();
  const createdAt =
    "2026-10-02T19:04:00.000Z";
  assert.throws(
    () => spawnSecurityValidatorChild({
      threatModel: base.model,
      coverageLedger: base.ledger,
      hunterSpawn: base.hunter,
      candidatePacket: base.candidate,
      validatorIdentitySha256:
        base.hunter.hunterIdentitySha256,
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
      parentBudget:
        base.hunter.parentBudget,
      q1Limits: limits(),
      createdAt,
    }),
    /self-validation is refused/,
  );
});

test("SEC4 refuses reuse of the Hunter child task", () => {
  const base = fixture();
  const createdAt =
    "2026-10-02T19:04:00.000Z";
  assert.throws(
    () => spawnSecurityValidatorChild({
      threatModel: base.model,
      coverageLedger: base.ledger,
      hunterSpawn: base.hunter,
      candidatePacket: base.candidate,
      validatorIdentitySha256: H5,
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
      parentBudget:
        base.hunter.parentBudget,
      q1Limits: limits(),
      childTaskId:
        base.hunter.childTask.task.childTaskId,
      createdAt,
    }),
    /fresh child task distinct from the Hunter/,
  );
});

test("SEC4 validator authority is an exact read-only allowlist", () => {
  const base = fixture();
  const createdAt =
    "2026-10-02T19:04:00.000Z";
  assert.throws(
    () => spawnSecurityValidatorChild({
      threatModel: base.model,
      coverageLedger: base.ledger,
      hunterSpawn: base.hunter,
      candidatePacket: base.candidate,
      validatorIdentitySha256: H5,
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
      parentBudget:
        base.hunter.parentBudget,
      q1Limits: limits(),
      createdAt,
    }),
    /may ALLOW only host:file-read and host:session/,
  );
});

test("SEC4 validator Q1 refuses network retry and nested-child budgets", () => {
  for (const [field, expected] of [
    ["networkRequests", /network budget must be zero/],
    ["retries", /retries must be zero/],
    ["childTasks", /cannot allocate nested child tasks/],
  ] as const) {
    const base = fixture();
    const createdAt =
      "2026-10-02T19:04:00.000Z";
    assert.throws(
      () => spawnSecurityValidatorChild({
        threatModel: base.model,
        coverageLedger: base.ledger,
        hunterSpawn: base.hunter,
        candidatePacket: base.candidate,
        validatorIdentitySha256: H5,
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
        parentBudget:
          base.hunter.parentBudget,
        q1Limits: limits({ [field]: 1 }),
        createdAt,
      }),
      expected,
    );
  }
});

test("SEC4 candidate validation refuses a tampered Hunter packet", () => {
  const base = fixture();
  assert.throws(
    () =>
      validateSecurityHunterCandidatePacketForValidation(
        base.model,
        base.ledger,
        base.hunter,
        {
          ...base.candidate,
          recordSha256: H7,
        },
      ),
    /candidate packet integrity mismatch/,
  );
});

test("SEC4 confirmation requires non-empty reproduction evidence", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  assert.throws(
    () => resolveSecurityValidation(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      {
        disposition: "CONFIRMED",
        proofEvidenceRefs: [],
        reproducedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        decidedAt:
          "2026-10-02T19:05:00.000Z",
      },
    ),
    /proofEvidenceRefs count is invalid/,
  );
});

test("SEC4 confirmation requires exact candidate source locations", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  assert.throws(
    () => resolveSecurityValidation(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      {
        disposition: "CONFIRMED",
        proofEvidenceRefs: [
          { id: "proof", sha256: H6 },
        ],
        reproducedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 11,
          endLine: 20,
        }],
        decidedAt:
          "2026-10-02T19:05:00.000Z",
      },
    ),
    /must match an exact candidate source location/,
  );
});

test("SEC4 confirmed finding binds distinct validator proof and continuity", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  const decision = resolveSecurityValidation(
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    {
      disposition: "CONFIRMED",
      proofEvidenceRefs: [
        { id: "proof", sha256: H6 },
      ],
      reproducedSourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      decidedAt:
        "2026-10-02T19:05:00.000Z",
    },
  );
  assert.equal(
    decision.record.disposition,
    "CONFIRMED",
  );
  assert.equal(
    decision.record.resultFinding.record.state,
    "CONFIRMED",
  );
  assert.equal(
    decision.record.resultFinding.record.revision,
    2,
  );
  assert.equal(
    decision.record.resultFinding.record.continuity
      .previousRecordSha256,
    spawn.validationFinding.recordSha256,
  );
  const evidence =
    decision.record.resultFinding.record.stateEvidence;
  assert.equal(evidence.state, "CONFIRMED");
  if (evidence.state === "CONFIRMED") {
    assert.equal(
      evidence.validatorIdentitySha256,
      H5,
    );
    assert.equal(
      evidence.proofEvidenceRefs[0]?.sha256,
      H6,
    );
  }
});

test("SEC4 rejection retains candidate evidence and explicit disproof", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  const decision = resolveSecurityValidation(
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    {
      disposition: "REJECTED",
      reason:
        "Caller enforces the authority check before this branch.",
      disproofEvidenceRefs: [
        { id: "disproof", sha256: H6 },
      ],
      checkedSourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      decidedAt:
        "2026-10-02T19:05:00.000Z",
    },
  );
  assert.equal(
    decision.record.resultFinding.record.state,
    "REJECTED",
  );
  assert.equal(
    decision.record.resultFinding.record.evidenceRefs[0]?.id,
    "hunter-trace",
  );
  const evidence =
    decision.record.resultFinding.record.stateEvidence;
  assert.equal(evidence.state, "REJECTED");
  if (evidence.state === "REJECTED") {
    assert.match(
      evidence.reason,
      /Caller enforces/,
    );
    assert.equal(
      evidence.disproofEvidenceRefs[0]?.id,
      "disproof",
    );
  }
});

test("SEC4 inconclusive review remains first-class NEEDS_VALIDATION", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  const decision = resolveSecurityValidation(
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    {
      disposition: "NEEDS_VALIDATION",
      reason:
        "Read-only evidence cannot establish exploitability without sandbox execution.",
      evidenceRefs: [
        { id: "uncertain", sha256: H6 },
      ],
      checkedSourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      decidedAt:
        "2026-10-02T19:05:00.000Z",
    },
  );
  assert.equal(
    decision.record.disposition,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    decision.record.resultFinding.record.state,
    "NEEDS_VALIDATION",
  );
  assert.equal(
    decision.record.validationMode,
    "READ_ONLY_ADVERSARIAL_REVIEW",
  );
});

test("SEC4 provider/model diversity never substitutes for confirmation proof", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture({
      runtimeProvenance: {
        providerId: "different-provider",
        modelId: "different-model",
      },
    });
  assert.throws(
    () => resolveSecurityValidation(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      {
        disposition: "CONFIRMED",
        proofEvidenceRefs: [],
        reproducedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        decidedAt:
          "2026-10-02T19:05:00.000Z",
      },
    ),
    /proofEvidenceRefs count is invalid/,
  );
});

function confirmedDecision() {
  const base = spawnFixture();
  const decision = resolveSecurityValidation(
    base.model,
    base.ledger,
    base.hunter,
    base.candidate,
    base.spawn,
    {
      disposition: "CONFIRMED",
      proofEvidenceRefs: [
        { id: "proof", sha256: H6 },
      ],
      reproducedSourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      decidedAt:
        "2026-10-02T19:05:00.000Z",
    },
  );
  return { ...base, decision };
}

test("SEC4 independent re-verifier must differ from Hunter and validator", () => {
  const {
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    decision,
  } = confirmedDecision();

  for (const identity of [
    hunter.hunterIdentitySha256,
    H5,
  ]) {
    assert.throws(
      () => independentlyReverifyConfirmedFinding(
        model,
        ledger,
        hunter,
        candidate,
        spawn,
        decision,
        {
          reVerifierIdentitySha256: identity,
          evidenceRefs: [
            { id: "recheck", sha256: H7 },
          ],
          checkedSourceLocations: [{
            path: "src/policy/check.ts",
            startLine: 10,
            endLine: 20,
          }],
          verified: true,
          reason: "Independent source check.",
          reviewedAt:
            "2026-10-02T19:06:00.000Z",
        },
      ),
      /must differ from Hunter and validator/,
    );
  }
});

test("SEC4 re-verification requires a confirmed validation decision", () => {
  const { model, ledger, hunter, candidate, spawn } =
    spawnFixture();
  const rejected = resolveSecurityValidation(
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    {
      disposition: "REJECTED",
      reason: "Disproved.",
      disproofEvidenceRefs: [
        { id: "disproof", sha256: H6 },
      ],
      checkedSourceLocations: [{
        path: "src/policy/check.ts",
        startLine: 10,
        endLine: 20,
      }],
      decidedAt:
        "2026-10-02T19:05:00.000Z",
    },
  );
  assert.throws(
    () => independentlyReverifyConfirmedFinding(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      rejected,
      {
        reVerifierIdentitySha256: H7,
        evidenceRefs: [
          { id: "recheck", sha256: H7 },
        ],
        checkedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        verified: true,
        reason: "Recheck.",
        reviewedAt:
          "2026-10-02T19:06:00.000Z",
      },
    ),
    /requires a CONFIRMED validation decision/,
  );
});

test("SEC4 independent re-verification binds evidence exact source and provenance without rewriting finding", () => {
  const {
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    decision,
  } = confirmedDecision();
  const receipt =
    independentlyReverifyConfirmedFinding(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      decision,
      {
        reVerifierIdentitySha256: H7,
        runtimeProvenance: {
          providerId: "provider-b",
          modelId: "reverify-model",
        },
        evidenceRefs: [
          { id: "recheck", sha256: H7 },
        ],
        checkedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        verified: true,
        reason:
          "Independent read-only check agrees with exact proof claim.",
        reviewedAt:
          "2026-10-02T19:06:00.000Z",
      },
    );

  assert.equal(
    receipt.record.disposition,
    "VERIFIED",
  );
  assert.equal(
    receipt.record.confirmedFindingSha256,
    decision.record.resultFinding.recordSha256,
  );
  assert.equal(
    receipt.record.validationDecisionSha256,
    decision.recordSha256,
  );
  assert.equal(
    receipt.record.runtimeProvenance?.providerId,
    "provider-b",
  );
});

test("SEC4 durable validation envelope refuses empty proof and broken predecessor continuity even when resealed", () => {
  const { decision } = confirmedDecision();

  const emptyProofRecord = {
    ...decision.record,
    validationEvidenceRefs: [],
    checkedSourceLocations: [],
  };
  const emptyProof = {
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1" as const,
    record: emptyProofRecord,
    recordSha256:
      securityValidationDecisionRecordSha256(
        emptyProofRecord,
      ),
  };
  assert.throws(
    () =>
      validateSecurityValidationDecisionEnvelope(
        emptyProof,
      ),
    /validationEvidenceRefs count is invalid/,
  );

  const brokenContinuityRecord = {
    ...decision.record,
    predecessorFindingSha256: H7,
  };
  const brokenContinuity = {
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1" as const,
    record: brokenContinuityRecord,
    recordSha256:
      securityValidationDecisionRecordSha256(
        brokenContinuityRecord,
      ),
  };
  assert.throws(
    () =>
      validateSecurityValidationDecisionEnvelope(
        brokenContinuity,
      ),
    /predecessor binding mismatch/,
  );
});

test("SEC4 authoritative lineage validator refuses a self-consistent resealed decision with forged source lineage", () => {
  const {
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    decision,
  } = confirmedDecision();

  const forgedRecord = {
    ...decision.record,
    candidatePacketSha256: H7,
    sourceTreeSha256: H6,
  };
  const forged = {
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1" as const,
    record: forgedRecord,
    recordSha256:
      securityValidationDecisionRecordSha256(
        forgedRecord,
      ),
  };

  assert.doesNotThrow(
    () =>
      validateSecurityValidationDecisionEnvelope(
        forged,
      ),
  );
  assert.throws(
    () =>
      validateSecurityValidationDecisionAgainstLineage(
        model,
        ledger,
        hunter,
        candidate,
        spawn,
        forged,
      ),
    /authoritative lineage binding mismatch/,
  );
});

test("SEC4 re-verifier refuses a self-consistent forged confirmation that is not bound to the authoritative validator run", () => {
  const {
    model,
    ledger,
    hunter,
    candidate,
    spawn,
    decision,
  } = confirmedDecision();

  const forgedRecord = {
    ...decision.record,
    validatorExecutionSha256: H7,
  };
  const forged = {
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1" as const,
    record: forgedRecord,
    recordSha256:
      securityValidationDecisionRecordSha256(
        forgedRecord,
      ),
  };

  assert.throws(
    () => independentlyReverifyConfirmedFinding(
      model,
      ledger,
      hunter,
      candidate,
      spawn,
      forged,
      {
        reVerifierIdentitySha256: H7,
        evidenceRefs: [
          { id: "recheck", sha256: H7 },
        ],
        checkedSourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        verified: true,
        reason:
          "Forged confirmation must not reach publication.",
        reviewedAt:
          "2026-10-02T19:06:00.000Z",
      },
    ),
    /authoritative lineage binding mismatch/,
  );
});
