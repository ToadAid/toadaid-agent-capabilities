import assert from "node:assert/strict";
import test from "node:test";

import type {
  CapabilityAuthorityDecision,
} from "../src/capabilityPolicy.js";
import {
  childTaskSha256,
  createChildTask,
  transitionChildTask,
} from "../src/childTaskLifecycle.js";
import {
  checkpointRunStateCapsule,
  createRunStateCapsule,
  resolveResumeCapabilityAuthority,
} from "../src/runStateCapsule.js";
import type {
  RunResumeAuthorityDecision,
} from "../src/runStateCapsule.js";
import {
  createSecurityFindingCandidate,
  createSecurityThreatModel,
  sealSecurityFindingRecord,
} from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
  recordSecurityCoverage,
} from "../src/securityCoverage.js";
import {
  assertSecurityAuditStatePredecessor,
  checkpointSecurityAuditState,
  createSecurityAuditState,
  parseSecurityAuditState,
  rebaseSecurityAuditStateSource,
  resumeSecurityAuditState,
  sealSecurityAuditStateRecord,
  serializeSecurityAuditState,
} from "../src/securityAuditState.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const H8 = "8".repeat(64);
const H9 = "9".repeat(64);

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

function model(
  sourceRevision: string,
  sourceTreeSha256: string,
) {
  return createSecurityThreatModel({
    auditId: "sec6-audit",
    runId: "sec6-root",
    repositoryIdentitySha256: H1,
    sourceRevision,
    sourceTreeSha256,
    scope: {
      includePaths: ["src"],
      excludePaths: [],
    },
    configurationSha256: H2,
    ruleSetSha256: H3,
    architecture: {
      components: [
        {
          componentId: "policy",
          kind: "SECURITY_CONTROL",
          label: "Policy",
          sourcePaths: [
            "src/policy/check.ts",
          ],
          riskSignals: [
            "AUTHORITY_BOUNDARY",
          ],
        },
        {
          componentId: "store",
          kind: "DATA_STORE",
          label: "Store",
          sourcePaths: [
            "src/other/store.ts",
          ],
          riskSignals: [
            "PERSISTENT_STATE",
          ],
        },
      ],
      trustBoundaries: [],
    },
    createdAt:
      sourceRevision === "rev-a"
        ? "2026-10-02T22:00:00.000Z"
        : "2026-10-02T22:30:00.000Z",
  });
}

function confirmedFinding(
  threatModel: ReturnType<typeof model>,
  findingId: string,
  attackClass:
    | "AUTHORIZATION_BYPASS"
    | "STATE_TAMPERING",
  path: string,
  evidenceSha: string,
) {
  const candidate =
    createSecurityFindingCandidate(
      threatModel,
      {
        findingId,
        attackClass,
        title: `Finding ${findingId}`,
        rationale: "Candidate rationale",
        evidenceRefs: [{
          id: `${findingId}-candidate`,
          sha256: evidenceSha,
        }],
        sourceLocations: [{
          path,
          startLine: 10,
          endLine: 20,
        }],
        createdAt:
          "2026-10-02T22:02:00.000Z",
      },
    );
  return sealSecurityFindingRecord({
    ...candidate.record,
    revision: 1,
    state: "CONFIRMED",
    stateEvidence: {
      state: "CONFIRMED",
      validatorIdentitySha256: H9,
      proofEvidenceRefs: [{
        id: `${findingId}-proof`,
        sha256: H8,
      }],
    },
    updatedAt:
      "2026-10-02T22:04:00.000Z",
    continuity: {
      previousRecordSha256:
        candidate.recordSha256,
    },
  });
}

function childTask(
  sourceTreeSha256: string,
) {
  const snapshot = {
    capturedAt:
      "2026-10-02T22:01:00.000Z",
    decisions: [
      allow("host:file-read"),
      allow("host:session"),
    ],
  };
  const runState =
    createRunStateCapsule({
      runId: "sec6-child-1",
      createdAt:
        "2026-10-02T22:01:00.000Z",
      objective: {
        summary: "Security child",
        status: "ACTIVE",
      },
      phase: "SECURITY_HUNT",
      authoritySnapshot: snapshot,
      evidenceRefs: [{
        id: "source-tree",
        locator:
          `security://source/${sourceTreeSha256}`,
        sha256: sourceTreeSha256,
      }],
    });
  const task = createChildTask({
    childTaskId: "sec6-child-1",
    parentRunId: "sec6-root",
    createdAt:
      "2026-10-02T22:01:00.000Z",
    delegatedCapabilities: [
      "host:file-read",
      "host:session",
    ],
    parentAuthority: [
      parentAllow("host:file-read"),
      parentAllow("host:session"),
    ],
    runState,
  });
  return {
    role: "HUNTER" as const,
    sourceTreeSha256,
    sourceDisposition:
      "CURRENT_SOURCE" as const,
    task,
    taskSha256:
      childTaskSha256(task),
  };
}

function fixture() {
  const threatModel = model("rev-a", H4);
  let coverage =
    createSecurityCoverageLedger(
      threatModel,
      {
        ledgerId: "sec6-coverage",
        areas: [
          {
            areaId: "policy",
            label: "Policy",
            paths: ["src/policy"],
          },
          {
            areaId: "other",
            label: "Other",
            paths: ["src/other"],
          },
        ],
        createdAt:
          "2026-10-02T22:00:00.000Z",
      },
    );
  coverage = recordSecurityCoverage(
    threatModel,
    coverage,
    {
      areaId: "policy",
      attackClass:
        "AUTHORIZATION_BYPASS",
      disposition: "COVERED",
      evidenceRefs: [{
        id: "policy-coverage",
        sha256: H5,
      }],
      inspectedAt:
        "2026-10-02T22:03:00.000Z",
    },
  );
  coverage = recordSecurityCoverage(
    threatModel,
    coverage,
    {
      areaId: "other",
      attackClass: "STATE_TAMPERING",
      disposition: "COVERED",
      evidenceRefs: [{
        id: "other-coverage",
        sha256: H6,
      }],
      inspectedAt:
        "2026-10-02T22:04:00.000Z",
    },
  );

  const policyFinding =
    confirmedFinding(
      threatModel,
      "finding-policy",
      "AUTHORIZATION_BYPASS",
      "src/policy/check.ts",
      H5,
    );
  const otherFinding =
    confirmedFinding(
      threatModel,
      "finding-other",
      "STATE_TAMPERING",
      "src/other/store.ts",
      H6,
    );
  const child = childTask(H4);

  const state =
    createSecurityAuditState({
      threatModel,
      coverageLedger: coverage,
      findings: [
        {
          finding: policyFinding,
          sourceDisposition:
            "CURRENT_REVISION",
          sourceChangeSha256: null,
        },
        {
          finding: otherFinding,
          sourceDisposition:
            "CURRENT_REVISION",
          sourceChangeSha256: null,
        },
      ],
      childTasks: [child],
      authoritySnapshot: {
        capturedAt:
          "2026-10-02T22:00:00.000Z",
        decisions: [
          allow("host:file-read"),
          allow("host:session"),
          allow("security:sandbox-exec"),
        ],
      },
      runtimeProvenance: {
        providerIdentitySha256: H7,
        modelIdentitySha256: H8,
      },
      createdAt:
        "2026-10-02T22:00:00.000Z",
    });

  return {
    threatModel,
    coverage,
    policyFinding,
    otherFinding,
    child,
    state,
  };
}

test("SEC6 initial durable state binds threat model coverage findings and P5 child lineage into P4 evidence", () => {
  const { state } = fixture();
  assert.equal(state.record.revision, 0);
  assert.equal(
    state.record.runState.revision,
    0,
  );
  assert.equal(
    state.record.runState.evidenceRefs
      .some((ref) =>
        ref.id ===
        "security-threat-model"),
    true,
  );
  assert.equal(
    state.record.runState.evidenceRefs
      .some((ref) =>
        ref.id ===
        "security-coverage-ledger"),
    true,
  );
  assert.equal(
    state.record.runState.evidenceRefs
      .filter((ref) =>
        ref.id.startsWith(
          "security-finding-",
        )).length,
    2,
  );
  assert.equal(
    state.record.runState.evidenceRefs
      .some((ref) =>
        ref.id ===
        "security-child-sec6-child-1"),
    true,
  );
});

test("SEC6 serialization round-trip preserves sealed durable audit truth", () => {
  const { state } = fixture();
  const parsed =
    parseSecurityAuditState(
      serializeSecurityAuditState(state),
    );
  assert.deepEqual(parsed, state);
});

test("SEC6 exact resume advances P4 continuity and refuses source or configuration drift", () => {
  const { state } = fixture();
  const serialized =
    serializeSecurityAuditState(state);

  const resumed =
    resumeSecurityAuditState(
      serialized,
      {
        resumedAt:
          "2026-10-02T22:10:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
          allow(
            "security:sandbox-exec",
          ),
        ],
      },
    );
  assert.equal(
    resumed.state.record.revision,
    1,
  );
  assert.equal(
    resumed.state.record
      .continuity.transition,
    "RESUME",
  );
  assert.equal(
    resumed.state.record.runState
      .continuity.reason,
    "RESTART",
  );
  assertSecurityAuditStatePredecessor(
    state,
    resumed.state,
  );

  assert.throws(
    () =>
      resumeSecurityAuditState(
        serialized,
        {
          resumedAt:
            "2026-10-02T22:10:00.000Z",
          repositoryIdentitySha256:
            H1,
          sourceRevision: "rev-b",
          sourceTreeSha256: H5,
          configurationSha256: H2,
          ruleSetSha256: H3,
          currentAuthority: [],
        },
      ),
    /exact resume identity mismatch/,
  );

  assert.throws(
    () =>
      resumeSecurityAuditState(
        serialized,
        {
          resumedAt:
            "2026-10-02T22:10:00.000Z",
          repositoryIdentitySha256:
            H1,
          sourceRevision: "rev-a",
          sourceTreeSha256: H4,
          configurationSha256: H9,
          ruleSetSha256: H3,
          currentAuthority: [],
        },
      ),
    /configurationSha256/,
  );
});

test("SEC6 saved state cannot restore revoked sandbox authority", () => {
  const { state } = fixture();
  const resumed =
    resumeSecurityAuditState(
      serializeSecurityAuditState(state),
      {
        resumedAt:
          "2026-10-02T22:10:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
          block(
            "security:sandbox-exec",
          ),
        ],
      },
    );
  const sandbox =
    resumed.resumeAuthority.find(
      (entry) =>
        entry.capabilityId ===
        "security:sandbox-exec",
    );
  assert.equal(
    sandbox?.decision,
    "BLOCK",
  );
  assert.equal(
    sandbox?.reason,
    "BLOCKED_BY_POLICY",
  );
});

test("SEC6 provider change is explicit provenance continuity and never rewrites authority", () => {
  const { state } = fixture();
  const resumed =
    resumeSecurityAuditState(
      serializeSecurityAuditState(state),
      {
        resumedAt:
          "2026-10-02T22:11:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
          block(
            "security:sandbox-exec",
          ),
        ],
        runtimeProvenance: {
          providerIdentitySha256: H9,
          modelIdentitySha256: H8,
        },
      },
    );
  assert.equal(
    resumed.state.record
      .continuity.transition,
    "PROVIDER_CHANGE",
  );
  assert.notEqual(
    resumed.state.record.continuity
      .providerChangeSha256,
    null,
  );
  assert.deepEqual(
    resumed.state.record.runState
      .authoritySnapshot,
    state.record.runState
      .authoritySnapshot,
  );
});

test("SEC6 source rebase invalidates only affected coverage and preserves immutable finding envelopes", () => {
  const {
    state,
    policyFinding,
    otherFinding,
  } = fixture();
  const nextModel =
    model("rev-b", H9);

  const outcome =
    rebaseSecurityAuditStateSource(
      state,
      {
        nextThreatModel: nextModel,
        areas: [
          {
            areaId: "policy",
            label: "Policy",
            paths: ["src/policy"],
          },
          {
            areaId: "other",
            label: "Other",
            paths: ["src/other"],
          },
        ],
        changedPaths: [
          "src/policy/check.ts",
        ],
        rebasedAt:
          "2026-10-02T22:30:00.000Z",
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
          block(
            "security:sandbox-exec",
          ),
        ],
      },
    );

  const next = outcome.state;
  assert.equal(
    next.record.continuity.transition,
    "SOURCE_REBASE",
  );
  assert.equal(
    next.record.threatModels.length,
    2,
  );

  const policyCell =
    next.record.coverageLedger.record.cells
      .find((cell) =>
        cell.areaId === "policy" &&
        cell.attackClass ===
          "AUTHORIZATION_BYPASS",
      );
  const otherCell =
    next.record.coverageLedger.record.cells
      .find((cell) =>
        cell.areaId === "other" &&
        cell.attackClass ===
          "STATE_TAMPERING",
      );
  assert.equal(
    policyCell?.disposition,
    "UNEXPLORED",
  );
  assert.equal(
    otherCell?.disposition,
    "COVERED",
  );

  const policyEntry =
    next.record.findings.find(
      (entry) =>
        entry.finding.record.findingId ===
        "finding-policy",
    );
  const otherEntry =
    next.record.findings.find(
      (entry) =>
        entry.finding.record.findingId ===
        "finding-other",
    );
  assert.equal(
    policyEntry?.sourceDisposition,
    "INVALIDATED_SOURCE_CHANGE",
  );
  assert.equal(
    otherEntry?.sourceDisposition,
    "CARRIED_UNCHANGED",
  );
  assert.equal(
    policyEntry?.finding.recordSha256,
    policyFinding.recordSha256,
  );
  assert.equal(
    otherEntry?.finding.recordSha256,
    otherFinding.recordSha256,
  );
});

test("SEC6 source rebase makes old P5 children historical and never creates a replacement child", () => {
  const { state } = fixture();
  const outcome =
    rebaseSecurityAuditStateSource(
      state,
      {
        nextThreatModel:
          model("rev-b", H9),
        areas: [
          {
            areaId: "policy",
            label: "Policy",
            paths: ["src/policy"],
          },
          {
            areaId: "other",
            label: "Other",
            paths: ["src/other"],
          },
        ],
        changedPaths: [
          "src/policy/check.ts",
        ],
        rebasedAt:
          "2026-10-02T22:30:00.000Z",
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
        ],
      },
    );
  assert.equal(
    outcome.state.record.childTasks.length,
    1,
  );
  assert.equal(
    outcome.state.record.childTasks[0]
      ?.task.childTaskId,
    "sec6-child-1",
  );
  assert.equal(
    outcome.state.record.childTasks[0]
      ?.sourceDisposition,
    "HISTORICAL_SOURCE",
  );
});

test("SEC6 source rebase refuses missing changed-path proof for changed tree", () => {
  const { state } = fixture();
  assert.throws(
    () =>
      rebaseSecurityAuditStateSource(
        state,
        {
          nextThreatModel:
            model("rev-b", H9),
          areas: [
            {
              areaId: "policy",
              label: "Policy",
              paths: ["src/policy"],
            },
            {
              areaId: "other",
              label: "Other",
              paths: ["src/other"],
            },
          ],
          changedPaths: [],
          rebasedAt:
            "2026-10-02T22:30:00.000Z",
          currentAuthority: [],
        },
      ),
    /changed source tree requires a non-empty changed-path manifest/,
  );
});

test("SEC6 child-task updates must preserve exact P5 predecessor continuity", () => {
  const { state, child } = fixture();

  const runningRunState =
    checkpointRunStateCapsule(
      child.task.runState,
      {
        updatedAt:
          "2026-10-02T22:05:00.000Z",
        reason: "CHECKPOINT",
        phase: "SECURITY_HUNT",
      },
    );
  const runningTask =
    transitionChildTask(
      child.task,
      {
        kind: "START",
        updatedAt:
          "2026-10-02T22:05:00.000Z",
        runState: runningRunState,
      },
    );
  const next =
    checkpointSecurityAuditState(
      state,
      {
        updatedAt:
          "2026-10-02T22:05:00.000Z",
        childTasks: [{
          ...child,
          task: runningTask,
          taskSha256:
            childTaskSha256(
              runningTask,
            ),
        }],
      },
    );
  assert.equal(
    next.record.childTasks[0]
      ?.task.status,
    "RUNNING",
  );

  const forgedTask = {
    ...runningTask,
    revision:
      runningTask.revision + 2,
  };
  assert.throws(
    () =>
      checkpointSecurityAuditState(
        state,
        {
          updatedAt:
            "2026-10-02T22:06:00.000Z",
          childTasks: [{
            ...child,
            task:
              forgedTask as typeof runningTask,
            taskSha256:
              childTaskSha256(
                forgedTask as typeof runningTask,
              ),
          }],
        },
      ),
    /child-task revision is not contiguous|child-task continuity generation must equal revision/,
  );
});

test("SEC6 BLOCKED checkpoint preserves evidence and resumes without fabricating progress", () => {
  const { state } = fixture();
  const blocked =
    checkpointSecurityAuditState(
      state,
      {
        updatedAt:
          "2026-10-02T22:07:00.000Z",
        status: "BLOCKED",
      },
    );
  assert.equal(
    blocked.record.status,
    "BLOCKED",
  );
  assert.equal(
    blocked.record.runState.objective
      .status,
    "BLOCKED",
  );
  assert.equal(
    blocked.record.findings.length,
    state.record.findings.length,
  );

  const resumed =
    resumeSecurityAuditState(
      serializeSecurityAuditState(blocked),
      {
        resumedAt:
          "2026-10-02T22:08:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority: [
          allow("host:file-read"),
          allow("host:session"),
          block(
            "security:sandbox-exec",
          ),
        ],
      },
    );
  assert.equal(
    resumed.state.record.status,
    "BLOCKED",
  );
  assert.equal(
    resumed.state.record.runState.objective
      .status,
    "BLOCKED",
  );
});

test("SEC6 direct P4 resume authority remains snapshot ∩ current policy", () => {
  const { state } = fixture();
  const decision =
    resolveResumeCapabilityAuthority(
      "security:sandbox-exec",
      state.record.runState,
      [
        block("security:sandbox-exec"),
      ],
    );
  assert.equal(
    decision.decision,
    "BLOCK",
  );
  assert.equal(
    decision.snapshotDecision,
    "ALLOW",
  );
  assert.equal(
    decision.currentDecision,
    "BLOCK",
  );
});

test("SEC6 saved authority snapshot cannot influence fresh resume authority", () => {
  const { state } = fixture();

  const forgedRunState = {
    ...state.record.runState,
    authoritySnapshot: {
      ...state.record.runState.authoritySnapshot,
      decisions:
        state.record.runState.authoritySnapshot.decisions.map(
          (decision) =>
            decision.capabilityId ===
              "security:sandbox-exec"
              ? allow(
                  "security:sandbox-exec",
                )
              : decision,
        ),
    },
  };
  const forged =
    sealSecurityAuditStateRecord({
      ...state.record,
      runState:
        forgedRunState as typeof state.record.runState,
    });

  const currentAuthority = [
    allow("host:file-read"),
    allow("host:session"),
    block("security:sandbox-exec"),
  ];
  const originalResume =
    resumeSecurityAuditState(
      serializeSecurityAuditState(state),
      {
        resumedAt:
          "2026-10-02T22:12:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority,
      },
    );
  const forgedResume =
    resumeSecurityAuditState(
      serializeSecurityAuditState(forged),
      {
        resumedAt:
          "2026-10-02T22:12:00.000Z",
        repositoryIdentitySha256: H1,
        sourceRevision: "rev-a",
        sourceTreeSha256: H4,
        configurationSha256: H2,
        ruleSetSha256: H3,
        currentAuthority,
      },
    );

  assert.deepEqual(
    forgedResume.resumeAuthority,
    originalResume.resumeAuthority,
  );
  assert.equal(
    forgedResume.resumeAuthority.find(
      (entry) =>
        entry.capabilityId ===
        "security:sandbox-exec",
    )?.decision,
    "BLOCK",
  );
});

test("SEC6 checkpoint cannot erase an existing durable finding", () => {
  const { state } = fixture();
  assert.throws(
    () =>
      checkpointSecurityAuditState(
        state,
        {
          updatedAt:
            "2026-10-02T22:12:00.000Z",
          findings: [],
        },
      ),
    /cannot drop an existing finding/,
  );
});

test("SEC6 checkpoint cannot erase existing P5 child lineage", () => {
  const { state } = fixture();
  assert.throws(
    () =>
      checkpointSecurityAuditState(
        state,
        {
          updatedAt:
            "2026-10-02T22:12:00.000Z",
          childTasks: [],
        },
      ),
    /cannot drop existing child lineage/,
  );
});

test("SEC6 checkpoint cannot relabel an existing child role or source provenance", () => {
  const { state, child } = fixture();

  assert.throws(
    () =>
      checkpointSecurityAuditState(
        state,
        {
          updatedAt:
            "2026-10-02T22:12:00.000Z",
          childTasks: [{
            ...child,
            role: "VALIDATOR",
          }],
        },
      ),
    /cannot relabel child role/,
  );

  assert.throws(
    () =>
      checkpointSecurityAuditState(
        state,
        {
          updatedAt:
            "2026-10-02T22:12:00.000Z",
          childTasks: [{
            ...child,
            sourceDisposition:
              "HISTORICAL_SOURCE",
          }],
        },
      ),
    /source disposition does not match source tree|cannot rewrite child source provenance/,
  );
});
