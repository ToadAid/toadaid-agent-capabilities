import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_CAPABILITY_MANIFEST,
} from "../src/capabilityPolicy.js";
import type {
  CapabilityPolicyLayer,
} from "../src/capabilityPolicy.js";
import {
  createSecurityFindingCandidate,
  createSecurityThreatModel,
  sealSecurityFindingRecord,
} from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
} from "../src/securityCoverage.js";
import {
  createSecurityAuditState,
} from "../src/securityAuditState.js";
import {
  buildCanonicalSecurityFindings,
} from "../src/securityReport.js";
import {
  SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES,
  SECURITY_SPECIALIST_MODES,
  assertSecurityRepairMergeActorSeparated,
  bindSecurityRepairPreMutationSnapshot,
  compileSecuritySpecialistRecipe,
  createSecurityRepairProposal,
  createSecurityRepairVerificationPackage,
  sealSecurityRepairProposalRecord,
  securitySpecialistRecipe,
  securitySpecialistRecipeSha256,
  validateSecurityRepairProposal,
  validateSecurityRepairVerification,
} from "../src/securitySpecialist.js";
import type {
  WorkspaceDiffReceipt,
  WorkspaceSnapshot,
} from "../src/workspaceHistoryTypes.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const H8 = "8".repeat(64);
const H9 = "9".repeat(64);
const HA = "a".repeat(64);
const HB = "b".repeat(64);

const ALL_ALLOWED: CapabilityPolicyLayer[] = [{
  scope: "agent",
  subject: "sec8-test",
  decisions: Object.freeze({
    "host:session": "ALLOW",
    "host:file-read": "ALLOW",
    "security:sandbox-exec": "ALLOW",
    "review:fix": "ALLOW",
    "host:file-write": "ALLOW",
    "host:command-exec": "ALLOW",
    "workspace:snapshot": "ALLOW",
    "workspace:diff": "ALLOW",
    "workspace:restore": "ALLOW",
  }),
}];

const READ_ONLY_ALLOWED: CapabilityPolicyLayer[] = [{
  scope: "agent",
  subject: "sec8-read-only",
  decisions: Object.freeze({
    "host:session": "ALLOW",
    "host:file-read": "ALLOW",
  }),
}];

function commonInputs() {
  return {
    repositoryIdentitySha256: H1,
    sourceRevision: "rev-a",
    sourceTreeSha256: H2,
  };
}

function modeInputs(
  mode: typeof SECURITY_SPECIALIST_MODES[number],
): Readonly<Record<string, unknown>> {
  switch (mode) {
    case "REPOSITORY_PREFLIGHT":
      return commonInputs();
    case "TARGETED_AUDIT":
      return {
        ...commonInputs(),
        targetScope: "src/security",
      };
    case "GAP_FILL_AUDIT":
      return {
        ...commonInputs(),
        coverageLedgerRecordSha256: H3,
      };
    case "VALIDATION_ONLY":
      return {
        ...commonInputs(),
        findingId: "finding-auth",
        findingRecordSha256: H4,
      };
    case "REVERIFICATION":
      return {
        ...commonInputs(),
        findingId: "finding-auth",
        findingRecordSha256: H4,
        priorValidatorIdentitySha256: H5,
      };
  }
}

function canonicalConfirmedFixture() {
  const threatModel =
    createSecurityThreatModel({
      auditId: "sec8-audit",
      runId: "sec8-run",
      repositoryIdentitySha256: H1,
      sourceRevision: "rev-a",
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
            "src/policy/check.ts",
          ],
          riskSignals: [
            "AUTHORITY_BOUNDARY",
          ],
        }],
        trustBoundaries: [],
      },
      createdAt:
        "2026-10-04T02:00:00.000Z",
    });

  const coverage =
    createSecurityCoverageLedger(
      threatModel,
      {
        ledgerId: "sec8-coverage",
        areas: [{
          areaId: "policy",
          label: "Policy",
          paths: ["src/policy"],
        }],
        createdAt:
          "2026-10-04T02:00:00.000Z",
      },
    );

  const candidate =
    createSecurityFindingCandidate(
      threatModel,
      {
        findingId: "finding-auth",
        attackClass:
          "AUTHORIZATION_BYPASS",
        title:
          "Confirmed authorization boundary finding",
        rationale:
          "SEC8 repair handoff fixture",
        evidenceRefs: [{
          id: "candidate-evidence",
          sha256: H5,
        }],
        sourceLocations: [{
          path: "src/policy/check.ts",
          startLine: 10,
          endLine: 20,
        }],
        createdAt:
          "2026-10-04T02:01:00.000Z",
      },
    );

  const needsValidation =
    sealSecurityFindingRecord({
      ...candidate.record,
      revision: 1,
      state: "NEEDS_VALIDATION",
      stateEvidence: {
        state: "NEEDS_VALIDATION",
        reason:
          "Fresh validator required",
      },
      updatedAt:
        "2026-10-04T02:02:00.000Z",
      continuity: {
        previousRecordSha256:
          candidate.recordSha256,
      },
    });

  const confirmed =
    sealSecurityFindingRecord({
      ...needsValidation.record,
      revision: 2,
      state: "CONFIRMED",
      stateEvidence: {
        state: "CONFIRMED",
        validatorIdentitySha256: H7,
        proofEvidenceRefs: [{
          id: "validator-proof",
          sha256: H8,
        }],
      },
      updatedAt:
        "2026-10-04T02:03:00.000Z",
      continuity: {
        previousRecordSha256:
          needsValidation.recordSha256,
      },
    });

  const state =
    createSecurityAuditState({
      threatModel,
      coverageLedger: coverage,
      findings: [{
        finding: confirmed,
        sourceDisposition:
          "CURRENT_REVISION",
        sourceChangeSha256: null,
      }],
      authoritySnapshot: {
        capturedAt:
          "2026-10-04T02:00:00.000Z",
        decisions: [],
      },
      createdAt:
        "2026-10-04T02:00:00.000Z",
    });

  return {
    candidate,
    confirmed,
    state,
    canonical:
      buildCanonicalSecurityFindings(
        state,
      ),
  };
}

function snapshot(
  id: string,
  createdAt: string,
  shaValue: string,
): WorkspaceSnapshot {
  return Object.freeze({
    schemaVersion:
      "toadaid.workspace-snapshot.v1",
    snapshotId: id,
    workspaceId: "sec8-workspace",
    createdAt,
    files: Object.freeze([{
      path: "src/policy/check.ts",
      sha256: shaValue,
      bytes: 10,
      mode: 0o644,
    }]),
    totalBytes: 10,
    policy: Object.freeze({
      maxFiles: 100,
      maxFileBytes: 1_000_000,
      maxTotalBytes: 10_000_000,
      excludedPaths: Object.freeze([
        ".git",
      ]),
    }),
  });
}

test("SEC8 P1 exposes exactly five bounded W1 specialist recipes", () => {
  assert.deepEqual(
    [...SECURITY_SPECIALIST_MODES],
    [
      "REPOSITORY_PREFLIGHT",
      "TARGETED_AUDIT",
      "GAP_FILL_AUDIT",
      "VALIDATION_ONLY",
      "REVERIFICATION",
    ],
  );

  const hashes = new Set<string>();
  for (
    const mode of
    SECURITY_SPECIALIST_MODES
  ) {
    const recipe =
      securitySpecialistRecipe(mode);
    assert.equal(
      recipe.schemaVersion,
      "toadaid.governed-recipe.v1",
    );
    assert.equal(recipe.maxRetries, 0);
    assert.deepEqual(
      recipe.capabilities.required,
      [
        "host:file-read",
        "host:session",
      ],
    );
    for (
      const forbidden of
      SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES
    ) {
      assert.ok(
        recipe.capabilities.forbidden
          ?.includes(forbidden),
      );
    }
    hashes.add(
      securitySpecialistRecipeSha256(
        mode,
      ),
    );
  }
  assert.equal(hashes.size, 5);
});

test("SEC8 P1 ambient mutation ALLOW never enters specialist effective capabilities", () => {
  for (
    const mode of
    SECURITY_SPECIALIST_MODES
  ) {
    const compiled =
      compileSecuritySpecialistRecipe(
        mode,
        modeInputs(mode),
        {
          manifest:
            CORE_CAPABILITY_MANIFEST,
          policyLayers: ALL_ALLOWED,
          compiledAt:
            "2026-10-04T02:10:00.000Z",
        },
      );

    assert.equal(
      compiled.inspectionOnly,
      true,
    );
    assert.equal(
      compiled.repairAuthorityIncluded,
      false,
    );
    assert.equal(
      compiled.fileMutationAuthorityIncluded,
      false,
    );
    assert.equal(
      compiled.gitAuthorityIncluded,
      false,
    );
    assert.equal(
      compiled.prAuthorityIncluded,
      false,
    );
    assert.equal(
      compiled.mergeAuthorityIncluded,
      false,
    );

    for (
      const forbidden of
      SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES
    ) {
      assert.equal(
        compiled.recipePlan
          .effectiveCapabilities
          .includes(forbidden),
        false,
      );
      const row =
        compiled.recipePlan
          .capabilityEvidence
          .find(
            (entry) =>
              entry.capabilityId ===
              forbidden,
          );
      assert.equal(
        row?.compileDecision,
        "FORBIDDEN",
      );
    }
  }
});

test("SEC8 P1 validation-only remains usable when sandbox authority is absent", () => {
  const compiled =
    compileSecuritySpecialistRecipe(
      "VALIDATION_ONLY",
      modeInputs("VALIDATION_ONLY"),
      {
        manifest:
          CORE_CAPABILITY_MANIFEST,
        policyLayers:
          READ_ONLY_ALLOWED,
        compiledAt:
          "2026-10-04T02:11:00.000Z",
      },
    );

  assert.equal(
    compiled.recipePlan
      .effectiveCapabilities
      .includes(
        "security:sandbox-exec",
      ),
    false,
  );
  assert.equal(
    compiled.recipePlan.steps.find(
      (step) =>
        step.id ===
        "optional-sandbox-proof",
    )?.status,
    "SKIPPED_OPTIONAL",
  );
});

test("SEC8 P1 repair proposal requires current-source CONFIRMED canonical truth", () => {
  const {
    candidate,
    canonical,
    state,
  } = canonicalConfirmedFixture();

  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-finding-auth",
        findingId: "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );

  assert.equal(
    proposal.record.findingId,
    "finding-auth",
  );
  assert.equal(
    proposal.record.authorityIncluded,
    false,
  );
  assert.equal(
    proposal.record.mergeAuthorityIncluded,
    false,
  );
  assert.deepEqual(
    proposal.record
      .requiredIndependentCapabilities,
    [
      "review:fix",
      "workspace:snapshot",
      "workspace:diff",
    ],
  );
  validateSecurityRepairProposal(proposal);

  const candidateState =
    createSecurityAuditState({
      threatModel:
        state.record.threatModels[0]!,
      coverageLedger:
        state.record.coverageLedger,
      findings: [{
        finding: candidate,
        sourceDisposition:
          "CURRENT_REVISION",
        sourceChangeSha256: null,
      }],
      authoritySnapshot: {
        capturedAt:
          "2026-10-04T02:00:00.000Z",
        decisions: [],
      },
      createdAt:
        "2026-10-04T02:00:00.000Z",
    });

  const candidateCanonical =
    buildCanonicalSecurityFindings(
      candidateState,
    );

  assert.throws(
    () =>
      createSecurityRepairProposal(
        candidateCanonical,
        {
          proposalId:
            "repair-candidate",
          findingId:
            "finding-auth",
          finderIdentitySha256: H6,
          createdAt:
            "2026-10-04T02:04:00.000Z",
        },
      ),
    /requires a CONFIRMED finding/,
  );
});

test("SEC8 P1 repair proposal refuses finder-validator identity collapse and self-merge", () => {
  const { canonical } =
    canonicalConfirmedFixture();

  assert.throws(
    () =>
      createSecurityRepairProposal(
        canonical,
        {
          proposalId:
            "repair-collapse",
          findingId:
            "finding-auth",
          finderIdentitySha256: H7,
          createdAt:
            "2026-10-04T02:04:00.000Z",
        },
      ),
    /finder and validator identity separation/,
  );

  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-separated",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );

  assert.throws(
    () =>
      assertSecurityRepairMergeActorSeparated(
        proposal,
        H6,
      ),
    /finder cannot merge its own fix/,
  );
  assert.throws(
    () =>
      assertSecurityRepairMergeActorSeparated(
        proposal,
        H7,
      ),
    /validator cannot merge its own fix/,
  );

  const separation =
    assertSecurityRepairMergeActorSeparated(
      proposal,
      H9,
    );
  assert.equal(
    separation.mergeAuthorityGranted,
    false,
  );
});

test("SEC8 P1 pre-mutation P6 snapshot and post-fix diff/test evidence stay bound to originating confirmed finding", () => {
  const { canonical } =
    canonicalConfirmedFixture();
  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-bound",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );

  const before = snapshot(
    "before-sec8",
    "2026-10-04T02:05:00.000Z",
    HA,
  );
  const after = snapshot(
    "after-sec8",
    "2026-10-04T02:06:00.000Z",
    HB,
  );

  const pre =
    bindSecurityRepairPreMutationSnapshot({
      canonicalFindings: canonical,
      proposal,
      snapshot: before,
      boundAt:
        "2026-10-04T02:05:30.000Z",
    });

  const diff: WorkspaceDiffReceipt =
    Object.freeze({
      schemaVersion:
        "toadaid.workspace-diff.v1",
      fromSnapshotId:
        before.snapshotId,
      toSnapshotId:
        after.snapshotId,
      entries: Object.freeze([{
        path: "src/policy/check.ts",
        kind: "MODIFIED" as const,
        fromSha256: HA,
        toSha256: HB,
      }]),
    });

  const verification =
    createSecurityRepairVerificationPackage({
      canonicalFindings: canonical,
      proposal,
      preMutation: pre,
      beforeSnapshot: before,
      afterSnapshot: after,
      diff,
      testEvidenceRefs: [{
        id: "post-fix-tests",
        sha256: H9,
      }],
      verifiedAt:
        "2026-10-04T02:07:00.000Z",
    });

  assert.equal(
    verification.record
      .findingRecordSha256,
    proposal.record
      .findingRecordSha256,
  );
  assert.equal(
    verification.record
      .beforeSnapshotId,
    "before-sec8",
  );
  assert.equal(
    verification.record
      .afterSnapshotId,
    "after-sec8",
  );
  assert.deepEqual(
    verification.record.changedPaths,
    ["src/policy/check.ts"],
  );
  assert.equal(
    verification.record
      .findingStatusMutationIncluded,
    false,
  );
  assert.equal(
    verification.record
      .mergeAuthorityIncluded,
    false,
  );
  validateSecurityRepairVerification(
    verification,
  );
});

test("SEC8 P1 repair verification refuses snapshot/diff substitution and empty test evidence", () => {
  const { canonical } =
    canonicalConfirmedFixture();
  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-refusal",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );
  const before = snapshot(
    "before-refusal",
    "2026-10-04T02:05:00.000Z",
    HA,
  );
  const after = snapshot(
    "after-refusal",
    "2026-10-04T02:06:00.000Z",
    HB,
  );
  const pre =
    bindSecurityRepairPreMutationSnapshot({
      canonicalFindings: canonical,
      proposal,
      snapshot: before,
      boundAt:
        "2026-10-04T02:05:30.000Z",
    });

  const wrongDiff: WorkspaceDiffReceipt =
    Object.freeze({
      schemaVersion:
        "toadaid.workspace-diff.v1",
      fromSnapshotId:
        "substituted-before",
      toSnapshotId:
        after.snapshotId,
      entries: Object.freeze([{
        path: "src/policy/check.ts",
        kind: "MODIFIED" as const,
        fromSha256: HA,
        toSha256: HB,
      }]),
    });

  assert.throws(
    () =>
      createSecurityRepairVerificationPackage({
        canonicalFindings: canonical,
        proposal,
        preMutation: pre,
        beforeSnapshot: before,
        afterSnapshot: after,
        diff: wrongDiff,
        testEvidenceRefs: [{
          id: "post-fix-tests",
          sha256: H9,
        }],
        verifiedAt:
          "2026-10-04T02:07:00.000Z",
      }),
    /does not match exact before\/after snapshot manifests/,
  );

  const goodDiff: WorkspaceDiffReceipt =
    Object.freeze({
      ...wrongDiff,
      fromSnapshotId:
        before.snapshotId,
    });

  assert.throws(
    () =>
      createSecurityRepairVerificationPackage({
        canonicalFindings: canonical,
        proposal,
        preMutation: pre,
        beforeSnapshot: before,
        afterSnapshot: after,
        diff: goodDiff,
        testEvidenceRefs: [],
        verifiedAt:
          "2026-10-04T02:07:00.000Z",
      }),
    /testEvidenceRefs count is invalid/,
  );
});

test("SEC8 P1 forged resealed repair proposal cannot bind downstream without canonical SEC7 truth", () => {
  const { canonical } =
    canonicalConfirmedFixture();
  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-authoritative",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );

  const forged =
    sealSecurityRepairProposalRecord({
      ...proposal.record,
      proposalId:
        "repair-resealed-forgery",
      canonicalFindingsRecordSha256:
        HA,
      auditId:
        "forged-audit",
      findingId:
        "forged-finding",
      findingRecordSha256:
        HB,
      affectedRevision:
        "forged-revision",
      affectedSourceTreeSha256:
        HA,
      proofEvidenceRefs: [{
        id: "forged-proof",
        sha256: HB,
      }],
    });

  validateSecurityRepairProposal(
    forged,
  );

  assert.throws(
    () =>
      bindSecurityRepairPreMutationSnapshot({
        canonicalFindings:
          canonical,
        proposal: forged,
        snapshot: snapshot(
          "before-forged",
          "2026-10-04T02:05:00.000Z",
          HA,
        ),
        boundAt:
          "2026-10-04T02:05:30.000Z",
      }),
    /does not match authoritative canonical finding truth|references unknown canonical finding/,
  );
});

test("SEC8 P1 verification recomputes P6 diff from exact before and after snapshots", () => {
  const { canonical } =
    canonicalConfirmedFixture();
  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-diff-recompute",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );
  const before = snapshot(
    "before-recompute",
    "2026-10-04T02:05:00.000Z",
    HA,
  );
  const after = snapshot(
    "after-recompute",
    "2026-10-04T02:06:00.000Z",
    HB,
  );
  const pre =
    bindSecurityRepairPreMutationSnapshot({
      canonicalFindings: canonical,
      proposal,
      snapshot: before,
      boundAt:
        "2026-10-04T02:05:30.000Z",
    });

  assert.throws(
    () =>
      createSecurityRepairVerificationPackage({
        canonicalFindings:
          canonical,
        proposal,
        preMutation: pre,
        beforeSnapshot: before,
        afterSnapshot: after,
        diff: {
          schemaVersion:
            "toadaid.workspace-diff.v1",
          fromSnapshotId:
            before.snapshotId,
          toSnapshotId:
            after.snapshotId,
          entries: [{
            path:
              "src/policy/check.ts",
            kind:
              "MODIFIED" as const,
            fromSha256: H3,
            toSha256: H4,
          }],
        },
        testEvidenceRefs: [{
          id: "post-fix-tests",
          sha256: H9,
        }],
        verifiedAt:
          "2026-10-04T02:07:00.000Z",
      }),
    /does not match exact before\/after snapshot manifests/,
  );

  assert.throws(
    () =>
      createSecurityRepairVerificationPackage({
        canonicalFindings:
          canonical,
        proposal,
        preMutation: pre,
        beforeSnapshot: before,
        afterSnapshot: after,
        diff: {
          schemaVersion:
            "toadaid.workspace-diff.v1",
          fromSnapshotId:
            before.snapshotId,
          toSnapshotId:
            after.snapshotId,
          entries: [{
            path:
              "src/unrelated.ts",
            kind:
              "MODIFIED" as const,
            fromSha256: HA,
            toSha256: HB,
          }],
        },
        testEvidenceRefs: [{
          id: "post-fix-tests",
          sha256: H9,
        }],
        verifiedAt:
          "2026-10-04T02:07:00.000Z",
      }),
    /does not match exact before\/after snapshot manifests/,
  );
});

test("SEC8 P1 verification rebinds actual before snapshot to pre-mutation evidence", () => {
  const { canonical } =
    canonicalConfirmedFixture();
  const proposal =
    createSecurityRepairProposal(
      canonical,
      {
        proposalId:
          "repair-before-rebind",
        findingId:
          "finding-auth",
        finderIdentitySha256: H6,
        createdAt:
          "2026-10-04T02:04:00.000Z",
      },
    );
  const before = snapshot(
    "before-rebind",
    "2026-10-04T02:05:00.000Z",
    HA,
  );
  const substitutedBefore =
    snapshot(
      "before-rebind",
      "2026-10-04T02:05:00.000Z",
      HB,
    );
  const after = snapshot(
    "after-rebind",
    "2026-10-04T02:06:00.000Z",
    HB,
  );
  const pre =
    bindSecurityRepairPreMutationSnapshot({
      canonicalFindings: canonical,
      proposal,
      snapshot: before,
      boundAt:
        "2026-10-04T02:05:30.000Z",
    });

  assert.throws(
    () =>
      createSecurityRepairVerificationPackage({
        canonicalFindings:
          canonical,
        proposal,
        preMutation: pre,
        beforeSnapshot:
          substitutedBefore,
        afterSnapshot: after,
        diff: {
          schemaVersion:
            "toadaid.workspace-diff.v1",
          fromSnapshotId:
            before.snapshotId,
          toSnapshotId:
            after.snapshotId,
          entries: [{
            path:
              "src/policy/check.ts",
            kind:
              "MODIFIED" as const,
            fromSha256: HA,
            toSha256: HB,
          }],
        },
        testEvidenceRefs: [{
          id: "post-fix-tests",
          sha256: H9,
        }],
        verifiedAt:
          "2026-10-04T02:07:00.000Z",
      }),
    /before snapshot does not match pre-mutation binding/,
  );
});
