import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  createOpenCodeReviewPlan,
  parseOcrDelegatePreviewJson,
  parseOcrDelegateRulesJson,
} from "../src/openCodeReviewAdapter.js";
import {
  assertReviewSessionPredecessor,
  createReviewPresentationState,
  createReviewSession,
  parseReviewSession,
  resumeReviewSession,
  sealReviewSessionRecord,
  serializeReviewSession,
  validateReviewSessionEnvelope,
} from "../src/reviewSession.js";

const REPOSITORY_SHA = "1".repeat(64);
const SOURCE_SHA = "2".repeat(64);
const RULES_SHA = "3".repeat(64);
const FINDING_A = "a".repeat(64);
const FINDING_B = "b".repeat(64);

function authority(): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId: "review:inspect",
    installed: true,
    decision: "ALLOW",
    reason: "AUTHORIZED_BY_POLICY",
    trace: [],
  };
}

function plan(maxFilesPerBatch = 10) {
  const preview = parseOcrDelegatePreviewJson(JSON.stringify({
    schema_version: "1",
    mode: "workspace",
    repository: "/repo",
    total_files: 2,
    reviewable_count: 2,
    excluded_count: 0,
    total_insertions: 15,
    total_deletions: 4,
    reviewable_files: [
      { path: "src/a.ts", status: "MODIFIED", insertions: 10, deletions: 4 },
      { path: "src/b.ts", status: "ADDED", insertions: 5, deletions: 0 },
    ],
    excluded_files: [],
  }));
  const rules = parseOcrDelegateRulesJson(JSON.stringify({
    schema_version: "1",
    groups: [
      {
        group_id: 1,
        source: "repo",
        pattern: "src/**",
        files: ["src/a.ts", "src/b.ts"],
        rule: "Check correctness and tests.",
      },
    ],
  }));
  return createOpenCodeReviewPlan(
    authority(),
    preview,
    rules,
    { maxFilesPerBatch },
  );
}

function createFixture() {
  return createReviewSession({
    sessionId: "review-session-1",
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "openai",
    model: "gpt-review",
    createdAt: "2026-09-26T05:20:00.000Z",
  });
}

test("R2 creates a sealed session bound to exact R1 review identity", () => {
  const session = createFixture();
  assert.equal(session.record.sessionId, "review-session-1");
  assert.equal(session.record.revision, 0);
  assert.equal(session.record.binding.repositoryIdentitySha256, REPOSITORY_SHA);
  assert.equal(session.record.binding.reviewedSourceSha256, SOURCE_SHA);
  assert.equal(session.record.binding.rulesSha256, RULES_SHA);
  assert.equal(session.record.binding.reviewMode, "workspace");
  assert.equal(session.record.transition, "INITIAL");
  assert.equal(session.record.lineage.parentRecordSha256, null);
  assert.equal(session.record.lineage.runtimeChanged, false);
  assert.match(session.record.binding.planSha256, /^[a-f0-9]{64}$/);
  assert.match(session.recordSha256, /^[a-f0-9]{64}$/);
});

test("R2 exact resume advances predecessor continuity without runtime transition", () => {
  const first = createFixture();
  const resumed = resumeReviewSession(first, {
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "openai",
    model: "gpt-review",
    resumedAt: "2026-09-26T05:21:00.000Z",
  });

  assert.equal(resumed.record.sessionId, first.record.sessionId);
  assert.equal(resumed.record.revision, 1);
  assert.equal(resumed.record.transition, "RESUME_SAME_RUNTIME");
  assert.equal(
    resumed.record.continuity.previousRecordSha256,
    first.recordSha256,
  );
  assert.equal(resumed.record.lineage.parentRecordSha256, first.recordSha256);
  assert.equal(resumed.record.lineage.runtimeChanged, false);
});

test("R2 refuses repository, source, rules, and plan drift on resume", () => {
  const first = createFixture();
  const base = {
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "openai",
    model: "gpt-review",
    resumedAt: "2026-09-26T05:21:00.000Z",
  };

  assert.throws(
    () => resumeReviewSession(first, {
      ...base,
      repositoryIdentitySha256: "4".repeat(64),
    }),
    /repository identity changed/,
  );
  assert.throws(
    () => resumeReviewSession(first, {
      ...base,
      reviewedSourceSha256: "5".repeat(64),
    }),
    /reviewed source changed/,
  );
  assert.throws(
    () => resumeReviewSession(first, {
      ...base,
      rulesSha256: "6".repeat(64),
    }),
    /rules\/config changed/,
  );
  assert.throws(
    () => resumeReviewSession(first, {
      ...base,
      plan: plan(1),
    }),
    /R1 review plan changed/,
  );
});

test("R2 refuses provider/model drift unless transition is explicit", () => {
  const first = createFixture();
  assert.throws(
    () => resumeReviewSession(first, {
      plan: plan(),
      repositoryIdentitySha256: REPOSITORY_SHA,
      reviewedSourceSha256: SOURCE_SHA,
      rulesSha256: RULES_SHA,
      provider: "other-provider",
      model: "other-model",
      resumedAt: "2026-09-26T05:21:00.000Z",
    }),
    /explicit runtime transition acceptance is required/,
  );
});

test("R2 explicit runtime transition emits parent-child lineage evidence only", () => {
  const first = createFixture();
  const resumed = resumeReviewSession(first, {
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "other-provider",
    model: "other-model",
    acceptRuntimeTransition: true,
    resumedAt: "2026-09-26T05:21:00.000Z",
  });

  assert.equal(resumed.record.transition, "RESUME_RUNTIME_TRANSITION");
  assert.equal(resumed.record.lineage.parentRecordSha256, first.recordSha256);
  assert.deepEqual(resumed.record.lineage.fromRuntime, {
    provider: "openai",
    model: "gpt-review",
  });
  assert.deepEqual(resumed.record.lineage.toRuntime, {
    provider: "other-provider",
    model: "other-model",
  });
  assert.equal(resumed.record.lineage.runtimeChanged, true);
  assert.equal("authority" in resumed.record, false);
  assert.equal("fixAuthority" in resumed.record, false);
});

test("R2 presentation state evolves without rewriting immutable session evidence", () => {
  const session = createFixture();
  const beforeSha = session.recordSha256;
  const firstView = createReviewPresentationState(session, {
    selectedFindingId: FINDING_A,
  });
  const secondView = createReviewPresentationState(session, {
    selectedFindingId: FINDING_B,
    hiddenFindingIds: [FINDING_A],
  });

  assert.equal(firstView.sessionRecordSha256, beforeSha);
  assert.equal(secondView.sessionRecordSha256, beforeSha);
  assert.notDeepEqual(firstView, secondView);
  assert.equal(session.recordSha256, beforeSha);
});

test("R2 parsed records reject unknown transition values and non-boolean lineage flags", () => {
  const first = createFixture();
  const resumed = resumeReviewSession(first, {
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "openai",
    model: "gpt-review",
    resumedAt: "2026-09-26T05:21:00.000Z",
  });

  assert.throws(
    () => sealReviewSessionRecord({
      ...resumed.record,
      transition: "FROG_TELEPORT" as never,
    }),
    /transition is invalid/,
  );

  assert.throws(
    () => sealReviewSessionRecord({
      ...first.record,
      lineage: {
        ...first.record.lineage,
        runtimeChanged: 0 as unknown as boolean,
      },
    }),
    /runtimeChanged must be boolean/,
  );
});

test("R2 predecessor assertion proves actual parent binding and runtime lineage", () => {
  const first = createFixture();
  const resumed = resumeReviewSession(first, {
    plan: plan(),
    repositoryIdentitySha256: REPOSITORY_SHA,
    reviewedSourceSha256: SOURCE_SHA,
    rulesSha256: RULES_SHA,
    provider: "openai",
    model: "gpt-review",
    resumedAt: "2026-09-26T05:21:00.000Z",
  });

  assert.doesNotThrow(() => assertReviewSessionPredecessor(first, resumed));

  const fakeParent = "f".repeat(64);
  const forged = sealReviewSessionRecord({
    ...resumed.record,
    lineage: {
      ...resumed.record.lineage,
      parentRecordSha256: fakeParent,
    },
    continuity: {
      previousRecordSha256: fakeParent,
    },
  });

  assert.throws(
    () => assertReviewSessionPredecessor(first, forged),
    /predecessor digest mismatch/,
  );
});

test("R2 parser strips unknown envelope fields instead of carrying ambient authority", () => {
  const session = createFixture();
  const serialized = JSON.stringify({
    ...session,
    authority: {
      capabilityId: "review:fix",
      decision: "ALLOW",
    },
  });

  const parsed = parseReviewSession(serialized);
  assert.equal("authority" in parsed, false);
  assert.deepEqual(parsed, session);
});

test("R2 serialization preserves integrity and tampering fails closed", () => {
  const session = createFixture();
  const parsed = parseReviewSession(serializeReviewSession(session));
  assert.deepEqual(parsed, session);

  const tampered = {
    ...session,
    record: {
      ...session.record,
      binding: {
        ...session.record.binding,
        rulesSha256: "9".repeat(64),
      },
    },
  };

  assert.throws(
    () => validateReviewSessionEnvelope(tampered),
    /integrity mismatch/,
  );
});
