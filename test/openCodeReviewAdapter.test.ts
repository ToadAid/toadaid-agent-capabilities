import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  buildOcrDelegatePreviewInvocation,
  buildOcrDelegateRuleInvocations,
  createOpenCodeReviewPlan,
  createReviewCoverageState,
  createReviewReflectionPacket,
  executeGovernedReviewFix,
  finalizeOpenCodeReview,
  markReviewFileReviewed,
  markReviewFileSkipped,
  openCodeReviewReceiptSha256,
  parseOcrDelegatePreviewJson,
  parseOcrDelegateRulesJson,
} from "../src/openCodeReviewAdapter.js";

function authority(capabilityId: string, decision: "ALLOW" | "BLOCK" = "ALLOW"): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision,
    reason: decision === "ALLOW" ? "AUTHORIZED_BY_POLICY" : "BLOCKED_BY_POLICY",
    trace: [],
  };
}

const previewJson = JSON.stringify({
  schema_version: "1",
  mode: "workspace",
  repository: "/repo",
  total_files: 3,
  reviewable_count: 2,
  excluded_count: 1,
  total_insertions: 15,
  total_deletions: 4,
  reviewable_files: [
    { path: "src/a.ts", status: "MODIFIED", insertions: 10, deletions: 4 },
    { path: "src/b.ts", status: "ADDED", insertions: 5, deletions: 0 },
  ],
  excluded_files: [
    { path: "vendor/x.js", status: "MODIFIED", insertions: 0, deletions: 0, exclude_reason: "excluded path" },
  ],
});

const rulesJson = JSON.stringify({
  schema_version: "1",
  groups: [
    { group_id: 1, source: "repo", pattern: "src/**", files: ["src/a.ts", "src/b.ts"], rule: "Check correctness and tests." },
  ],
});

test("builds argv-only delegation invocations", () => {
  assert.deepEqual(buildOcrDelegatePreviewInvocation({ mode: "range", from: "main", to: "feature/x" }), {
    executable: "ocr",
    args: ["delegate", "preview", "--format", "json", "--from", "main", "--to", "feature/x"],
  });
  assert.deepEqual(buildOcrDelegateRuleInvocations(["src/a.ts", "src/b.ts"], 1), [
    { executable: "ocr", args: ["delegate", "rule", "--format", "json", "--", "src/a.ts"] },
    { executable: "ocr", args: ["delegate", "rule", "--format", "json", "--", "src/b.ts"] },
  ]);
  assert.throws(() => buildOcrDelegatePreviewInvocation({ mode: "range", from: "--help", to: "x" }), /accepted Git ref/);
});

test("parses current OCR schema and rejects unsafe paths", () => {
  const preview = parseOcrDelegatePreviewJson(previewJson);
  assert.equal(preview.schemaVersion, "1");
  assert.equal(preview.reviewableFiles.length, 2);
  const unsafe = JSON.parse(previewJson);
  unsafe.reviewable_files[0].path = "../secret";
  assert.throws(() => parseOcrDelegatePreviewJson(JSON.stringify(unsafe)), /unsafe path segment/);
});

test("rules require unique path assignment", () => {
  const duplicate = JSON.stringify({ schema_version: "1", groups: [
    { group_id: 1, source: "a", pattern: "*", files: ["src/a.ts"], rule: "a" },
    { group_id: 2, source: "b", pattern: "*", files: ["src/a.ts"], rule: "b" },
  ]});
  assert.throws(() => parseOcrDelegateRulesJson(duplicate), /more than one group/);
});

test("plan is deterministic and bounded with mandatory rule coverage", () => {
  const preview = parseOcrDelegatePreviewJson(previewJson);
  const rules = parseOcrDelegateRulesJson(rulesJson);
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), preview, rules, { maxFilesPerBatch: 1 });
  assert.equal(plan.checklist.length, 2);
  assert.equal(plan.batches.length, 2);
  assert.equal(plan.childTasks.filter((child) => child.role === "REVIEWER").length, 2);
  assert.equal(plan.childTasks.at(-1)?.role, "REFLECTION");
  assert.ok(plan.childTasks.every((child) => child.delegatedCapabilities.length === 1 && child.delegatedCapabilities[0] === "review:inspect"));

  const missing = parseOcrDelegateRulesJson(JSON.stringify({ schema_version: "1", groups: [
    { group_id: 1, source: "repo", pattern: "src/a.ts", files: ["src/a.ts"], rule: "x" },
  ]}));
  assert.throws(() => createOpenCodeReviewPlan(authority("review:inspect"), preview, missing), /did not account/);
});

test("same path with different status gets distinct checklist identity", () => {
  const preview = parseOcrDelegatePreviewJson(JSON.stringify({
    schema_version: "1", mode: "workspace", repository: "/repo",
    total_files: 2, reviewable_count: 2, excluded_count: 0, total_insertions: 4, total_deletions: 3,
    reviewable_files: [
      { path: "src/a.ts", status: "DELETED", insertions: 0, deletions: 3 },
      { path: "src/a.ts", status: "UNTRACKED", insertions: 4, deletions: 0 },
    ], excluded_files: [],
  }));
  const rules = parseOcrDelegateRulesJson(JSON.stringify({ schema_version: "1", groups: [
    { group_id: 1, source: "repo", pattern: "src/**", files: ["src/a.ts"], rule: "x" },
  ]}));
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), preview, rules);
  assert.equal(plan.checklist.length, 2);
  assert.notEqual(plan.checklist[0]!.key, plan.checklist[1]!.key);
});

test("inspection requires exact current authority", () => {
  const preview = parseOcrDelegatePreviewJson(previewJson);
  const rules = parseOcrDelegateRulesJson(rulesJson);
  assert.throws(() => createOpenCodeReviewPlan(authority("review:inspect", "BLOCK"), preview, rules), /not authorized/);
  assert.throws(() => createOpenCodeReviewPlan(authority("review:fix"), preview, rules), /review:inspect/);
});

test("coverage cannot finalize with pending files", () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  const state = createReviewCoverageState(plan);
  assert.throws(() => finalizeOpenCodeReview(plan, state, "2026-09-24T22:40:00.000Z"), /incomplete/);
});

test("every file is reviewed or skipped with concrete reason", () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  let state = createReviewCoverageState(plan);
  state = markReviewFileReviewed(state, plan.checklist[0]!.key, [{ content: "Possible null dereference", category: "bug", severity: "high", startLine: 12 }]);
  assert.throws(() => markReviewFileSkipped(state, plan.checklist[1]!.key, "   "), /must not be empty/);
  state = markReviewFileSkipped(state, plan.checklist[1]!.key, "Generated fixture; excluded after manual verification");
  const receipt = finalizeOpenCodeReview(plan, state, "2026-09-24T22:40:00.000Z");
  assert.equal(receipt.coverageRate, 1);
  assert.equal(receipt.reviewedFiles, 1);
  assert.equal(receipt.skippedFiles, 1);
  assert.equal(receipt.findings.length, 1);
  assert.match(openCodeReviewReceiptSha256(receipt), /^[a-f0-9]{64}$/);
  const reflection = createReviewReflectionPacket(receipt);
  assert.equal(reflection.findingCount, 1);
});

test("settled coverage cannot be silently rewritten", () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  let state = createReviewCoverageState(plan);
  state = markReviewFileReviewed(state, plan.checklist[0]!.key);
  assert.throws(() => markReviewFileReviewed(state, plan.checklist[0]!.key), /already settled/);
});

test("governed fix requires review:fix plus P6 snapshot and diff authority", async () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  let state = createReviewCoverageState(plan);
  state = markReviewFileReviewed(state, plan.checklist[0]!.key, [{ content: "Bug", severity: "high" }]);
  state = markReviewFileReviewed(state, plan.checklist[1]!.key);
  const receipt = finalizeOpenCodeReview(plan, state, "2026-09-24T22:40:00.000Z");
  const finding = receipt.findings[0]!;
  const calls: string[] = [];
  const bridge = {
    async snapshot(label: "before" | "after") {
      calls.push(`snapshot:${label}`);
      return {
        schemaVersion: "toadaid.workspace-snapshot.v1" as const,
        snapshotId: label,
        workspaceId: "repo",
        createdAt: "2026-09-24T22:45:00.000Z",
        files: [],
        totalBytes: 0,
        policy: { maxFiles: 1, maxFileBytes: 1, maxTotalBytes: 1, excludedPaths: [] },
      };
    },
    async apply(findings: readonly unknown[]) { calls.push(`apply:${findings.length}`); },
    async diff(before: { snapshotId: string }, after: { snapshotId: string }) {
      calls.push("diff");
      return { schemaVersion: "toadaid.workspace-diff.v1" as const, fromSnapshotId: before.snapshotId, toSnapshotId: after.snapshotId, entries: [] };
    },
  };
  await assert.rejects(
    () => executeGovernedReviewFix(
      { completedAt: "2026-09-24T22:50:00.000Z", receipt, findingIds: [finding.findingId] },
      { reviewFix: authority("review:fix"), workspaceSnapshot: authority("workspace:snapshot", "BLOCK"), workspaceDiff: authority("workspace:diff") },
      bridge,
    ),
    /workspace:snapshot/,
  );
  assert.deepEqual(calls, []);

  const fixReceipt = await executeGovernedReviewFix(
    { completedAt: "2026-09-24T22:50:00.000Z", receipt, findingIds: [finding.findingId] },
    { reviewFix: authority("review:fix"), workspaceSnapshot: authority("workspace:snapshot"), workspaceDiff: authority("workspace:diff") },
    bridge,
  );
  assert.deepEqual(calls, ["snapshot:before", "apply:1", "snapshot:after", "diff"]);
  assert.equal(fixReceipt.beforeSnapshotId, "before");
  assert.equal(fixReceipt.afterSnapshotId, "after");
});

test("fix cannot name a finding that was not in the completed review", async () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  let state = createReviewCoverageState(plan);
  state = markReviewFileReviewed(state, plan.checklist[0]!.key);
  state = markReviewFileReviewed(state, plan.checklist[1]!.key);
  const receipt = finalizeOpenCodeReview(plan, state, "2026-09-24T22:40:00.000Z");
  await assert.rejects(
    () => executeGovernedReviewFix(
      { completedAt: "2026-09-24T22:50:00.000Z", receipt, findingIds: ["deadbeef"] },
      { reviewFix: authority("review:fix"), workspaceSnapshot: authority("workspace:snapshot"), workspaceDiff: authority("workspace:diff") },
      {
        snapshot: async () => ({ schemaVersion: "toadaid.workspace-snapshot.v1" as const, snapshotId: "x", workspaceId: "repo", createdAt: "2026-09-24T22:45:00.000Z", files: [], totalBytes: 0, policy: { maxFiles: 1, maxFileBytes: 1, maxTotalBytes: 1, excludedPaths: [] } }),
        apply: async () => {},
        diff: async () => ({ schemaVersion: "toadaid.workspace-diff.v1", fromSnapshotId: "x", toSnapshotId: "y", entries: [] }),
      },
    ),
    /unknown findingId/,
  );
});

test("fix receipt refuses a diff that is not bound to the before/after snapshots", async () => {
  const plan = createOpenCodeReviewPlan(authority("review:inspect"), parseOcrDelegatePreviewJson(previewJson), parseOcrDelegateRulesJson(rulesJson));
  let state = createReviewCoverageState(plan);
  state = markReviewFileReviewed(state, plan.checklist[0]!.key, [{ content: "Bug", severity: "high" }]);
  state = markReviewFileReviewed(state, plan.checklist[1]!.key);
  const receipt = finalizeOpenCodeReview(plan, state, "2026-09-24T22:40:00.000Z");
  const finding = receipt.findings[0]!;
  await assert.rejects(
    () => executeGovernedReviewFix(
      { completedAt: "2026-09-24T22:50:00.000Z", receipt, findingIds: [finding.findingId] },
      { reviewFix: authority("review:fix"), workspaceSnapshot: authority("workspace:snapshot"), workspaceDiff: authority("workspace:diff") },
      {
        snapshot: async (label) => ({ schemaVersion: "toadaid.workspace-snapshot.v1" as const, snapshotId: label, workspaceId: "repo", createdAt: "2026-09-24T22:45:00.000Z", files: [], totalBytes: 0, policy: { maxFiles: 1, maxFileBytes: 1, maxTotalBytes: 1, excludedPaths: [] } }),
        apply: async () => {},
        diff: async () => ({ schemaVersion: "toadaid.workspace-diff.v1", fromSnapshotId: "wrong", toSnapshotId: "also-wrong", entries: [] }),
      },
    ),
    /different snapshots/,
  );
});
