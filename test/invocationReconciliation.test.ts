import assert from "node:assert/strict";
import test from "node:test";

import {
  assessCapabilityInvocationResume,
  authorizeCapabilityInvocation,
  beginCapabilityInvocationReconciliation,
  closeCapabilityInvocationReconciliation,
  completeCapabilityInvocation,
  createCapabilityInvocation,
  failCapabilityInvocation,
  sealCapabilityInvocationRecord,
  startCapabilityInvocation,
} from "../src/capabilityInvocation.js";
import {
  createReplayFence,
  resolveReplayReconciliation,
} from "../src/replayFence.js";
import type {
  CapabilityManifest,
  CapabilityPolicyLayer,
} from "../src/capabilityPolicy.js";

const H = "a".repeat(64);
const H2 = "b".repeat(64);
const H3 = "c".repeat(64);
const OPENED_AT = "2026-10-02T13:00:03.000Z";
const RESOLVED_AT = "2026-10-02T13:00:04.000Z";
const CLOSED_AT = "2026-10-02T13:00:05.000Z";

const manifest: CapabilityManifest = {
  schemaVersion: "toadaid.capability-manifest.v1",
  capabilities: [
    {
      id: "review:fix",
      description: "fix",
      defaultDecision: "BLOCK",
    },
  ],
};
const policyLayers: readonly CapabilityPolicyLayer[] = [
  {
    scope: "agent",
    subject: "frog",
    decisions: { "review:fix": "ALLOW" },
  },
];
const policy = { manifest, policyLayers };

function requested(invocationId: string) {
  return createCapabilityInvocation({
    invocationId,
    runId: "run-reconcile-1",
    capabilityId: "review:fix",
    toolName: "review.fix",
    intentSha256: H,
    argumentsSha256: H2,
    createdAt: "2026-10-02T13:00:00.000Z",
  });
}

function authorized(invocationId: string) {
  return authorizeCapabilityInvocation(
    requested(invocationId),
    policy,
    { now: () => new Date("2026-10-02T13:00:01.000Z") },
  );
}

function started(invocationId = "inv-reconcile-1") {
  return startCapabilityInvocation(
    authorized(invocationId),
    "manager-a",
    policy,
    { now: () => new Date("2026-10-02T13:00:02.000Z") },
  );
}

function openLocked(
  replayClass: "SAFE_READ" | "NON_REPLAYABLE" = "NON_REPLAYABLE",
  invocationId = "inv-reconcile-1",
) {
  const invocation = started(invocationId);
  const fence = createReplayFence(
    authorized(invocationId),
    { replayClass },
    { now: () => new Date("2026-10-02T13:00:01.500Z") },
  );
  return beginCapabilityInvocationReconciliation(
    fence,
    invocation,
    {
      reconciliationId: `recon-${invocationId}`,
      reasonCode: "OUTCOME_UNKNOWN",
      evidenceRefs: [
        { id: "provider-error", sha256: H3 },
      ],
      openedAt: OPENED_AT,
    },
    {
      now: () => new Date(OPENED_AT),
      randomId: () => `recon-${invocationId}`,
    },
  );
}

test("H1/X1B-P1 opening X1 yields a reconciliation-locked H1 successor", () => {
  const pair = openLocked();
  assert.equal(
    pair.invocation.record.status,
    "RECONCILIATION_REQUIRED",
  );
  assert.equal(pair.reconciliation.record.status, "OPEN");
  assert.equal(
    pair.invocation.record.reconciliation?.openReconciliationSha256,
    pair.reconciliation.recordSha256,
  );
  assert.equal(
    pair.reconciliation.record.invocationRecordSha256,
    pair.invocation.record.continuity.previousRecordSha256,
  );
  assert.equal(
    assessCapabilityInvocationResume(pair.invocation, policy).decision,
    "RECONCILIATION_REQUIRED",
  );
});

test("H1/X1B-P1 reconciliation lock cannot move lifecycle time backward", () => {
  const invocation = started("inv-reconcile-time");
  const fence = createReplayFence(
    authorized("inv-reconcile-time"),
    { replayClass: "NON_REPLAYABLE" },
    {
      now: () =>
        new Date("2026-10-02T13:00:01.500Z"),
    },
  );

  assert.throws(
    () =>
      beginCapabilityInvocationReconciliation(
        fence,
        invocation,
        {
          reconciliationId:
            "recon-inv-reconcile-time",
          reasonCode: "OUTCOME_UNKNOWN",
          openedAt:
            "2026-10-02T13:00:01.500Z",
        },
        {
          now: () =>
            new Date(
              "2026-10-02T13:00:01.500Z",
            ),
        },
      ),
    /earlier than active H1 predecessor/,
  );
});

test("H1/X1B-P1 sealed lock must bind its direct predecessor SHA", () => {
  const pair = openLocked(
    "NON_REPLAYABLE",
    "inv-reconcile-lock-integrity",
  );
  const lock = pair.invocation.record.reconciliation;
  if (!lock) {
    throw new Error("expected reconciliation lock");
  }

  assert.throws(
    () =>
      sealCapabilityInvocationRecord({
        ...pair.invocation.record,
        reconciliation: {
          ...lock,
          invocationRecordSha256: H3,
        },
      }),
    /lock predecessor SHA mismatch/,
  );
});

test("H1/X1B-P1 reconciliation lock blocks ordinary COMPLETED and FAILED terminalizers", () => {
  const pair = openLocked();
  assert.throws(
    () =>
      completeCapabilityInvocation(
        pair.invocation,
        "manager-a",
        H3,
      ),
    /only started invocation may complete/,
  );
  assert.throws(
    () =>
      failCapabilityInvocation(
        pair.invocation,
        "manager-a",
        "ProviderTimeout",
        H3,
      ),
    /only started invocation may fail/,
  );
});

test("H1/X1B-P1 confirmed executed resolves to terminal RECONCILED EXECUTED truth", () => {
  const pair = openLocked("SAFE_READ");
  const resolved = resolveReplayReconciliation(
    pair.reconciliation,
    {
      finding: "CONFIRMED_EXECUTED",
      proofSha256: H3,
      proofRefs: [
        { id: "provider-proof", sha256: H2 },
      ],
      resolvedAt: RESOLVED_AT,
    },
  );
  const terminal =
    closeCapabilityInvocationReconciliation(
      pair.invocation,
      resolved,
      "manager-closeout",
      { now: () => new Date(CLOSED_AT) },
    );

  assert.equal(terminal.record.status, "RECONCILED");
  if (terminal.record.outcome?.kind !== "RECONCILED") {
    throw new Error("expected reconciled outcome");
  }
  assert.equal(
    terminal.record.outcome.executionTruth,
    "EXECUTED",
  );
  assert.equal(
    terminal.record.outcome.reconciliationSha256,
    resolved.recordSha256,
  );
  assert.equal(
    terminal.record.outcome.disposition,
    "DO_NOT_RETRY",
  );
  assert.equal(
    assessCapabilityInvocationResume(terminal, policy).decision,
    "TERMINAL",
  );
});

test("H1/X1B-P1 confirmed not executed remains explicit and preserves NEW_INVOCATION_REQUIRED", () => {
  const pair = openLocked("NON_REPLAYABLE");
  const resolved = resolveReplayReconciliation(
    pair.reconciliation,
    {
      finding: "CONFIRMED_NOT_EXECUTED",
      proofSha256: H3,
      resolvedAt: RESOLVED_AT,
    },
  );
  const terminal =
    closeCapabilityInvocationReconciliation(
      pair.invocation,
      resolved,
      "manager-closeout",
      { now: () => new Date(CLOSED_AT) },
    );
  if (terminal.record.outcome?.kind !== "RECONCILED") {
    throw new Error("expected reconciled outcome");
  }
  assert.equal(
    terminal.record.outcome.executionTruth,
    "NOT_EXECUTED",
  );
  assert.equal(
    terminal.record.outcome.disposition,
    "NEW_INVOCATION_REQUIRED",
  );
});

test("H1/X1B-P1 still-unknown truth is terminalized explicitly rather than fabricated", () => {
  const pair = openLocked("NON_REPLAYABLE");
  const resolved = resolveReplayReconciliation(
    pair.reconciliation,
    {
      finding: "STILL_UNKNOWN",
      resolvedAt: RESOLVED_AT,
    },
  );
  const terminal =
    closeCapabilityInvocationReconciliation(
      pair.invocation,
      resolved,
      "manager-closeout",
      { now: () => new Date(CLOSED_AT) },
    );
  if (terminal.record.outcome?.kind !== "RECONCILED") {
    throw new Error("expected reconciled outcome");
  }
  assert.equal(
    terminal.record.outcome.executionTruth,
    "UNKNOWN",
  );
  assert.equal(terminal.record.outcome.proofSha256, null);
  assert.equal(
    terminal.record.outcome.disposition,
    "DO_NOT_RETRY",
  );
});

test("H1/X1B-P1 sealed reconciled outcome cannot contradict lock identity", () => {
  const pair = openLocked(
    "NON_REPLAYABLE",
    "inv-reconcile-terminal-integrity",
  );
  const resolved = resolveReplayReconciliation(
    pair.reconciliation,
    {
      finding: "CONFIRMED_EXECUTED",
      proofSha256: H3,
      resolvedAt: RESOLVED_AT,
    },
  );
  const terminal =
    closeCapabilityInvocationReconciliation(
      pair.invocation,
      resolved,
      "manager-closeout",
      { now: () => new Date(CLOSED_AT) },
    );
  const reconciledOutcome =
    terminal.record.outcome;
  if (
    reconciledOutcome?.kind !==
    "RECONCILED"
  ) {
    throw new Error("expected reconciled outcome");
  }

  assert.throws(
    () =>
      sealCapabilityInvocationRecord({
        ...terminal.record,
        outcome: {
          ...reconciledOutcome,
          reconciliationId:
            "recon-substituted",
        },
      }),
    /contradicts H1\/X1 lock identity/,
  );
});

test("H1/X1B-P1 closeout refuses unresolved or unrelated X1 lineage", () => {
  const pair = openLocked("NON_REPLAYABLE");
  assert.throws(
    () =>
      closeCapabilityInvocationReconciliation(
        pair.invocation,
        pair.reconciliation,
        "manager-closeout",
        { now: () => new Date(CLOSED_AT) },
      ),
    /requires resolved X1 truth/,
  );

  const other = openLocked(
    "NON_REPLAYABLE",
    "inv-reconcile-other",
  );
  const otherResolved = resolveReplayReconciliation(
    other.reconciliation,
    {
      finding: "CONFIRMED_EXECUTED",
      proofSha256: H3,
      resolvedAt: RESOLVED_AT,
    },
  );
  assert.throws(
    () =>
      closeCapabilityInvocationReconciliation(
        pair.invocation,
        otherResolved,
        "manager-closeout",
        { now: () => new Date(CLOSED_AT) },
      ),
    /does not continue exact H1\/X1 lock/,
  );
});

test("H1/X1B-P1 closeout timestamp cannot predate resolved X1 evidence", () => {
  const pair = openLocked("NON_REPLAYABLE");
  const resolved = resolveReplayReconciliation(
    pair.reconciliation,
    {
      finding: "CONFIRMED_EXECUTED",
      proofSha256: H3,
      resolvedAt: RESOLVED_AT,
    },
  );
  assert.throws(
    () =>
      closeCapabilityInvocationReconciliation(
        pair.invocation,
        resolved,
        "manager-closeout",
        {
          now: () =>
            new Date("2026-10-02T13:00:03.500Z"),
        },
      ),
    /earlier than X1 resolution/,
  );
});
