import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  assertRunStatePredecessor,
  checkpointRunStateCapsule,
  createRunStateCapsule,
  parseRunStateCapsule,
  resolveResumeCapabilityAuthority,
  resumeRunStateCapsule,
  runStateCapsuleSha256,
  serializeRunStateCapsule,
} from "../src/runStateCapsule.js";

function authority(capabilityId: string, decision: "ALLOW" | "BLOCK"): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision,
    reason: decision === "ALLOW" ? "AUTHORIZED_BY_POLICY" : "BLOCKED_BY_POLICY",
    trace: [],
  };
}

function initialCapsule() {
  return createRunStateCapsule({
    runId: "run-001",
    createdAt: "2026-09-24T20:00:00.000Z",
    objective: { summary: "Inspect and repair the portal", status: "ACTIVE" },
    phase: "inspect",
    authoritySnapshot: {
      capturedAt: "2026-09-24T20:00:00.000Z",
      decisions: [
        authority("browser:evidence", "ALLOW"),
        authority("browser:interaction", "BLOCK"),
      ],
    },
    evidenceRefs: [
      { id: "evidence-2", locator: "receipt:2" },
      { id: "evidence-1", locator: "receipt:1" },
    ],
    work: {
      pending: [
        { id: "work-2", summary: "Repair the portal" },
        { id: "work-1", summary: "Inspect the portal" },
      ],
    },
  });
}

test("creates canonical bounded run state", () => {
  const capsule = initialCapsule();

  assert.equal(capsule.revision, 0);
  assert.equal(capsule.continuity.reason, "INITIAL");
  assert.deepEqual(capsule.evidenceRefs.map((entry) => entry.id), ["evidence-1", "evidence-2"]);
  assert.deepEqual(capsule.work.pending.map((entry) => entry.id), ["work-1", "work-2"]);
  assert.match(runStateCapsuleSha256(capsule), /^[a-f0-9]{64}$/);
});

test("sealed capsule detects tampering", () => {
  const serialized = serializeRunStateCapsule(initialCapsule());
  const envelope = JSON.parse(serialized) as { capsule: { phase: string } };
  envelope.capsule.phase = "hijacked";

  assert.throws(() => parseRunStateCapsule(JSON.stringify(envelope)), /integrity mismatch/);
});

test("checkpoint advances a tamper-evident contiguous chain", () => {
  const initial = initialCapsule();
  const checkpoint = checkpointRunStateCapsule(initial, {
    updatedAt: "2026-09-24T20:10:00.000Z",
    reason: "COMPACTION",
    phase: "repair",
    work: {
      completed: [{ id: "work-1", summary: "Inspect the portal" }],
      pending: [{ id: "work-2", summary: "Repair the portal" }],
    },
  });

  assert.equal(checkpoint.revision, 1);
  assert.equal(checkpoint.continuity.previousCapsuleSha256, runStateCapsuleSha256(initial));
  assert.deepEqual(checkpoint.authoritySnapshot, initial.authoritySnapshot);
  assert.doesNotThrow(() => assertRunStatePredecessor(initial, checkpoint));
});

test("restart preserves objective, work, references, and authority snapshot", () => {
  const initial = initialCapsule();
  const resumed = resumeRunStateCapsule(
    serializeRunStateCapsule(initial),
    "2026-09-24T20:20:00.000Z",
  );

  assert.equal(resumed.revision, 1);
  assert.equal(resumed.continuity.reason, "RESTART");
  assert.equal(resumed.objective.summary, initial.objective.summary);
  assert.deepEqual(resumed.work, initial.work);
  assert.deepEqual(resumed.evidenceRefs, initial.evidenceRefs);
  assert.deepEqual(resumed.authoritySnapshot, initial.authoritySnapshot);
  assert.doesNotThrow(() => assertRunStatePredecessor(initial, resumed));
});

test("resume authority is the intersection of snapshot and current policy", () => {
  const capsule = initialCapsule();

  assert.equal(
    resolveResumeCapabilityAuthority(
      "browser:evidence",
      capsule,
      [authority("browser:evidence", "ALLOW")],
    ).decision,
    "ALLOW",
  );

  assert.equal(
    resolveResumeCapabilityAuthority(
      "browser:evidence",
      capsule,
      [authority("browser:evidence", "BLOCK")],
    ).reason,
    "BLOCKED_BY_CURRENT_POLICY",
  );

  assert.equal(
    resolveResumeCapabilityAuthority(
      "browser:interaction",
      capsule,
      [authority("browser:interaction", "ALLOW")],
    ).reason,
    "BLOCKED_IN_SNAPSHOT",
  );

  assert.equal(
    resolveResumeCapabilityAuthority(
      "review:inspect",
      capsule,
      [authority("review:inspect", "ALLOW")],
    ).reason,
    "UNKNOWN_IN_SNAPSHOT",
  );
});

test("work item ids cannot exist in multiple lifecycle buckets", () => {
  assert.throws(
    () => createRunStateCapsule({
      runId: "run-duplicate-work",
      createdAt: "2026-09-24T20:00:00.000Z",
      objective: { summary: "Test duplicate work", status: "ACTIVE" },
      phase: "test",
      authoritySnapshot: { capturedAt: "2026-09-24T20:00:00.000Z", decisions: [] },
      work: {
        completed: [{ id: "same", summary: "Done" }],
        pending: [{ id: "same", summary: "Still pending" }],
      },
    }),
    /appears in both/,
  );
});

test("checkpoint cannot rewrite authority snapshot", () => {
  const initial = initialCapsule();
  const checkpoint = checkpointRunStateCapsule(initial, {
    updatedAt: "2026-09-24T20:05:00.000Z",
    reason: "CHECKPOINT",
  });

  const rewritten = {
    ...checkpoint,
    authoritySnapshot: {
      ...checkpoint.authoritySnapshot,
      decisions: [authority("browser:interaction", "ALLOW")],
    },
  };

  assert.throws(() => assertRunStatePredecessor(initial, rewritten), /cannot rewrite authority snapshot/);
});
