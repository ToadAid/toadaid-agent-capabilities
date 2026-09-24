import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  assertChildTaskPredecessor,
  createChildTask,
  parseChildTask,
  resolveChildTaskCapabilityAuthority,
  serializeChildTask,
  transitionChildTask,
} from "../src/childTaskLifecycle.js";
import {
  checkpointRunStateCapsule,
  createRunStateCapsule,
  resolveResumeCapabilityAuthority,
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

function parentResumeAuthority(decision: "ALLOW" | "BLOCK" = "ALLOW") {
  const parent = createRunStateCapsule({
    runId: "parent-001",
    createdAt: "2026-09-24T22:00:00.000Z",
    objective: { summary: "Coordinate child research", status: "ACTIVE" },
    phase: "delegate",
    authoritySnapshot: {
      capturedAt: "2026-09-24T22:00:00.000Z",
      decisions: [authority("browser:evidence", "ALLOW")],
    },
  });
  return [resolveResumeCapabilityAuthority(
    "browser:evidence",
    parent,
    [authority("browser:evidence", decision)],
  )];
}

function initialChildRunState() {
  return createRunStateCapsule({
    runId: "child-001",
    createdAt: "2026-09-24T22:00:00.000Z",
    objective: { summary: "Inspect one research target", status: "ACTIVE" },
    phase: "inspect",
    authoritySnapshot: {
      capturedAt: "2026-09-24T22:00:00.000Z",
      decisions: [authority("browser:evidence", "ALLOW")],
    },
  });
}

function initialChild() {
  return createChildTask({
    childTaskId: "child-001",
    parentRunId: "parent-001",
    createdAt: "2026-09-24T22:00:00.000Z",
    delegatedCapabilities: ["browser:evidence"],
    parentAuthority: parentResumeAuthority(),
    runState: initialChildRunState(),
  });
}

test("creates child with bounded delegated authority", () => {
  const child = initialChild();
  assert.equal(child.status, "CREATED");
  assert.equal(child.attempt, 0);
  assert.deepEqual(child.delegatedCapabilities, ["browser:evidence"]);
});

test("parent cannot delegate authority it does not currently hold", () => {
  assert.throws(
    () => createChildTask({
      childTaskId: "child-denied",
      parentRunId: "parent-001",
      createdAt: "2026-09-24T22:00:00.000Z",
      delegatedCapabilities: ["browser:evidence"],
      parentAuthority: parentResumeAuthority("BLOCK"),
      runState: createRunStateCapsule({
        runId: "child-denied",
        createdAt: "2026-09-24T22:00:00.000Z",
        objective: { summary: "Denied child", status: "ACTIVE" },
        phase: "inspect",
        authoritySnapshot: {
          capturedAt: "2026-09-24T22:00:00.000Z",
          decisions: [authority("browser:evidence", "ALLOW")],
        },
      }),
    }),
    /cannot delegate capability not allowed by parent/,
  );
});

test("child run state cannot carry ALLOW outside delegated authority", () => {
  assert.throws(
    () => createChildTask({
      childTaskId: "child-wide",
      parentRunId: "parent-001",
      createdAt: "2026-09-24T22:00:00.000Z",
      delegatedCapabilities: [],
      parentAuthority: parentResumeAuthority(),
      runState: createRunStateCapsule({
        runId: "child-wide",
        createdAt: "2026-09-24T22:00:00.000Z",
        objective: { summary: "Too-wide child", status: "ACTIVE" },
        phase: "inspect",
        authoritySnapshot: {
          capturedAt: "2026-09-24T22:00:00.000Z",
          decisions: [authority("browser:evidence", "ALLOW")],
        },
      }),
    }),
    /outside delegated authority/,
  );
});

test("failed child resumes from contiguous durable state", () => {
  const created = initialChild();
  const startedState = checkpointRunStateCapsule(created.runState, {
    updatedAt: "2026-09-24T22:01:00.000Z",
    reason: "CHECKPOINT",
  });
  const started = transitionChildTask(created, {
    kind: "START",
    updatedAt: "2026-09-24T22:01:00.000Z",
    runState: startedState,
  });

  const failedState = checkpointRunStateCapsule(started.runState, {
    updatedAt: "2026-09-24T22:02:00.000Z",
    reason: "CHECKPOINT",
  });
  const failed = transitionChildTask(started, {
    kind: "FAIL",
    updatedAt: "2026-09-24T22:02:00.000Z",
    runState: failedState,
  });

  const resumedState = checkpointRunStateCapsule(failed.runState, {
    updatedAt: "2026-09-24T22:03:00.000Z",
    reason: "CHECKPOINT",
  });
  const resumed = transitionChildTask(failed, {
    kind: "RESUME",
    updatedAt: "2026-09-24T22:03:00.000Z",
    runState: resumedState,
  });

  assert.equal(failed.status, "FAILED");
  assert.equal(resumed.status, "RUNNING");
  assert.equal(resumed.attempt, 2);
  assert.doesNotThrow(() => assertChildTaskPredecessor(failed, resumed));
});

test("complete is terminal and requires COMPLETE child objective", () => {
  const created = initialChild();
  const started = transitionChildTask(created, {
    kind: "START",
    updatedAt: "2026-09-24T22:01:00.000Z",
    runState: checkpointRunStateCapsule(created.runState, {
      updatedAt: "2026-09-24T22:01:00.000Z",
      reason: "CHECKPOINT",
    }),
  });
  const completeState = checkpointRunStateCapsule(started.runState, {
    updatedAt: "2026-09-24T22:02:00.000Z",
    reason: "CHECKPOINT",
    objective: { summary: "Inspect one research target", status: "COMPLETE" },
  });
  const complete = transitionChildTask(started, {
    kind: "COMPLETE",
    updatedAt: "2026-09-24T22:02:00.000Z",
    runState: completeState,
  });

  assert.equal(complete.status, "COMPLETE");
  assert.throws(
    () => transitionChildTask(complete, {
      kind: "RESUME",
      updatedAt: "2026-09-24T22:03:00.000Z",
      runState: checkpointRunStateCapsule(complete.runState, {
        updatedAt: "2026-09-24T22:03:00.000Z",
        reason: "CHECKPOINT",
      }),
    }),
    /invalid child-task transition/,
  );
});

test("sealed child task detects tampering", () => {
  const serialized = serializeChildTask(initialChild());
  const envelope = JSON.parse(serialized) as { task: { parentRunId: string } };
  envelope.task.parentRunId = "parent-hijacked";
  assert.throws(() => parseChildTask(JSON.stringify(envelope)), /integrity mismatch/);
});

test("child execution authority is delegated parent child intersection", () => {
  const child = initialChild();

  assert.equal(
    resolveChildTaskCapabilityAuthority(
      "browser:evidence",
      child,
      parentResumeAuthority("ALLOW"),
      [authority("browser:evidence", "ALLOW")],
    ).decision,
    "ALLOW",
  );

  assert.equal(
    resolveChildTaskCapabilityAuthority(
      "browser:evidence",
      child,
      parentResumeAuthority("BLOCK"),
      [authority("browser:evidence", "ALLOW")],
    ).reason,
    "BLOCKED_BY_PARENT",
  );

  assert.equal(
    resolveChildTaskCapabilityAuthority(
      "browser:evidence",
      child,
      parentResumeAuthority("ALLOW"),
      [authority("browser:evidence", "BLOCK")],
    ).reason,
    "BLOCKED_BY_CHILD_RUN",
  );

  assert.equal(
    resolveChildTaskCapabilityAuthority(
      "browser:interaction",
      child,
      [],
      [],
    ).reason,
    "NOT_DELEGATED",
  );
});
