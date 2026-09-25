import assert from "node:assert/strict";
import test from "node:test";

import {
  createHumanInterrupt,
  createHumanInterruptResumeProof,
  parseHumanInterrupt,
  resolveHumanInterrupt,
  serializeHumanInterrupt,
  validateHumanInterruptEnvelope,
  validateHumanInterruptResponse,
} from "../src/humanInterrupt.js";
import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import type { RunStateCapsule } from "../src/runStateCapsule.js";

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

function runState(revision = 3): RunStateCapsule {
  return {
    schemaVersion: "toadaid.run-state-capsule.v1",
    runId: "run-1",
    revision,
    createdAt: "2026-09-24T20:00:00.000Z",
    updatedAt: "2026-09-24T20:01:00.000Z",
    objective: { summary: "Deploy safely", status: "BLOCKED" },
    phase: "human-decision",
    authoritySnapshot: { capturedAt: "2026-09-24T20:01:00.000Z", decisions: [] },
    evidenceRefs: [],
    artifactRefs: [],
    work: { completed: [], pending: [], blocked: [] },
    continuity: { generation: 3, reason: "MANUAL", previousCapsuleSha256: null },
  };
}

const decisionSchema = {
  type: "object" as const,
  properties: {
    decision: { type: "string" as const, enum: ["approve", "reject"] },
    note: { type: "string" as const, maxLength: 200 },
  },
  required: ["decision"],
  additionalProperties: false as const,
};

function createOpen() {
  return createHumanInterrupt(
    {
      interruptId: "int-1",
      createdAt: "2026-09-24T20:02:00.000Z",
      reason: "DECISION_REQUIRED",
      prompt: "Deploy?",
      responseSchema: decisionSchema,
    },
    runState(),
    authority("interrupt:create"),
  );
}

test("creates an OPEN interrupt bound to the exact P4 run state", () => {
  const envelope = createOpen();
  assert.equal(envelope.record.status, "OPEN");
  assert.equal(envelope.record.revision, 0);
  assert.equal(envelope.record.runBinding.runId, "run-1");
  assert.equal(envelope.record.runBinding.runRevision, 3);
  assert.equal(envelope.record.resolution, null);
});

test("interrupt creation requires current interrupt:create authority", () => {
  assert.throws(
    () => createHumanInterrupt(
      {
        interruptId: "int-blocked",
        createdAt: "2026-09-24T20:02:00.000Z",
        reason: "MANUAL",
        prompt: "Need help",
        responseSchema: { type: "boolean" },
      },
      runState(),
      authority("interrupt:create", "BLOCK"),
    ),
    /not authorized/,
  );
});

test("typed response schema rejects undeclared properties", () => {
  assert.throws(
    () => validateHumanInterruptResponse({ decision: "approve", extra: true }, decisionSchema),
    /undeclared property/,
  );
});

test("typed response schema enforces enum and integer bounds", () => {
  assert.throws(() => validateHumanInterruptResponse("maybe", { type: "string", enum: ["yes", "no"] }), /allowed enum/);
  assert.throws(() => validateHumanInterruptResponse(11, { type: "integer", minimum: 0, maximum: 10 }), /maximum/);
  assert.equal(validateHumanInterruptResponse(7, { type: "integer", minimum: 0, maximum: 10 }), 7);
});

test("resolution requires current interrupt:resolve authority", () => {
  assert.throws(
    () => resolveHumanInterrupt(
      createOpen(),
      { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve" } },
      runState(),
      authority("interrupt:resolve", "BLOCK"),
    ),
    /not authorized/,
  );
});

test("resolution refuses a different run revision even with valid authority", () => {
  assert.throws(
    () => resolveHumanInterrupt(
      createOpen(),
      { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve" } },
      runState(4),
      authority("interrupt:resolve"),
    ),
    /binding mismatch/,
  );
});

test("resolution is predecessor-bound and transitions OPEN to RESOLVED once", () => {
  const open = createOpen();
  const resolved = resolveHumanInterrupt(
    open,
    { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve", note: "ship" } },
    runState(),
    authority("interrupt:resolve"),
  );
  assert.equal(resolved.record.status, "RESOLVED");
  assert.equal(resolved.record.revision, 1);
  assert.equal(resolved.record.continuity.previousRecordSha256, open.recordSha256);
  assert.throws(
    () => resolveHumanInterrupt(
      resolved,
      { responderId: "tommy", resolvedAt: "2026-09-24T20:04:00.000Z", response: { decision: "reject" } },
      runState(),
      authority("interrupt:resolve"),
    ),
    /already resolved/,
  );
});

test("resolution rejects responses that do not satisfy the saved schema", () => {
  assert.throws(
    () => resolveHumanInterrupt(
      createOpen(),
      { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "maybe" } },
      runState(),
      authority("interrupt:resolve"),
    ),
    /allowed enum/,
  );
});

test("tampered resolved response fails record integrity", () => {
  const resolved = resolveHumanInterrupt(
    createOpen(),
    { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve" } },
    runState(),
    authority("interrupt:resolve"),
  );
  const tampered = JSON.parse(serializeHumanInterrupt(resolved)) as {
    record: { resolution: { response: { decision: string } } };
  };
  tampered.record.resolution.response.decision = "reject";
  assert.throws(() => parseHumanInterrupt(JSON.stringify(tampered)), /integrity mismatch/);
});

test("resume proof requires a resolved interrupt and exact unchanged bound run", () => {
  const open = createOpen();
  assert.throws(
    () => createHumanInterruptResumeProof(open, runState(), "2026-09-24T20:04:00.000Z"),
    /must be resolved/,
  );
  const resolved = resolveHumanInterrupt(
    open,
    { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve" } },
    runState(),
    authority("interrupt:resolve"),
  );
  const proof = createHumanInterruptResumeProof(resolved, runState(), "2026-09-24T20:04:00.000Z");
  assert.equal(proof.interruptRecordSha256, resolved.recordSha256);
  assert.equal(proof.responderId, "tommy");
  assert.throws(
    () => createHumanInterruptResumeProof(resolved, runState(4), "2026-09-24T20:04:00.000Z"),
    /binding mismatch/,
  );
});

test("saved human response never contains or modifies capability authority", () => {
  const resolved = resolveHumanInterrupt(
    createOpen(),
    { responderId: "tommy", resolvedAt: "2026-09-24T20:03:00.000Z", response: { decision: "approve" } },
    runState(),
    authority("interrupt:resolve"),
  );
  const serialized = serializeHumanInterrupt(resolved);
  assert.equal(serialized.includes("authoritySnapshot"), false);
  assert.equal(serialized.includes("AUTHORIZED_BY_POLICY"), false);
});

test("serialization round-trip preserves a sealed interrupt exactly", () => {
  const open = createOpen();
  const serialized = serializeHumanInterrupt(open);
  const parsed = parseHumanInterrupt(serialized);
  assert.deepEqual(parsed, open);
  assert.deepEqual(validateHumanInterruptEnvelope(parsed), open);
});
