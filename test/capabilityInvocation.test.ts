import assert from "node:assert/strict";
import test from "node:test";

import {
  assessCapabilityInvocationResume,
  authorizeCapabilityInvocation,
  completeCapabilityInvocation,
  createCapabilityInvocation,
  createCapabilityInvocationProgressReceipt,
  failCapabilityInvocation,
  parseCapabilityInvocation,
  requestCapabilityInvocationCancellation,
  serializeCapabilityInvocation,
  startCapabilityInvocation,
  validateCapabilityInvocationEnvelope,
} from "../src/capabilityInvocation.js";
import type { CapabilityManifest, CapabilityPolicyLayer } from "../src/capabilityPolicy.js";

const manifest: CapabilityManifest = {
  schemaVersion: "toadaid.capability-manifest.v1",
  capabilities: [{ id: "review:inspect", description: "inspect", defaultDecision: "BLOCK" }],
};
const layers = (decision: "ALLOW" | "BLOCK" = "ALLOW"): readonly CapabilityPolicyLayer[] => [{
  scope: "agent",
  subject: "frog",
  decisions: { "review:inspect": decision },
}];
const policy = (decision: "ALLOW" | "BLOCK" = "ALLOW") => ({ manifest, policyLayers: layers(decision) });
const at = (value: string) => ({ now: () => new Date(value) });
const H = "a".repeat(64);
const R = "b".repeat(64);
const E = "c".repeat(64);

function requested() {
  return createCapabilityInvocation({
    invocationId: "inv-1",
    runId: "run-1",
    capabilityId: "review:inspect",
    toolName: "ocr.preview",
    externalToolCallId: "call-9",
    intentSha256: H,
    argumentsSha256: R,
    createdAt: "2026-09-25T03:00:00.000Z",
  });
}

test("creates a sealed request without raw arguments", () => {
  const envelope = requested();
  assert.equal(envelope.record.status, "REQUESTED");
  assert.equal(JSON.stringify(envelope).includes("secret argument"), false);
  assert.match(envelope.recordSha256, /^[0-9a-f]{64}$/);
});

test("current ALLOW authorizes and preserves stable invocation identity", () => {
  const authorized = authorizeCapabilityInvocation(requested(), policy(), at("2026-09-25T03:00:01.000Z"));
  assert.equal(authorized.record.status, "AUTHORIZED");
  assert.equal(authorized.record.invocationId, "inv-1");
  assert.equal(authorized.record.authorization?.decision, "ALLOW");
});

test("policy refusal becomes terminal REFUSED evidence", () => {
  const refused = authorizeCapabilityInvocation(requested(), policy("BLOCK"), at("2026-09-25T03:00:01.000Z"));
  assert.equal(refused.record.status, "REFUSED");
  assert.equal(refused.record.authorization?.decision, "BLOCK");
  assert.equal(assessCapabilityInvocationResume(refused, policy()).decision, "TERMINAL");
});

test("revocation between authorization and start refuses start", () => {
  const authorized = authorizeCapabilityInvocation(requested(), policy(), at("2026-09-25T03:00:01.000Z"));
  const refused = startCapabilityInvocation(authorized, "manager-b", policy("BLOCK"), at("2026-09-25T03:00:02.000Z"));
  assert.equal(refused.record.status, "REFUSED");
  assert.equal(refused.record.start, null);
});

test("start rechecks authority and records manager identity", () => {
  const authorized = authorizeCapabilityInvocation(requested(), policy(), at("2026-09-25T03:00:01.000Z"));
  const started = startCapabilityInvocation(authorized, "manager-b", policy(), at("2026-09-25T03:00:02.000Z"));
  assert.equal(started.record.status, "STARTED");
  assert.equal(started.record.start?.managerId, "manager-b");
});

test("progress receipt is bound to exact invocation state", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  const progress = createCapabilityInvocationProgressReceipt(started, 3, "fetching-rules", "manager-b");
  assert.equal(progress.invocationId, "inv-1");
  assert.equal(progress.recordSha256, started.recordSha256);
  assert.equal(progress.sequence, 3);
});

test("cancellation request does not claim the side effect stopped", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  const cancel = requestCapabilityInvocationCancellation(started, "manager-b", "OPERATOR_REQUEST");
  assert.equal(cancel.record.status, "CANCEL_REQUESTED");
  assert.equal(cancel.record.outcome, null);
  assert.equal(assessCapabilityInvocationResume(cancel, policy()).decision, "RECONCILIATION_REQUIRED");
});

test("completion records only result digest and evidence references", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  const completed = completeCapabilityInvocation(started, "manager-a", E, [{ id: "receipt", sha256: H }]);
  assert.equal(completed.record.status, "COMPLETED");
  assert.equal(completed.record.outcome?.kind, "COMPLETED");
  assert.equal(assessCapabilityInvocationResume(completed, policy()).decision, "TERMINAL");
});

test("failure records fingerprint instead of raw error body", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  const failed = failCapabilityInvocation(started, "manager-a", "ProviderTimeout", E);
  assert.equal(failed.record.status, "FAILED");
  assert.equal(failed.record.outcome?.kind, "FAILED");
});

test("authorized resume rechecks current policy", () => {
  const authorized = authorizeCapabilityInvocation(requested(), policy());
  assert.equal(assessCapabilityInvocationResume(authorized, policy()).decision, "READY_TO_START");
  assert.equal(assessCapabilityInvocationResume(authorized, policy("BLOCK")).decision, "BLOCKED_BY_REVOCATION");
});

test("started resume is reconciliation-required rather than blind retry", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  assert.equal(assessCapabilityInvocationResume(started, policy()).decision, "RECONCILIATION_REQUIRED");
});

test("tampering breaks the envelope hash", () => {
  const envelope = requested();
  const tampered = { ...envelope, record: { ...envelope.record, toolName: "evil.tool" } };
  assert.throws(() => validateCapabilityInvocationEnvelope(tampered), /integrity/);
});

test("serialization roundtrip preserves sealed state", () => {
  const started = startCapabilityInvocation(authorizeCapabilityInvocation(requested(), policy()), "manager-a", policy());
  assert.deepEqual(parseCapabilityInvocation(serializeCapabilityInvocation(started)), started);
});
