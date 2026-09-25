import assert from "node:assert/strict";
import test from "node:test";

import {
  assertBrowserSessionLeaseUsable,
  createBrowserSessionLease,
  normalizeBrowserSessionOrigins,
  parseBrowserSessionLease,
  revokeBrowserSessionLease,
  serializeBrowserSessionLease,
  validateBrowserSessionLeaseEnvelope,
} from "../src/browserSessionLease.js";
import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";

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

const sessionAllow = authority("browser:session");
const persistAllow = authority("browser:session-persist");
const at = (iso: string) => ({ now: () => new Date(iso) });

test("normalizes exact origins and rejects non-http schemes", () => {
  assert.deepEqual(normalizeBrowserSessionOrigins(["https://example.com/a", "https://example.com/b"]), ["https://example.com"]);
  assert.throws(() => normalizeBrowserSessionOrigins(["file:///tmp/a"]), /http/);
});

test("creates an ephemeral owner-bound lease by default", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s1", ownerId: "agent0", allowedOrigins: ["https://example.com/path"] },
    { session: sessionAllow },
    at("2026-09-24T12:00:00Z"),
  );
  assert.equal(envelope.lease.persistence, "EPHEMERAL");
  assert.equal(envelope.lease.stateRef, null);
  assert.deepEqual(envelope.lease.allowedOrigins, ["https://example.com"]);
});

test("persistent lease requires separate persistence authority", () => {
  assert.throws(
    () => createBrowserSessionLease(
      { sessionId: "s2", ownerId: "agent0", allowedOrigins: ["https://example.com"], persistence: "PERSISTENT" },
      { session: sessionAllow },
    ),
    /browser:session-persist/,
  );
  const envelope = createBrowserSessionLease(
    { sessionId: "s2", ownerId: "agent0", allowedOrigins: ["https://example.com"], persistence: "PERSISTENT" },
    { session: sessionAllow, persistence: persistAllow },
  );
  assert.match(envelope.lease.stateRef ?? "", /^browser-session-state:[0-9a-f]{64}$/);
});

test("valid lease cannot self-authorize when current session authority is blocked", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s3", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  assert.throws(
    () => assertBrowserSessionLeaseUsable(envelope, { ownerId: "agent0", url: "https://example.com/x" }, { session: authority("browser:session", "BLOCK") }),
    /not authorized/,
  );
});

test("owner mismatch is refused", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s4", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  assert.throws(
    () => assertBrowserSessionLeaseUsable(envelope, { ownerId: "agent1", url: "https://example.com" }, { session: sessionAllow }),
    /owner mismatch/,
  );
});

test("origin mismatch is refused", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s5", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  assert.throws(
    () => assertBrowserSessionLeaseUsable(envelope, { ownerId: "agent0", url: "https://evil.example" }, { session: sessionAllow }),
    /origin is not authorized/,
  );
});

test("expired lease is refused", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s6", ownerId: "agent0", allowedOrigins: ["https://example.com"], ttlMs: 1_000 },
    { session: sessionAllow },
    at("2026-09-24T12:00:00Z"),
  );
  assert.throws(
    () => assertBrowserSessionLeaseUsable(envelope, { ownerId: "agent0", url: "https://example.com" }, { session: sessionAllow }, at("2026-09-24T12:00:01Z")),
    /expired/,
  );
});

test("tampered lease fails integrity validation", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s7", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  const tampered = { ...envelope, lease: { ...envelope.lease, ownerId: "attacker" } };
  assert.throws(() => validateBrowserSessionLeaseEnvelope(tampered), /integrity/);
});

test("revocation is sticky and prevents later use", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s8", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
    at("2026-09-24T12:00:00Z"),
  );
  const revoked = revokeBrowserSessionLease(envelope, "agent0", { session: sessionAllow }, at("2026-09-24T12:05:00Z"));
  assert.equal(revoked.lease.status, "REVOKED");
  assert.equal(revokeBrowserSessionLease(revoked, "agent0", { session: sessionAllow }).leaseSha256, revoked.leaseSha256);
  assert.throws(
    () => assertBrowserSessionLeaseUsable(revoked, { ownerId: "agent0", url: "https://example.com" }, { session: sessionAllow }),
    /revoked/,
  );
});

test("persistent stateRef is owner/session bound and contains no owner text", () => {
  const a = createBrowserSessionLease(
    { sessionId: "same", ownerId: "agent0", allowedOrigins: ["https://example.com"], persistence: "PERSISTENT" },
    { session: sessionAllow, persistence: persistAllow },
  );
  const b = createBrowserSessionLease(
    { sessionId: "same", ownerId: "agent1", allowedOrigins: ["https://example.com"], persistence: "PERSISTENT" },
    { session: sessionAllow, persistence: persistAllow },
  );
  assert.notEqual(a.lease.stateRef, b.lease.stateRef);
  assert.equal((a.lease.stateRef ?? "").includes("agent0"), false);
});

test("serialization round-trip preserves integrity", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s10", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  assert.deepEqual(parseBrowserSessionLease(serializeBrowserSessionLease(envelope)), envelope);
});

test("use binding persists only origin, never query or fragment", () => {
  const envelope = createBrowserSessionLease(
    { sessionId: "s11", ownerId: "agent0", allowedOrigins: ["https://example.com"] },
    { session: sessionAllow },
  );
  const binding = assertBrowserSessionLeaseUsable(
    envelope,
    { ownerId: "agent0", url: "https://example.com/account?token=secret#x" },
    { session: sessionAllow },
  );
  assert.equal(binding.origin, "https://example.com");
  assert.equal(JSON.stringify(binding).includes("secret"), false);
});
