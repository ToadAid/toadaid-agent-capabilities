import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  assertSecretLeasePredecessor,
  assertSecretMaterializationGrantUsable,
  createSecretLease,
  createSecretMaterializationGrant,
  parseSecretLease,
  parseSecretMaterializationGrant,
  resolveSecretFileProjectionPath,
  revokeSecretLease,
  serializeSecretLease,
  serializeSecretMaterializationGrant,
  validateSecretLeaseEnvelope,
  validateSecretMaterializationGrantEnvelope,
} from "../src/secretLease.js";

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

const leaseAllow = authority("secret:lease");
const materializeAllow = authority("secret:materialize");
const consumerAllow = authority("github:read");
const at = (iso: string) => ({ now: () => new Date(iso) });
const handle = `secret-ref:${"a".repeat(64)}`;

function baseLease() {
  return createSecretLease(
    {
      leaseId: "lease-1",
      ownerId: "agent0",
      providerId: "github",
      profileId: "readonly",
      secretHandle: handle,
      allowedCapabilities: ["github:read"],
      allowedTargets: [
        { kind: "ENV", name: "GITHUB_TOKEN" },
        { kind: "FILE", relativePath: "github/token.txt", mode: 384 },
      ],
      createdAt: "2026-09-25T01:00:00.000Z",
      ttlMs: 60_000,
    },
    leaseAllow,
  );
}

function grant(lease = baseLease()) {
  return createSecretMaterializationGrant(
    lease,
    {
      materializationId: "mat-1",
      ownerId: "agent0",
      providerId: "github",
      profileId: "readonly",
      forCapabilityId: "github:read",
      target: { kind: "ENV", name: "GITHUB_TOKEN" },
      issuedAt: "2026-09-25T01:00:10.000Z",
      ttlMs: 30_000,
    },
    { materialize: materializeAllow, consumer: consumerAllow },
    at("2026-09-25T01:00:10.000Z"),
  );
}

test("creates an opaque scoped lease without secret bytes", () => {
  const lease = baseLease().lease;
  assert.equal(lease.secretHandle, handle);
  assert.deepEqual(lease.allowedCapabilities, ["github:read"]);
  assert.equal(JSON.stringify(lease).includes("ghp_"), false);
  assert.equal(lease.status, "ACTIVE");
});

test("lease creation requires secret:lease authority", () => {
  assert.throws(() => createSecretLease({
    ownerId: "agent0", providerId: "github", profileId: "readonly", secretHandle: handle,
    allowedCapabilities: ["github:read"], allowedTargets: [{ kind: "ENV", name: "GITHUB_TOKEN" }],
    createdAt: "2026-09-25T01:00:00.000Z",
  }, authority("secret:lease", "BLOCK")), /not authorized/);
});

test("materialization requires separate secret:materialize authority", () => {
  assert.throws(() => createSecretMaterializationGrant(baseLease(), {
    ownerId: "agent0", providerId: "github", profileId: "readonly", forCapabilityId: "github:read",
    target: { kind: "ENV", name: "GITHUB_TOKEN" }, issuedAt: "2026-09-25T01:00:10.000Z",
  }, { materialize: authority("secret:materialize", "BLOCK"), consumer: consumerAllow }, at("2026-09-25T01:00:10.000Z")), /secret:materialize/);
});

test("materialization requires the consumer capability to still be allowed", () => {
  assert.throws(() => createSecretMaterializationGrant(baseLease(), {
    ownerId: "agent0", providerId: "github", profileId: "readonly", forCapabilityId: "github:read",
    target: { kind: "ENV", name: "GITHUB_TOKEN" }, issuedAt: "2026-09-25T01:00:10.000Z",
  }, { materialize: materializeAllow, consumer: authority("github:read", "BLOCK") }, at("2026-09-25T01:00:10.000Z")), /consumer capability/);
});

test("lease cannot widen to another consumer capability", () => {
  assert.throws(() => createSecretMaterializationGrant(baseLease(), {
    ownerId: "agent0", providerId: "github", profileId: "readonly", forCapabilityId: "github:write",
    target: { kind: "ENV", name: "GITHUB_TOKEN" }, issuedAt: "2026-09-25T01:00:10.000Z",
  }, { materialize: materializeAllow, consumer: authority("github:write") }, at("2026-09-25T01:00:10.000Z")), /does not allow capability/);
});

test("owner provider and profile bindings are exact", () => {
  for (const request of [
    { ownerId: "agent1", providerId: "github", profileId: "readonly" },
    { ownerId: "agent0", providerId: "gitlab", profileId: "readonly" },
    { ownerId: "agent0", providerId: "github", profileId: "writer" },
  ]) {
    assert.throws(() => createSecretMaterializationGrant(baseLease(), {
      ...request, forCapabilityId: "github:read", target: { kind: "ENV", name: "GITHUB_TOKEN" },
      issuedAt: "2026-09-25T01:00:10.000Z",
    }, { materialize: materializeAllow, consumer: consumerAllow }, at("2026-09-25T01:00:10.000Z")), /mismatch/);
  }
});

test("file projection refuses traversal and resolves under the runtime root", () => {
  assert.throws(() => createSecretLease({
    ownerId: "agent0", providerId: "github", profileId: "readonly", secretHandle: handle,
    allowedCapabilities: ["github:read"], allowedTargets: [{ kind: "FILE", relativePath: "../token", mode: 384 }],
    createdAt: "2026-09-25T01:00:00.000Z",
  }, leaseAllow), /unsafe|relative/);
  assert.equal(resolveSecretFileProjectionPath("/tmp/toadaid-secrets", { kind: "FILE", relativePath: "github/token.txt", mode: 384 }), "/tmp/toadaid-secrets/github/token.txt");
});

test("expired lease refuses materialization", () => {
  assert.throws(() => createSecretMaterializationGrant(baseLease(), {
    ownerId: "agent0", providerId: "github", profileId: "readonly", forCapabilityId: "github:read",
    target: { kind: "ENV", name: "GITHUB_TOKEN" }, issuedAt: "2026-09-25T01:01:01.000Z",
  }, { materialize: materializeAllow, consumer: consumerAllow }, at("2026-09-25T01:01:01.000Z")), /expired/);
});

test("revocation is sticky and requires no authority to narrow access", () => {
  const active = baseLease();
  const revoked = revokeSecretLease(active, "operator", "2026-09-25T01:00:20.000Z");
  assert.equal(revoked.lease.status, "REVOKED");
  assert.doesNotThrow(() => assertSecretLeasePredecessor(active, revoked));
  assert.equal(revokeSecretLease(revoked, "operator", "2026-09-25T01:00:30.000Z").leaseSha256, revoked.leaseSha256);
  assert.throws(() => assertSecretMaterializationGrantUsable(grant(active), revoked, { materialize: materializeAllow, consumer: consumerAllow }, at("2026-09-25T01:00:21.000Z")), /revoked|not bound/);
});

test("materialization grant is short-lived and contains only the opaque handle", () => {
  const envelope = grant();
  assert.equal(envelope.grant.secretHandle, handle);
  assert.equal(Date.parse(envelope.grant.expiresAt) - Date.parse(envelope.grant.issuedAt), 30_000);
  assert.equal(JSON.stringify(envelope).includes("actual-secret"), false);
});

test("tampered lease and grant envelopes fail integrity validation", () => {
  const lease = baseLease();
  assert.throws(() => validateSecretLeaseEnvelope({ ...lease, lease: { ...lease.lease, ownerId: "agent1" } }), /integrity/);
  const materialization = grant();
  assert.throws(() => validateSecretMaterializationGrantEnvelope({ ...materialization, grant: { ...materialization.grant, profileId: "writer" } }), /integrity/);
});

test("grant use rechecks current materialization and consumer authority", () => {
  const lease = baseLease();
  const envelope = grant(lease);
  assert.throws(() => assertSecretMaterializationGrantUsable(envelope, lease, {
    materialize: authority("secret:materialize", "BLOCK"), consumer: consumerAllow,
  }, at("2026-09-25T01:00:20.000Z")), /secret:materialize/);
  assert.throws(() => assertSecretMaterializationGrantUsable(envelope, lease, {
    materialize: materializeAllow, consumer: authority("github:read", "BLOCK"),
  }, at("2026-09-25T01:00:20.000Z")), /consumer capability/);
});

test("lease and grant serialization round-trip without materializing a secret", () => {
  const lease = baseLease();
  assert.deepEqual(parseSecretLease(serializeSecretLease(lease)), lease);
  const materialization = grant(lease);
  assert.deepEqual(parseSecretMaterializationGrant(serializeSecretMaterializationGrant(materialization)), materialization);
});
