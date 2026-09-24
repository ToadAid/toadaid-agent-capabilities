import assert from "node:assert/strict";
import test from "node:test";

import {
  assertCapabilityAllowed,
  CapabilityAuthorizationError,
  CORE_CAPABILITY_MANIFEST,
  createCapabilityManifest,
  resolveCapabilityAuthority,
  validateCapabilityPolicyChain,
} from "../src/capabilityPolicy.js";

const allowEvidence = {
  scope: "agent" as const,
  subject: "agent0",
  decisions: { "browser:evidence": "ALLOW" as const },
};

test("installed capabilities are blocked by default", () => {
  const decision = resolveCapabilityAuthority(
    "browser:evidence",
    CORE_CAPABILITY_MANIFEST,
    [],
  );

  assert.equal(decision.installed, true);
  assert.equal(decision.decision, "BLOCK");
  assert.equal(decision.reason, "MANIFEST_DEFAULT");
});

test("explicit allow grants an installed capability", () => {
  const decision = resolveCapabilityAuthority(
    "browser:evidence",
    CORE_CAPABILITY_MANIFEST,
    [allowEvidence],
  );

  assert.equal(decision.decision, "ALLOW");
  assert.equal(decision.reason, "AUTHORIZED_BY_POLICY");
});

test("explicit block is sticky across downstream policy layers", () => {
  const decision = resolveCapabilityAuthority(
    "browser:interaction",
    CORE_CAPABILITY_MANIFEST,
    [
      {
        scope: "agent",
        subject: "agent0",
        decisions: { "browser:interaction": "ALLOW" },
      },
      {
        scope: "project",
        subject: "trading-desk",
        decisions: { "browser:interaction": "BLOCK" },
      },
      {
        scope: "session",
        subject: "session-1",
        decisions: { "browser:interaction": "ALLOW" },
      },
    ],
  );

  assert.equal(decision.decision, "BLOCK");
  assert.equal(decision.reason, "BLOCKED_BY_POLICY");
  assert.equal(decision.trace.at(-1)?.stickyBlock, true);
});

test("DEFAULT inherits without widening authority", () => {
  const decision = resolveCapabilityAuthority(
    "browser:evidence",
    CORE_CAPABILITY_MANIFEST,
    [
      allowEvidence,
      {
        scope: "project",
        subject: "trading-desk",
        decisions: { "browser:evidence": "DEFAULT" },
      },
    ],
  );

  assert.equal(decision.decision, "ALLOW");
});

test("unknown capability ids fail closed", () => {
  const decision = resolveCapabilityAuthority(
    "wallet:sign",
    CORE_CAPABILITY_MANIFEST,
    [],
  );

  assert.equal(decision.installed, false);
  assert.equal(decision.decision, "BLOCK");
  assert.equal(decision.reason, "UNKNOWN_CAPABILITY");
});

test("policy rejects stale or typo capability ids", () => {
  assert.throws(
    () => validateCapabilityPolicyChain(CORE_CAPABILITY_MANIFEST, [
      {
        scope: "agent",
        subject: "agent0",
        decisions: { "browser:interactoin": "ALLOW" },
      },
    ]),
    /not installed/,
  );
});

test("manifest rejects duplicate capability ids", () => {
  assert.throws(
    () => createCapabilityManifest([
      { id: "browser:evidence", description: "one", defaultDecision: "BLOCK" },
      { id: "browser:evidence", description: "two", defaultDecision: "BLOCK" },
    ]),
    /duplicate capability id/,
  );
});

test("assertCapabilityAllowed returns authority or throws typed refusal", () => {
  assert.equal(
    assertCapabilityAllowed("browser:evidence", CORE_CAPABILITY_MANIFEST, [allowEvidence]).decision,
    "ALLOW",
  );

  assert.throws(
    () => assertCapabilityAllowed("browser:interaction", CORE_CAPABILITY_MANIFEST, []),
    (error: unknown) => {
      if (!(error instanceof CapabilityAuthorizationError)) {
        return false;
      }
      assert.equal(error.authority.decision, "BLOCK");
      return true;
    },
  );
});
