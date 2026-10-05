import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_CAPABILITY_MANIFEST,
  resolveCapabilityAuthority,
} from "../src/capabilityPolicy.js";
import type {
  CapabilityAuthorityDecision,
  CapabilityPolicyLayer,
} from "../src/capabilityPolicy.js";
import {
  HOST_CONNECTOR_ACTION_CAPABILITIES,
  assertHostConnectorSessionLeasePredecessor,
  assertHostConnectorSessionLeaseUsable,
  createHostConnectorSessionLease,
  narrowHostConnectorSessionLease,
  parseHostConnectorSessionLease,
  revokeHostConnectorSessionLease,
  serializeHostConnectorSessionLease,
  validateHostConnectorSessionLeaseEnvelope,
} from "../src/hostConnectorSessionLease.js";
import type {
  HostConnectorActionCapabilityId,
} from "../src/hostConnectorSessionLeaseTypes.js";

const NOW = "2026-09-26T22:10:00.000Z";
const CONFIG_SHA = "a".repeat(64);

function runtime(at = NOW) {
  return { now: () => new Date(at) };
}

function useRuntime(
  leaseSha256: string,
  at = NOW,
) {
  return {
    now: () => new Date(at),
    resolveCurrentLeaseSha256: () => leaseSha256,
  };
}

function decision(
  capabilityId: string,
  allow = true,
): CapabilityAuthorityDecision {
  const layers: readonly CapabilityPolicyLayer[] = allow
    ? [
        {
          scope: "agent",
          subject: "agent0",
          decisions: { [capabilityId]: "ALLOW" },
        },
      ]
    : [];

  return resolveCapabilityAuthority(
    capabilityId,
    CORE_CAPABILITY_MANIFEST,
    layers,
  );
}

function createLease(
  allowedCapabilities:
    readonly HostConnectorActionCapabilityId[] = [
      "host:filesystem-read",
      "host:filesystem-write",
    ],
) {
  return createHostConnectorSessionLease(
    {
      hostId: "test-host-001",
      sessionId: "host-session-001",
      ownerId: "agent0",
      allowedCapabilities,
      connectionConfigSha256: CONFIG_SHA,
      ttlMs: 60_000,
      createdAt: NOW,
    },
    decision("host:session"),
    runtime(),
  );
}

function use(
  capabilityId: HostConnectorActionCapabilityId,
) {
  return {
    hostId: "test-host-001",
    sessionId: "host-session-001",
    ownerId: "agent0",
    capabilityId,
  } as const;
}

test("P15 installs host session/actions separately and BLOCK by default", () => {
  for (const capabilityId of [
    "host:session",
    ...HOST_CONNECTOR_ACTION_CAPABILITIES,
  ]) {
    const authority = decision(capabilityId, false);
    assert.equal(authority.installed, true);
    assert.equal(authority.decision, "BLOCK");
    assert.equal(authority.reason, "MANIFEST_DEFAULT");
  }
});

test("P15 lease declares maximum scope but never grants action authority", () => {
  const lease = createLease(["host:command-execute"]);

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:command-execute"),
      {
        session: decision("host:session"),
        action: decision("host:command-execute", false),
      },
      useRuntime(lease.leaseSha256),
    ),
    /host connector capability is not authorized: host:command-execute/,
  );
});

test("P15 exact host/session/owner identity and current action authority produce bounded use binding", () => {
  const lease = createLease(["host:filesystem-read"]);

  const binding = assertHostConnectorSessionLeaseUsable(
    lease,
    use("host:filesystem-read"),
    {
      session: decision("host:session"),
      action: decision("host:filesystem-read"),
    },
    useRuntime(lease.leaseSha256),
  );

  assert.equal(binding.hostId, "test-host-001");
  assert.equal(binding.sessionId, "host-session-001");
  assert.equal(binding.ownerId, "agent0");
  assert.equal(binding.capabilityId, "host:filesystem-read");
  assert.equal(binding.leaseSha256, lease.leaseSha256);
  assert.equal(binding.connectionConfigSha256, CONFIG_SHA);

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      {
        ...use("host:filesystem-read"),
        hostId: "other-host",
      },
      {
        session: decision("host:session"),
        action: decision("host:filesystem-read"),
      },
      useRuntime(lease.leaseSha256),
    ),
    /identity mismatch/,
  );
});

test("P15 current P3 ALLOW cannot widen capability scope beyond the lease", () => {
  const lease = createLease(["host:filesystem-read"]);

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:filesystem-write"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-write"),
      },
      useRuntime(lease.leaseSha256),
    ),
    /lease does not permit capability: host:filesystem-write/,
  );
});

test("P15 narrowing removes one permission while unrelated host capability stays usable", () => {
  const lease = createLease([
    "host:filesystem-read",
    "host:filesystem-write",
    "host:tool-invoke",
  ]);

  const narrowed = narrowHostConnectorSessionLease(
    lease,
    {
      ownerId: "agent0",
      allowedCapabilities: [
        "host:filesystem-read",
        "host:tool-invoke",
      ],
      updatedAt: "2026-09-26T22:10:10.000Z",
    },
    decision("host:session"),
    runtime("2026-09-26T22:10:10.000Z"),
  );

  assert.doesNotThrow(
    () => assertHostConnectorSessionLeasePredecessor(
      lease,
      narrowed,
    ),
  );

  assert.doesNotThrow(
    () => assertHostConnectorSessionLeaseUsable(
      narrowed,
      use("host:filesystem-read"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-read"),
      },
      useRuntime(
        narrowed.leaseSha256,
        "2026-09-26T22:10:11.000Z",
      ),
    ),
  );

  assert.doesNotThrow(
    () => assertHostConnectorSessionLeaseUsable(
      narrowed,
      use("host:tool-invoke"),
      {
        session: decision("host:session"),
        action: decision("host:tool-invoke"),
      },
      useRuntime(
        narrowed.leaseSha256,
        "2026-09-26T22:10:11.000Z",
      ),
    ),
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      narrowed,
      use("host:filesystem-write"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-write"),
      },
      useRuntime(
        narrowed.leaseSha256,
        "2026-09-26T22:10:11.000Z",
      ),
    ),
    /lease does not permit capability/,
  );
});

test("P15 narrowing is monotonic and refuses no-op or widening transitions", () => {
  const lease = createLease(["host:filesystem-read"]);

  assert.throws(
    () => narrowHostConnectorSessionLease(
      lease,
      {
        ownerId: "agent0",
        allowedCapabilities: ["host:filesystem-read"],
        updatedAt: "2026-09-26T22:10:10.000Z",
      },
      decision("host:session"),
      runtime("2026-09-26T22:10:10.000Z"),
    ),
    /strictly reduce capability scope/,
  );

  assert.throws(
    () => narrowHostConnectorSessionLease(
      lease,
      {
        ownerId: "agent0",
        allowedCapabilities: [
          "host:filesystem-read",
          "host:command-execute",
        ],
        updatedAt: "2026-09-26T22:10:10.000Z",
      },
      decision("host:session"),
      runtime("2026-09-26T22:10:10.000Z"),
    ),
    /cannot widen capability scope/,
  );
});

test("P15 revocation is predecessor-bound and blocks every host action", () => {
  const lease = createLease([
    "host:filesystem-read",
    "host:connector-use",
  ]);

  const revoked = revokeHostConnectorSessionLease(
    lease,
    {
      ownerId: "agent0",
      revokedAt: "2026-09-26T22:10:10.000Z",
    },
    decision("host:session"),
    runtime("2026-09-26T22:10:10.000Z"),
  );

  assert.equal(revoked.lease.status, "REVOKED");
  assert.deepEqual(revoked.lease.allowedCapabilities, []);
  assert.doesNotThrow(
    () => assertHostConnectorSessionLeasePredecessor(
      lease,
      revoked,
    ),
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      revoked,
      use("host:filesystem-read"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-read"),
      },
      useRuntime(
        revoked.leaseSha256,
        "2026-09-26T22:10:11.000Z",
      ),
    ),
    /lease is revoked/,
  );
});

test("P15 expiry and host-session revocation fail current use closed", () => {
  const lease = createLease(["host:tool-invoke"]);

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:tool-invoke"),
      {
        session: decision("host:session"),
        action: decision("host:tool-invoke"),
      },
      useRuntime(
        lease.leaseSha256,
        "2026-09-26T22:11:00.000Z",
      ),
    ),
    /lease is expired/,
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:tool-invoke"),
      {
        session: decision("host:session", false),
        action: decision("host:tool-invoke"),
      },
      useRuntime(lease.leaseSha256),
    ),
    /host connector capability is not authorized: host:session/,
  );
});

test("P15 persistent connection configuration remains provenance, never permission", () => {
  const lease = createLease(["host:connector-use"]);
  assert.equal(
    lease.lease.connectionConfigSha256,
    CONFIG_SHA,
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:connector-use"),
      {
        session: decision("host:session"),
        action: decision("host:connector-use", false),
      },
      useRuntime(lease.leaseSha256),
    ),
    /host connector capability is not authorized: host:connector-use/,
  );
});

test("P15 stale predecessor leases fail after narrowing or revocation", () => {
  const original = createLease([
    "host:filesystem-read",
    "host:filesystem-write",
  ]);

  const narrowed = narrowHostConnectorSessionLease(
    original,
    {
      ownerId: "agent0",
      allowedCapabilities: ["host:filesystem-read"],
      updatedAt: "2026-09-26T22:10:10.000Z",
    },
    decision("host:session"),
    runtime("2026-09-26T22:10:10.000Z"),
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      original,
      use("host:filesystem-write"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-write"),
      },
      useRuntime(
        narrowed.leaseSha256,
        "2026-09-26T22:10:11.000Z",
      ),
    ),
    /lease is stale/,
  );

  const revoked = revokeHostConnectorSessionLease(
    narrowed,
    {
      ownerId: "agent0",
      revokedAt: "2026-09-26T22:10:20.000Z",
    },
    decision("host:session"),
    runtime("2026-09-26T22:10:20.000Z"),
  );

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      narrowed,
      use("host:filesystem-read"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-read"),
      },
      useRuntime(
        revoked.leaseSha256,
        "2026-09-26T22:10:21.000Z",
      ),
    ),
    /lease is stale/,
  );
});

test("P15 use fails closed when current lease truth is unavailable", () => {
  const lease = createLease(["host:filesystem-read"]);

  assert.throws(
    () => assertHostConnectorSessionLeaseUsable(
      lease,
      use("host:filesystem-read"),
      {
        session: decision("host:session"),
        action: decision("host:filesystem-read"),
      },
      {
        now: () => new Date(NOW),
        resolveCurrentLeaseSha256: () => null,
      },
    ),
    /current lease is unavailable/,
  );
});

test("P15 serialization is canonicalized and tampering fails closed", () => {
  const lease = createLease(["host:filesystem-read"]);
  const parsed = parseHostConnectorSessionLease(
    JSON.stringify({
      ...JSON.parse(
        serializeHostConnectorSessionLease(lease),
      ),
      ambientAuthority: {
        "host:command-execute": "ALLOW",
      },
    }),
  );

  assert.equal("ambientAuthority" in parsed, false);
  assert.deepEqual(parsed, lease);

  const tampered = {
    ...lease,
    lease: {
      ...lease.lease,
      allowedCapabilities: [
        "host:filesystem-read",
        "host:command-execute",
      ] as const,
    },
  };

  assert.throws(
    () => validateHostConnectorSessionLeaseEnvelope(tampered),
    /integrity mismatch/,
  );
});
