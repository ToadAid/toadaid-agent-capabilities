import assert from "node:assert/strict";
import test from "node:test";

import type {
  CapabilityAuthorityDecision,
} from "../src/capabilityPolicy.js";
import {
  createBrowserSessionLease,
  revokeBrowserSessionLease,
} from "../src/browserSessionLease.js";
import {
  finalizeReusableBrowserRequest,
  prepareReusableBrowserRequest,
  validateReusableBrowserPoolCandidate,
} from "../src/browserSessionReuse.js";
import type {
  ReusableBrowserRuntimeAdapter,
} from "../src/browserSessionReuseTypes.js";

const NOW = "2026-09-26T06:20:00.000Z";

function decision(
  capabilityId: string,
  value: "ALLOW" | "BLOCK" = "ALLOW",
): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: value,
    reason: value === "ALLOW" ? "AUTHORIZED_BY_POLICY" : "BLOCKED_BY_POLICY",
    trace: [],
  };
}

function authority(persistent = false) {
  return {
    session: decision("browser:session"),
    ...(persistent
      ? { persistence: decision("browser:session-persist") }
      : {}),
  };
}

function runtime(at = NOW) {
  return { now: () => new Date(at) };
}

function lease(persistent: boolean) {
  return createBrowserSessionLease(
    {
      sessionId: persistent ? "persistent-session" : "ephemeral-session",
      ownerId: "agent0",
      allowedOrigins: [
        "https://example.com",
        "https://cdn.example.com",
      ],
      ttlMs: 60_000,
      persistence: persistent ? "PERSISTENT" : "EPHEMERAL",
    },
    authority(persistent),
    runtime(),
  );
}

function adapter(options: { mismatchApply?: boolean } = {}) {
  const calls: Array<Record<string, unknown>> = [];
  const claimedCandidates = new Set<string>();

  const value: ReusableBrowserRuntimeAdapter = {
    async claimPoolCandidate(input) {
      calls.push({
        kind: "claim",
        identity: input.identity,
        candidateSha256: input.candidateSha256,
      });
      if (claimedCandidates.has(input.candidateSha256)) {
        return {
          schemaVersion:
            "toadaid.reusable-browser-candidate-claim-receipt.v1",
          candidateSha256: input.candidateSha256,
          disposition: "ALREADY_CLAIMED",
        };
      }
      claimedCandidates.add(input.candidateSha256);
      return {
        schemaVersion:
          "toadaid.reusable-browser-candidate-claim-receipt.v1",
        candidateSha256: input.candidateSha256,
        disposition: "CLAIMED",
      };
    },
    async resetRequestState(identity) {
      calls.push({ kind: "reset", identity });
      return {
        schemaVersion: "toadaid.reusable-browser-reset-receipt.v1",
        resetComplete: true,
      };
    },
    async applyRequestState(input) {
      calls.push({
        kind: "apply",
        identity: input.identity,
        settings: input.settings,
        settingsSha256: input.settingsSha256,
      });
      return {
        schemaVersion: "toadaid.reusable-browser-policy-apply-receipt.v1",
        appliedSettingsSha256: options.mismatchApply
          ? "f".repeat(64)
          : input.settingsSha256,
      };
    },
    async quarantineAndEvict(input) {
      calls.push({
        kind: "quarantine",
        identity: input.identity,
        reason: input.reason,
      });
    },
    async disposeOneShot(input) {
      calls.push({
        kind: "dispose",
        identity: input.identity,
        reason: input.reason,
      });
    },
  };

  return { value, calls };
}

function use() {
  return {
    ownerId: "agent0",
    url: "https://example.com/account?token=ignored",
  };
}

test("P9B one-shot anonymous always resets/applies policy and disposes", async () => {
  const session = lease(false);
  const fake = adapter();

  const prepared = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(false),
      mode: "ONE_SHOT_ANONYMOUS",
      policy: {
        timeoutMs: 12_000,
        headers: { "X-Trace": "one-shot" },
        allowedResourceOrigins: ["https://cdn.example.com"],
        allowedResourceTypes: ["document", "image", "fetch"],
      },
    },
    fake.value,
    runtime(),
  );

  assert.equal(prepared.checkout, "FRESH");
  assert.equal(prepared.reuseKey, null);
  assert.deepEqual(fake.calls.map((entry) => entry.kind), [
    "reset",
    "apply",
  ]);

  const applied = fake.calls[1]!;
  const settings = applied.settings as {
    timeoutMs: number;
    headers: readonly { name: string; value: string }[];
    allowedTopLevelOrigins: readonly string[];
    allowedResourceOrigins: readonly string[];
  };
  assert.equal(settings.timeoutMs, 12_000);
  assert.deepEqual(settings.headers, [
    { name: "x-trace", value: "one-shot" },
  ]);
  assert.deepEqual(settings.allowedTopLevelOrigins, [
    "https://example.com",
  ]);
  assert.deepEqual(settings.allowedResourceOrigins, [
    "https://cdn.example.com",
    "https://example.com",
  ]);

  const final = await finalizeReusableBrowserRequest(
    {
      preparation: prepared,
      lease: session,
      use: use(),
      authority: authority(false),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );

  assert.equal(final.disposition, "DISPOSE");
  assert.equal(final.reason, "ONE_SHOT_COMPLETE");
  assert.equal(final.candidate, null);
  assert.equal(fake.calls.at(-1)?.kind, "dispose");
});

test("P9B persistent checkout revalidates P8 and reapplies changed policy on reuse", async () => {
  const session = lease(true);
  const fake = adapter();

  const first = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
      policy: {
        timeoutMs: 10_000,
        headers: { "X-Request": "first" },
      },
    },
    fake.value,
    runtime(),
  );

  const finalized = await finalizeReusableBrowserRequest(
    {
      preparation: first,
      lease: session,
      use: use(),
      authority: authority(true),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );
  assert.equal(finalized.disposition, "RETURN_TO_POOL");
  assert.ok(finalized.candidate);

  const second = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
      candidate: finalized.candidate!,
      policy: {
        timeoutMs: 20_000,
        headers: { "X-Request": "second" },
      },
    },
    fake.value,
    runtime("2026-09-26T06:20:02.000Z"),
  );

  assert.equal(second.checkout, "REUSED");
  assert.notEqual(second.settingsSha256, first.settingsSha256);

  const applies = fake.calls.filter((entry) => entry.kind === "apply");
  assert.equal(applies.length, 2);
  const secondSettings = applies[1]!.settings as {
    timeoutMs: number;
    headers: readonly { name: string; value: string }[];
  };
  assert.equal(secondSettings.timeoutMs, 20_000);
  assert.deepEqual(secondSettings.headers, [
    { name: "x-request", value: "second" },
  ]);
});

test("P9B reusable candidate is atomically single-claim", async () => {
  const session = lease(true);
  const fake = adapter();

  const first = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
    },
    fake.value,
    runtime(),
  );
  const finalized = await finalizeReusableBrowserRequest(
    {
      preparation: first,
      lease: session,
      use: use(),
      authority: authority(true),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );
  const candidate = finalized.candidate!;

  const reused = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
      candidate,
    },
    fake.value,
    runtime("2026-09-26T06:20:02.000Z"),
  );
  assert.equal(reused.checkout, "REUSED");
  assert.equal(reused.sourceCandidateSha256, candidate.candidateSha256);

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        candidate,
      },
      fake.value,
      runtime("2026-09-26T06:20:03.000Z"),
    ),
    /already claimed/,
  );

  const claimCalls = fake.calls.filter((entry) => entry.kind === "claim");
  assert.equal(claimCalls.length, 2);
  assert.notEqual(fake.calls.at(-1)?.kind, "quarantine");
});

test("P9B persistent pool candidates are exact-origin scoped", async () => {
  const session = lease(true);
  const fake = adapter();

  const prepared = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
    },
    fake.value,
    runtime(),
  );
  const finalized = await finalizeReusableBrowserRequest(
    {
      preparation: prepared,
      lease: session,
      use: use(),
      authority: authority(true),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );

  assert.equal(finalized.candidate!.origin, "https://example.com");

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: {
          ownerId: "agent0",
          url: "https://cdn.example.com/resource",
        },
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        candidate: finalized.candidate!,
      },
      fake.value,
      runtime("2026-09-26T06:20:02.000Z"),
    ),
    /does not match current P8 session/,
  );
});

test("P9B v1 refuses private-network widening without separate authority", async () => {
  const session = lease(true);
  const fake = adapter();

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        policy: {
          allowPrivateNetwork: true,
        },
      },
      fake.value,
      runtime(),
    ),
    /does not grant private-network authority/,
  );

  assert.equal(fake.calls.length, 0);
});

test("P9B refuses sensitive headers instead of smuggling secret authority", async () => {
  const session = lease(true);
  const fake = adapter();

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        policy: {
          headers: { Authorization: "Bearer secret" },
        },
      },
      fake.value,
      runtime(),
    ),
    /forbids sensitive\/runtime header: authorization/,
  );

  assert.equal(fake.calls.length, 0);
});

test("P9B resource policy cannot widen beyond exact P8 lease origins", async () => {
  const session = lease(true);
  const fake = adapter();

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        policy: {
          allowedResourceOrigins: ["https://evil.example"],
        },
      },
      fake.value,
      runtime(),
    ),
    /outside P8 lease authority/,
  );

  assert.equal(fake.calls.length, 0);
});

test("P9B one-shot and persistent session modes cannot cross", async () => {
  const persistent = lease(true);
  const ephemeral = lease(false);
  const fake = adapter();

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: persistent,
        use: use(),
        authority: authority(true),
        mode: "ONE_SHOT_ANONYMOUS",
      },
      fake.value,
      runtime(),
    ),
    /requires an EPHEMERAL P8 browser session/,
  );

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: ephemeral,
        use: use(),
        authority: authority(false),
        mode: "PERSISTENT_AUTHENTICATED",
      },
      fake.value,
      runtime(),
    ),
    /requires a PERSISTENT P8 browser session/,
  );
});

test("P9B runtime policy mismatch quarantines persistent page before refusal", async () => {
  const session = lease(true);
  const fake = adapter({ mismatchApply: true });

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
      },
      fake.value,
      runtime(),
    ),
    /did not apply the exact request settings/,
  );

  assert.deepEqual(fake.calls.map((entry) => entry.kind), [
    "reset",
    "apply",
    "quarantine",
  ]);
});

test("P9B execution errors and poisoned pages are quarantined, never pooled", async () => {
  const session = lease(true);

  for (const outcome of [
    { status: "ERROR", pageHealth: "HEALTHY" },
    { status: "SUCCESS", pageHealth: "POISONED" },
  ] as const) {
    const fake = adapter();
    const prepared = await prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
      },
      fake.value,
      runtime(),
    );

    const final = await finalizeReusableBrowserRequest(
      {
        preparation: prepared,
        lease: session,
        use: use(),
        authority: authority(true),
        outcome,
      },
      fake.value,
      runtime("2026-09-26T06:20:01.000Z"),
    );

    assert.equal(final.disposition, "QUARANTINE_EVICT");
    assert.equal(final.candidate, null);
    assert.equal(fake.calls.at(-1)?.kind, "quarantine");
  }
});

test("P9B pool return rechecks current P8 authority and lease truth", async () => {
  const session = lease(true);
  const fake = adapter();

  const prepared = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
    },
    fake.value,
    runtime(),
  );

  const final = await finalizeReusableBrowserRequest(
    {
      preparation: prepared,
      lease: session,
      use: use(),
      authority: {
        session: decision("browser:session", "BLOCK"),
        persistence: decision("browser:session-persist"),
      },
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );

  assert.equal(final.disposition, "QUARANTINE_EVICT");
  assert.equal(final.reason, "AUTHORITY_OR_LEASE_CHANGED");
  assert.equal(final.candidate, null);
  assert.equal(fake.calls.at(-1)?.kind, "quarantine");
});

test("P9B revoked lease cannot return successful page to reusable pool", async () => {
  const session = lease(true);
  const fake = adapter();

  const prepared = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
    },
    fake.value,
    runtime(),
  );

  const revoked = revokeBrowserSessionLease(
    session,
    "agent0",
    authority(true),
    runtime("2026-09-26T06:20:01.000Z"),
  );

  const final = await finalizeReusableBrowserRequest(
    {
      preparation: prepared,
      lease: revoked,
      use: use(),
      authority: authority(true),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:02.000Z"),
  );

  assert.equal(final.disposition, "QUARANTINE_EVICT");
  assert.equal(final.reason, "AUTHORITY_OR_LEASE_CHANGED");
});

test("P9B tampered or cross-session pool candidates fail closed", async () => {
  const session = lease(true);
  const fake = adapter();

  const prepared = await prepareReusableBrowserRequest(
    {
      lease: session,
      use: use(),
      authority: authority(true),
      mode: "PERSISTENT_AUTHENTICATED",
    },
    fake.value,
    runtime(),
  );
  const final = await finalizeReusableBrowserRequest(
    {
      preparation: prepared,
      lease: session,
      use: use(),
      authority: authority(true),
      outcome: { status: "SUCCESS", pageHealth: "HEALTHY" },
    },
    fake.value,
    runtime("2026-09-26T06:20:01.000Z"),
  );

  const candidate = final.candidate!;
  assert.doesNotThrow(() => validateReusableBrowserPoolCandidate(candidate));

  const tampered = {
    ...candidate,
    lastSettingsSha256: "9".repeat(64),
  };
  assert.throws(
    () => validateReusableBrowserPoolCandidate(tampered),
    /integrity mismatch/,
  );

  await assert.rejects(
    prepareReusableBrowserRequest(
      {
        lease: session,
        use: use(),
        authority: authority(true),
        mode: "PERSISTENT_AUTHENTICATED",
        candidate: {
          ...candidate,
          sessionId: "different-session",
          candidateSha256: candidate.candidateSha256,
        },
      },
      fake.value,
      runtime("2026-09-26T06:20:02.000Z"),
    ),
    /integrity mismatch|does not match current P8 session/,
  );
});
