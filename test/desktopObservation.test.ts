import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_CAPABILITY_MANIFEST,
  resolveCapabilityAuthority,
} from "../src/capabilityPolicy.js";
import type {
  CapabilityPolicyLayer,
} from "../src/capabilityPolicy.js";
import {
  assertCapabilityContractCompatible,
  createCapabilityInvocationContractBinding,
} from "../src/capabilityContract.js";
import {
  capabilityContractDescriptorSha256,
  createCapabilityContractRegistry,
} from "../src/capabilityContractSchema.js";
import {
  sealCapabilityInvocationRecord,
} from "../src/capabilityInvocationRecord.js";
import {
  DESKTOP_OBSERVATION_CONTRACT_IDS,
  DESKTOP_OBSERVATION_TOOL_NAMES,
  assertDesktopElementReferenceCurrent,
  assertDesktopObservationReceiptIntegrity,
  desktopObservationAdapterRegistrationSha256,
  desktopObservationParametersSha256,
  normalizeDesktopObservationRequest,
  observeGovernedDesktop,
} from "../src/desktopObservation.js";
import type {
  DesktopObservationAdapterRegistration,
  DesktopObservationHead,
  DesktopObservationRequest,
  DesktopScreenshotRequest,
  GovernedDesktopObservationAdapter,
} from "../src/desktopObservationTypes.js";
import {
  createHostConnectorSessionLease,
  narrowHostConnectorSessionLease,
} from "../src/hostConnectorSessionLease.js";
import {
  createRunBudgetLedger,
} from "../src/runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "../src/runBudgetTypes.js";

const NOW = "2026-09-27T03:00:00.000Z";
const IMPL_SHA = "a".repeat(64);
const INTENT_SHA = "b".repeat(64);

function policy(
  capabilityId: string,
  allow = true,
) {
  const layers: readonly CapabilityPolicyLayer[] = allow
    ? [
        {
          scope: "agent",
          subject: "agent0",
          decisions: {
            [capabilityId]: "ALLOW",
          },
        },
      ]
    : [];
  return resolveCapabilityAuthority(
    capabilityId,
    CORE_CAPABILITY_MANIFEST,
    layers,
  );
}

function budgetLimits(): RunBudgetVector {
  return {
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 10,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 300_000,
    childTasks: 0,
  };
}

function screenshotRequest(): DesktopScreenshotRequest {
  return {
    kind: "SCREENSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: { displayIds: [0] },
    annotate: false,
    maxWallClockMs: 5_000,
  };
}

function makeContext(
  request: DesktopObservationRequest,
  adapterOverrides: Partial<GovernedDesktopObservationAdapter> = {},
) {
  const normalized =
    normalizeDesktopObservationRequest(request);
  const capabilityId = normalized.capabilityId;
  const toolName =
    DESKTOP_OBSERVATION_TOOL_NAMES[capabilityId];
  const contractId =
    DESKTOP_OBSERVATION_CONTRACT_IDS[capabilityId];

  const descriptor = {
    schemaVersion:
      "toadaid.capability-contract.v2" as const,
    capabilityId,
    contractId,
    version: { major: 1, minor: 0 },
    features: [
      "bounded-observation",
      "lease-bound",
      "q1-accounted",
    ],
    requestSchema: { schemaId: "toadaid.desktop.observation-request", schemaSha256: "8".repeat(64) },
    resultSchema: { schemaId: "toadaid.desktop.observation-result", schemaSha256: "9".repeat(64) },
    receiptSchema: { schemaId: "toadaid.desktop.observation-receipt", schemaSha256: "a".repeat(64) },
  };
  const registration: DesktopObservationAdapterRegistration = {
    schemaVersion: "toadaid.desktop-observation-adapter-registration.v1",
    adapterId: "windows-mcp-observer",
    capabilityId,
    toolName,
    contractId,
    descriptorSha256: capabilityContractDescriptorSha256(descriptor),
    implementationFingerprintSha256: IMPL_SHA,
  };
  const registry =
    createCapabilityContractRegistry([descriptor]);
  const requirement = {
    capabilityId,
    contractId,
    major: 1,
    minMinor: 0,
    requiredFeatures: [
      "bounded-observation",
      "lease-bound",
      "q1-accounted",
    ],
  };
  const compatibility =
    assertCapabilityContractCompatible(
      registry,
      requirement,
    );

  const invocation =
    sealCapabilityInvocationRecord({
      schemaVersion:
        "toadaid.capability-invocation.v1",
      invocationId: "desktop-invocation-001",
      revision: 2,
      status: "STARTED",
      runId: "run-001",
      childTaskId: null,
      capabilityId,
      toolName,
      externalToolCallId: null,
      createdAt: NOW,
      updatedAt: NOW,
      request: {
        intentSha256: INTENT_SHA,
        argumentsSha256:
          desktopObservationParametersSha256(
            request,
          ),
      },
      authorization: {
        checkedAt: NOW,
        decision: "ALLOW",
        reason: "AUTHORIZED_BY_POLICY",
        decisionSha256: "c".repeat(64),
      },
      start: {
        startedAt: NOW,
        managerId: "desktop-manager",
      },
      cancellation: null,
      outcome: null,
      continuity: {
        previousRecordSha256: "d".repeat(64),
      },
    });

  const contractBinding =
    createCapabilityInvocationContractBinding(
      invocation,
      requirement,
      registry,
      {
        providerDescriptorSha256: "b".repeat(64),
        adapterRegistrationSha256: desktopObservationAdapterRegistrationSha256(registration),
        implementationFingerprintSha256: IMPL_SHA,
      },
    );
  const contractReady = {
    schemaVersion:
      "toadaid.capability-invocation-contract-ready.v1" as const,
    invocationId: invocation.record.invocationId,
    capabilityId,
    bindingSha256:
      contractBinding.bindingSha256,
    provider: {
      providerDescriptorSha256: contractBinding.providerDescriptorSha256,
      adapterRegistrationSha256: contractBinding.adapterRegistrationSha256,
      implementationFingerprintSha256: contractBinding.implementationFingerprintSha256,
    },
    compatibility,
  };

  const lease = createHostConnectorSessionLease(
    {
      hostId: "dell7920",
      sessionId: "host-session-001",
      ownerId: "agent0",
      allowedCapabilities: [capabilityId],
      connectionConfigSha256: "e".repeat(64),
      ttlMs: 60_000,
      createdAt: NOW,
    },
    policy("host:session"),
    { now: () => new Date(NOW) },
  );

  const baseAdapter: GovernedDesktopObservationAdapter = {
    registration,
    async observe(adapterRequest) {
      return {
        schemaVersion:
          "toadaid.desktop-observation-adapter-result.v1",
        observationEpoch:
          adapterRequest.observationEpoch,
        hostId: adapterRequest.hostId,
        sessionId: adapterRequest.sessionId,
        displayIds:
          adapterRequest.parameters.displayIds,
        windowId:
          adapterRequest.parameters.windowId,
        evidenceSha256: "f".repeat(64),
        artifacts: [
          {
            id: "artifact-001",
            kind:
              adapterRequest.parameters.kind ===
              "DISPLAY_INVENTORY"
                ? "DISPLAY_INVENTORY"
                : adapterRequest.parameters.kind ===
                    "WAIT_FOR"
                  ? "WAIT_RESULT"
                  : adapterRequest.parameters.kind ===
                      "UI_SNAPSHOT"
                    ? "UI_TREE"
                    : "SCREENSHOT",
            sha256: "1".repeat(64),
          },
        ],
        ...(adapterRequest.parameters.kind ===
        "UI_SNAPSHOT"
          ? {
              elements: [
                {
                  elementId: "button-save",
                  evidenceSha256:
                    "2".repeat(64),
                  inputSecurity:
                    "ORDINARY_TEXT",
                },
              ],
            }
          : {}),
        ...(adapterRequest.parameters.kind ===
        "WAIT_FOR"
          ? { matched: true }
          : {}),
      };
    },
  };

  const adapter = {
    ...baseAdapter,
    ...adapterOverrides,
  } as GovernedDesktopObservationAdapter;

  const budget = createRunBudgetLedger(
    {
      budgetId: "budget-001",
      runId: "run-001",
      createdAt: NOW,
      limits: budgetLimits(),
    },
    { now: () => new Date(NOW) },
  );

  const observationHeads = new Map<
    string,
    DesktopObservationHead
  >();
  const observationHeadKey = (
    hostId: string,
    sessionId: string,
    windowId: string,
  ) => `${hostId}\n${sessionId}\n${windowId}`;
  const observationHeadRuntime = {
    publishCurrentObservationHead(
      head: DesktopObservationHead,
    ) {
      observationHeads.set(
        observationHeadKey(
          head.hostId,
          head.sessionId,
          head.windowId,
        ),
        head,
      );
    },
    claimCurrentObservationHead(
      expected: DesktopObservationHead,
      next: DesktopObservationHead,
    ) {
      const key = observationHeadKey(
        expected.hostId,
        expected.sessionId,
        expected.windowId,
      );
      const current =
        observationHeads.get(key) ?? null;
      if (
        current === null ||
        JSON.stringify(current) !==
          JSON.stringify(expected)
      ) {
        return false;
      }
      observationHeads.set(key, next);
      return true;
    },
    resolveCurrentObservationHead(
      identity: Readonly<{
        hostId: string;
        sessionId: string;
        windowId: string;
      }>,
    ) {
      return (
        observationHeads.get(
          observationHeadKey(
            identity.hostId,
            identity.sessionId,
            identity.windowId,
          ),
        ) ?? null
      );
    },
  };

  return {
    normalized,
    descriptor,
    registry,
    requirement,
    compatibility,
    invocation,
    contractBinding,
    contractReady,
    lease,
    registration,
    adapter,
    budget,
    observationHeadRuntime,
    input: {
      lease,
      leaseRuntime: {
        now: () => new Date(NOW),
        resolveCurrentLeaseSha256: () =>
          lease.leaseSha256,
      },
      observationHeadRuntime,
      sessionAuthority: policy("host:session"),
      actionAuthority: policy(capabilityId),
      invocation,
      contractBinding,
      contractReady,
      contractRequirement: requirement,
      contractRegistry: registry,
      budget,
      request,
    },
  };
}

test("P16 installs four observation capabilities separately and BLOCK by default", () => {
  for (const capabilityId of [
    "host:display-inventory",
    "host:screenshot",
    "host:ui-snapshot",
    "host:wait-for",
  ]) {
    const authority = policy(
      capabilityId,
      false,
    );
    assert.equal(authority.installed, true);
    assert.equal(authority.decision, "BLOCK");
    assert.equal(
      authority.reason,
      "MANIFEST_DEFAULT",
    );
  }
});

test("P16 screenshot refuses ambient full-desktop capture and ambiguous scope", () => {
  assert.throws(
    () =>
      normalizeDesktopObservationRequest({
        kind: "SCREENSHOT",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        scope: {},
      }),
    /requires explicit displayIds or bounded region/,
  );

  assert.throws(
    () =>
      normalizeDesktopObservationRequest({
        kind: "SCREENSHOT",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        scope: {
          displayIds: [0],
          region: {
            left: 0,
            top: 0,
            right: 100,
            bottom: 100,
          },
        },
      }),
    /choose displayIds or region/,
  );
});

test("P16 successful screenshot crosses P15/P3/C1/H1 and spends Q1 budget before adapter entry", async () => {
  const ctx = makeContext(
    screenshotRequest(),
  );

  const outcome = await observeGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-001",
    },
  );

  assert.equal(outcome.receipt.status, "OK");
  assert.equal(
    outcome.receipt.capabilityId,
    "host:screenshot",
  );
  assert.equal(
    outcome.receipt.observationEpoch,
    "observation-001",
  );
  assert.deepEqual(
    outcome.receipt.displayIds,
    [0],
  );
  assert.equal(
    outcome.receipt.leaseSha256,
    ctx.lease.leaseSha256,
  );
  assert.equal(
    outcome.receipt.contractBindingSha256,
    ctx.contractBinding.bindingSha256,
  );
  assert.equal(
    outcome.receipt.budget.reservedCost.toolCalls,
    1,
  );
  assert.equal(
    outcome.receipt.budget.reservedCost.wallClockMs,
    5_000,
  );
  assert.notEqual(
    outcome.budget.recordSha256,
    ctx.budget.recordSha256,
  );
  assert.equal(
    outcome.budget.record.usageReceipts.length,
    1,
  );
});

test("P16 stale P15 lease head refuses observation before adapter entry", async () => {
  const ctx = makeContext(
    screenshotRequest(),
  );
  let calls = 0;
  const adapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    async observe(request) {
      calls += 1;
      return ctx.adapter.observe(request);
    },
  };
  const narrowed =
    narrowHostConnectorSessionLease(
      ctx.lease,
      {
        ownerId: "agent0",
        allowedCapabilities: [],
        updatedAt:
          "2026-09-27T03:00:10.000Z",
      },
      policy("host:session"),
      {
        now: () =>
          new Date(
            "2026-09-27T03:00:10.000Z",
          ),
      },
    );

  await assert.rejects(
    observeGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        leaseRuntime: {
          now: () => new Date(NOW),
          resolveCurrentLeaseSha256: () =>
            narrowed.leaseSha256,
        },
      },
      {
        now: () => new Date(NOW),
        randomId: () => "observation-002",
      },
    ),
    /lease is stale/,
  );
  assert.equal(calls, 0);
});

test("P16 changed H1 parameters fail closed before adapter entry", async () => {
  const ctx = makeContext(
    screenshotRequest(),
  );
  let calls = 0;
  const adapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    async observe(request) {
      calls += 1;
      return ctx.adapter.observe(request);
    },
  };

  await assert.rejects(
    observeGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        request: {
          ...screenshotRequest(),
          annotate: true,
        },
      },
      {
        now: () => new Date(NOW),
        randomId: () => "observation-003",
      },
    ),
    /parameters do not match H1 argumentsSha256/,
  );
  assert.equal(calls, 0);
});

test("P16 changed C1 implementation fingerprint fails closed before adapter entry", async () => {
  const ctx = makeContext(
    screenshotRequest(),
  );
  let calls = 0;
  const adapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    registration: {
      ...ctx.registration,
      implementationFingerprintSha256:
        "9".repeat(64),
    },
    async observe(request) {
      calls += 1;
      return ctx.adapter.observe(request);
    },
  };

  await assert.rejects(
    observeGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "observation-004",
      },
    ),
    /does not match current C1 truth/,
  );
  assert.equal(calls, 0);
});

test("P16 Q1 preflight refuses insufficient budget before adapter entry", async () => {
  const ctx = makeContext(
    screenshotRequest(),
  );
  let calls = 0;
  const adapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    async observe(request) {
      calls += 1;
      return ctx.adapter.observe(request);
    },
  };
  const tinyBudget = createRunBudgetLedger(
    {
      budgetId: "budget-tiny",
      runId: "run-001",
      createdAt: NOW,
      limits: {
        ...budgetLimits(),
        toolCalls: 0,
        wallClockMs: 0,
      },
    },
    { now: () => new Date(NOW) },
  );

  await assert.rejects(
    observeGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        budget: tinyBudget,
      },
      {
        now: () => new Date(NOW),
        randomId: () => "observation-005",
      },
    ),
    /run budget exceeded/,
  );
  assert.equal(calls, 0);
});

test("P16 UI element references bind exact observation/window epoch and stale after a newer observation", async () => {
  const request: DesktopObservationRequest = {
    kind: "UI_SNAPSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    windowId: "window-editor",
    includeScreenshot: false,
    useDom: false,
    maxElements: 10,
    maxWallClockMs: 5_000,
  };
  const ctx = makeContext(request);

  const first = await observeGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-ui-001",
    },
  );
  assert.equal(first.receipt.status, "OK");
  assert.equal(first.receipt.elements.length, 1);
  const element = first.receipt.elements[0]!;
  assert.doesNotThrow(() =>
    assertDesktopElementReferenceCurrent(
      element,
      first.receipt,
      ctx.observationHeadRuntime,
    ),
  );
  assert.throws(
    () =>
      assertDesktopElementReferenceCurrent(
        {
          ...element,
          inputSecurity: "SECRET_OR_PASSWORD",
        },
        first.receipt,
        ctx.observationHeadRuntime,
      ),
    /not present in current observation/,
  );

  const second = await observeGovernedDesktop(
    ctx.adapter,
    {
      ...ctx.input,
      budget: first.budget,
    },
    {
      now: () => new Date(NOW),
      randomId: () => "observation-ui-002",
    },
  );

  assert.throws(
    () =>
      assertDesktopElementReferenceCurrent(
        element,
        first.receipt,
        ctx.observationHeadRuntime,
      ),
    /not the current window observation head/,
  );

  assert.throws(
    () =>
      assertDesktopElementReferenceCurrent(
        element,
        second.receipt,
        ctx.observationHeadRuntime,
      ),
    /stale or mismatched/,
  );
});

test("P16 capture failure emits DEGRADED head for the new epoch and invalidates old window elements", async () => {
  const request: DesktopObservationRequest = {
    kind: "UI_SNAPSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    windowId: "window-editor",
    includeScreenshot: false,
    useDom: false,
    maxElements: 10,
    maxWallClockMs: 5_000,
  };
  const ctx = makeContext(request);

  const first = await observeGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-ok-001",
    },
  );
  const element = first.receipt.elements[0]!;
  assert.doesNotThrow(() =>
    assertDesktopElementReferenceCurrent(
      element,
      first.receipt,
      ctx.observationHeadRuntime,
    ),
  );

  const failingAdapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    async observe() {
      throw new Error("capture failed");
    },
  };

  const outcome = await observeGovernedDesktop(
    failingAdapter,
    {
      ...ctx.input,
      budget: first.budget,
    },
    {
      now: () => new Date(NOW),
      randomId: () => "observation-failed-001",
    },
  );

  assert.equal(
    outcome.receipt.status,
    "DEGRADED",
  );
  assert.equal(
    outcome.receipt.degradedReason,
    "ADAPTER_ERROR",
  );
  assert.equal(
    outcome.receipt.observationEpoch,
    "observation-failed-001",
  );
  assert.equal(
    outcome.receipt.evidenceSha256,
    null,
  );
  assert.deepEqual(
    outcome.receipt.elements,
    [],
  );
  assert.throws(
    () =>
      assertDesktopElementReferenceCurrent(
        element,
        first.receipt,
        ctx.observationHeadRuntime,
      ),
    /not the current window observation head/,
  );
});

test("P16 rejects artifact-kind confusion and windowless reusable UI element evidence", async () => {
  const screenshot = makeContext(
    screenshotRequest(),
    {
      async observe(adapterRequest) {
        return {
          schemaVersion:
            "toadaid.desktop-observation-adapter-result.v1",
          observationEpoch:
            adapterRequest.observationEpoch,
          hostId: adapterRequest.hostId,
          sessionId: adapterRequest.sessionId,
          displayIds: [0],
          windowId: null,
          evidenceSha256: "8".repeat(64),
          artifacts: [
            {
              id: "wrong-kind",
              kind: "UI_TREE",
              sha256: "7".repeat(64),
            },
          ],
        };
      },
    },
  );

  const wrongKind = await observeGovernedDesktop(
    screenshot.adapter,
    screenshot.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-wrong-kind",
    },
  );
  assert.equal(wrongKind.receipt.status, "DEGRADED");
  assert.equal(
    wrongKind.receipt.degradedReason,
    "ADAPTER_RESULT_INVALID",
  );

  const windowlessRequest: DesktopObservationRequest = {
    kind: "UI_SNAPSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: { displayIds: [0] },
    includeScreenshot: false,
    useDom: false,
    maxElements: 10,
    maxWallClockMs: 5_000,
  };
  const windowless = makeContext(
    windowlessRequest,
    {
      async observe(adapterRequest) {
        return {
          schemaVersion:
            "toadaid.desktop-observation-adapter-result.v1",
          observationEpoch:
            adapterRequest.observationEpoch,
          hostId: adapterRequest.hostId,
          sessionId: adapterRequest.sessionId,
          displayIds: [0],
          windowId: "window-editor",
          evidenceSha256: "6".repeat(64),
          artifacts: [
            {
              id: "ui-tree-001",
              kind: "UI_TREE",
              sha256: "5".repeat(64),
            },
          ],
          elements: [
            {
              elementId: "button-save",
              evidenceSha256: "4".repeat(64),
              inputSecurity:
                "ORDINARY_TEXT",
            },
          ],
        };
      },
    },
  );

  const windowlessResult = await observeGovernedDesktop(
    windowless.adapter,
    windowless.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-windowless-elements",
    },
  );
  assert.equal(
    windowlessResult.receipt.status,
    "DEGRADED",
  );
  assert.equal(
    windowlessResult.receipt.degradedReason,
    "ADAPTER_RESULT_INVALID",
  );
  assert.deepEqual(
    windowlessResult.receipt.elements,
    [],
  );
});

test("P16 current-head binding rejects tampered observation receipts", async () => {
  const request: DesktopObservationRequest = {
    kind: "UI_SNAPSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    windowId: "window-editor",
    includeScreenshot: false,
    useDom: false,
    maxElements: 10,
    maxWallClockMs: 5_000,
  };
  const ctx = makeContext(request);
  const outcome = await observeGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-integrity-001",
    },
  );
  const element = outcome.receipt.elements[0]!;

  assert.doesNotThrow(() =>
    assertDesktopObservationReceiptIntegrity(
      outcome.receipt,
    ),
  );

  const tampered = {
    ...outcome.receipt,
    elements: [
      ...outcome.receipt.elements,
      {
        ...element,
        elementId: "injected-element",
      },
    ],
  };
  assert.throws(
    () =>
      assertDesktopElementReferenceCurrent(
        {
          ...element,
          elementId: "injected-element",
        },
        tampered,
        ctx.observationHeadRuntime,
      ),
    /receipt integrity mismatch/,
  );
});

test("P16 wait-for is exact-window scoped with bounded timeout/interval and one governed tool call", async () => {
  assert.throws(
    () =>
      normalizeDesktopObservationRequest({
        kind: "WAIT_FOR",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        windowId: "window-editor",
        condition: "text_exists",
        text: "Ready",
        timeoutMs: 120_001,
      }),
    /timeoutMs/,
  );

  const request: DesktopObservationRequest = {
    kind: "WAIT_FOR",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    windowId: "window-editor",
    condition: "text_exists",
    text: "Ready",
    timeoutMs: 2_000,
    intervalMs: 250,
    useDom: false,
  };
  const ctx = makeContext(request);
  let calls = 0;
  const adapter: GovernedDesktopObservationAdapter = {
    ...ctx.adapter,
    async observe(adapterRequest) {
      calls += 1;
      return ctx.adapter.observe(adapterRequest);
    },
  };

  const outcome = await observeGovernedDesktop(
    adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "observation-wait-001",
    },
  );

  assert.equal(calls, 1);
  assert.equal(outcome.receipt.status, "OK");
  assert.equal(
    outcome.receipt.windowId,
    "window-editor",
  );
  assert.equal(
    outcome.receipt.budget.reservedCost.toolCalls,
    1,
  );
  assert.equal(
    outcome.receipt.budget.reservedCost.wallClockMs,
    2_000,
  );
});
