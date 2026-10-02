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
  createCapabilityInvocation,
  sealCapabilityInvocationRecord,
} from "../src/capabilityInvocationRecord.js";
import {
  DESKTOP_INTERACTION_CONTRACT_IDS,
  DESKTOP_INTERACTION_TOOL_NAMES,
  desktopInteractionAdapterRegistrationSha256,
  desktopInteractionParametersSha256,
  interactGovernedDesktop,
  normalizeDesktopInteractionRequest,
} from "../src/desktopInteraction.js";
import type {
  DesktopInteractionAdapterRegistration,
  DesktopInteractionObservationBinding,
  DesktopInteractionRequest,
  DesktopPointerClickRequest,
  DesktopTextInputRequest,
  GovernedDesktopInteractionAdapter,
} from "../src/desktopInteractionTypes.js";
import {
  desktopObservationParametersSha256,
} from "../src/desktopObservation.js";
import type {
  DesktopObservationHead,
  DesktopObservationReceipt,
  DesktopObservationRequest,
  DesktopObservationScope,
  DesktopObservedElementReference,
} from "../src/desktopObservationTypes.js";
import {
  createHostConnectorSessionLease,
  narrowHostConnectorSessionLease,
} from "../src/hostConnectorSessionLease.js";
import {
  sha256,
} from "../src/invocationSchema.js";
import {
  createReplayFence,
} from "../src/replayFence.js";
import {
  createRunBudgetLedger,
} from "../src/runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "../src/runBudgetTypes.js";

const NOW = "2026-09-27T03:10:00.000Z";
const IMPL_SHA = "a".repeat(64);
const INTENT_SHA = "b".repeat(64);
const PROVIDER_DESCRIPTOR_SHA = "c".repeat(64);
const PROVIDER_GENERATION_SHA = "d".repeat(64);
const EVIDENCE_NAMESPACE = "windows-mcp-session-001";

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

function observationFixture(
  scope: DesktopObservationScope = {
    region: {
      left: 0,
      top: 0,
      right: 800,
      bottom: 600,
    },
  },
) {
  const observationRequest: DesktopObservationRequest = {
    kind: "UI_SNAPSHOT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope,
    windowId: "window-editor",
    includeScreenshot: false,
    useDom: false,
    maxElements: 32,
    maxWallClockMs: 5_000,
  };
  const evidenceSha256 = "f".repeat(64);
  const element: DesktopObservedElementReference =
    Object.freeze({
      schemaVersion:
        "toadaid.desktop-observed-element-ref.v1",
      elementId: "button-save",
      hostId: "dell7920",
      sessionId: "host-session-001",
      windowId: "window-editor",
      observationEpoch: "observation-001",
      observationEvidenceSha256:
        evidenceSha256,
      providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
      providerGenerationSha256: PROVIDER_GENERATION_SHA,
      evidenceNamespace: EVIDENCE_NAMESPACE,
      elementEvidenceSha256:
        "2".repeat(64),
      inputSecurity: "ORDINARY_TEXT",
    });

  const core = Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-receipt.v1" as const,
    status: "OK" as const,
    capabilityId:
      "host:ui-snapshot" as const,
    invocationId: "observation-invocation-001",
    runId: "run-001",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    leaseSha256: "3".repeat(64),
    contractBindingSha256: "4".repeat(64),
    descriptorSha256: "5".repeat(64),
    adapterRegistrationSha256: "6".repeat(64),
    observationEpoch: "observation-001",
    parametersSha256:
      desktopObservationParametersSha256(
        observationRequest,
      ),
    observedAt: NOW,
    displayIds: Object.freeze(scope.displayIds ?? []),
    displayTopologyEpoch: scope.displayTopologyEpoch ?? "topology-001",
    windowId: "window-editor",
    providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
    providerGenerationSha256: PROVIDER_GENERATION_SHA,
    evidenceNamespace: EVIDENCE_NAMESPACE,
    geometry: Object.freeze({
      coordinateSpace: scope.displayIds ? "DESKTOP_PHYSICAL" as const : "WINDOW_CLIENT_PHYSICAL" as const,
      bounds: scope.region ?? { left: 0, top: 0, right: 1920, bottom: 1080 },
      displayTopologyEpoch: scope.displayTopologyEpoch ?? "topology-001",
    }),
    matched: null,
    completionReason: null,
    cancellationStatus: "NOT_REQUESTED" as const,
    evidenceSha256,
    artifacts: Object.freeze([
      Object.freeze({
        id: "ui-tree-001",
        kind: "UI_TREE" as const,
        sha256: "7".repeat(64),
      }),
    ]),
    elements: Object.freeze([element]),
    budget: Object.freeze({
      ledgerSha256Before: "8".repeat(64),
      ledgerSha256After: "9".repeat(64),
      reservedCost: Object.freeze({
        modelRequests: 0,
        inputTokens: 0,
        outputTokens: 0,
        toolCalls: 1,
        networkRequests: 0,
        retries: 0,
        wallClockMs: 5_000,
        childTasks: 0,
      }),
    }),
    degradedReason: null,
    errorClass: null,
    errorFingerprint: null,
  });
  const observationReceipt: DesktopObservationReceipt =
    Object.freeze({
      ...core,
      receiptSha256: sha256(core),
    });
  const observation: DesktopInteractionObservationBinding =
    Object.freeze({
      receiptSha256:
        observationReceipt.receiptSha256,
      observationEpoch:
        observationReceipt.observationEpoch,
      evidenceSha256,
      windowId: "window-editor",
    });

  const heads = new Map<
    string,
    DesktopObservationHead
  >();
  const key = (
    hostId: string,
    sessionId: string,
    windowId: string,
  ) => `${hostId}\n${sessionId}\n${windowId}`;
  const observationHeadRuntime = {
    resolveCurrentProviderIdentity() {
      return {
        providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
        providerGenerationSha256: PROVIDER_GENERATION_SHA,
        evidenceNamespace: EVIDENCE_NAMESPACE,
      };
    },
    publishCurrentObservationHead(
      head: DesktopObservationHead,
    ) {
      heads.set(
        key(
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
      const headKey = key(
        expected.hostId,
        expected.sessionId,
        expected.windowId,
      );
      const current = heads.get(headKey) ?? null;
      if (
        current === null ||
        JSON.stringify(current) !==
          JSON.stringify(expected)
      ) {
        return false;
      }
      heads.set(headKey, next);
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
        heads.get(
          key(
            identity.hostId,
            identity.sessionId,
            identity.windowId,
          ),
        ) ?? null
      );
    },
  };
  observationHeadRuntime.publishCurrentObservationHead({
    schemaVersion:
      "toadaid.desktop-observation-head.v1",
    hostId: "dell7920",
    sessionId: "host-session-001",
    windowId: "window-editor",
    observationEpoch: "observation-001",
    providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
    providerGenerationSha256: PROVIDER_GENERATION_SHA,
    evidenceNamespace: EVIDENCE_NAMESPACE,
    status: "OK",
    evidenceSha256,
    receiptSha256:
      observationReceipt.receiptSha256,
  });

  return {
    observationRequest,
    observationReceipt,
    observation,
    element,
    observationHeadRuntime,
  };
}

function clickRequest(): DesktopPointerClickRequest {
  const observation = observationFixture();
  return {
    kind: "POINTER_CLICK",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    observation: observation.observation,
    target: {
      kind: "ELEMENT",
      element: observation.element,
    },
    button: "LEFT",
    clickCount: 1,
    maxObservationAgeMs: 5_000,
    maxWallClockMs: 5_000,
  };
}

function makeContext(
  request: DesktopInteractionRequest,
  replayClass:
    | "SAFE_READ"
    | "IDEMPOTENT_WRITE"
    | "NON_REPLAYABLE" = "NON_REPLAYABLE",
  adapterOverrides:
    Partial<GovernedDesktopInteractionAdapter> = {},
  observationScope?: DesktopObservationScope,
) {
  const observation =
    observationFixture(observationScope);
  const normalized =
    normalizeDesktopInteractionRequest(request);
  const capabilityId = normalized.capabilityId;
  const toolName =
    DESKTOP_INTERACTION_TOOL_NAMES[capabilityId];
  const contractId =
    DESKTOP_INTERACTION_CONTRACT_IDS[capabilityId];

  const descriptor = {
    schemaVersion:
      "toadaid.capability-contract.v2" as const,
    capabilityId,
    contractId,
    version: { major: 1, minor: 0 },
    features: [
      "p16-observation-bound",
      "x1-non-replayable",
      "q1-accounted",
    ],
    requestSchema: { schemaId: "toadaid.desktop.interaction-request", schemaSha256: "8".repeat(64) },
    resultSchema: { schemaId: "toadaid.desktop.interaction-result", schemaSha256: "9".repeat(64) },
    receiptSchema: { schemaId: "toadaid.desktop.interaction-receipt", schemaSha256: "a".repeat(64) },
  };
  const registration: DesktopInteractionAdapterRegistration = {
    schemaVersion: "toadaid.desktop-interaction-adapter-registration.v1",
    adapterId: "windows-mcp-interaction-adapter",
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
      "p16-observation-bound",
      "x1-non-replayable",
      "q1-accounted",
    ],
  };
  const compatibility =
    assertCapabilityContractCompatible(
      registry,
      requirement,
    );

  const argumentsSha256 =
    desktopInteractionParametersSha256(request);
  const preStart = createCapabilityInvocation({
    invocationId: "interaction-invocation-001",
    runId: "run-001",
    capabilityId,
    toolName,
    intentSha256: INTENT_SHA,
    argumentsSha256,
    createdAt: NOW,
  });
  const replayFence = createReplayFence(
    preStart,
    { replayClass, createdAt: NOW },
    { now: () => new Date(NOW) },
  );

  const invocation =
    sealCapabilityInvocationRecord({
      schemaVersion:
        "toadaid.capability-invocation.v1",
      invocationId: "interaction-invocation-001",
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
        argumentsSha256,
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
        providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
        adapterRegistrationSha256: desktopInteractionAdapterRegistrationSha256(registration),
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

  const baseAdapter: GovernedDesktopInteractionAdapter =
    {
      registration,
      async prepare(preparationRequest) {
        return {
          schemaVersion:
            "toadaid.desktop-interaction-prepare-result.v1",
          status: "PREPARED",
          providerDescriptorSha256:
            preparationRequest.providerDescriptorSha256,
          providerGenerationSha256:
            preparationRequest.providerGenerationSha256,
          implementationFingerprintSha256:
            preparationRequest.implementationFingerprintSha256,
          providerNonce: "provider-nonce-001",
          resolvedTargetIdentitySha256:
            sha256({
              windowId:
                preparationRequest.windowId,
              targetEvidenceSha256:
                preparationRequest.targetEvidenceSha256,
            }),
        };
      },
      async dispatch(adapterRequest) {
        return {
          schemaVersion:
            "toadaid.desktop-interaction-adapter-result.v1",
          preparationTicketSha256:
            adapterRequest.preparationTicket.ticketSha256,
          interactionEpoch:
            adapterRequest.interactionEpoch,
          hostId: adapterRequest.hostId,
          sessionId: adapterRequest.sessionId,
          windowId: adapterRequest.windowId,
          evidenceSha256: "1".repeat(64),
          resultingObservation: null,
        };
      },
    };
  const adapter = {
    ...baseAdapter,
    ...adapterOverrides,
  } as GovernedDesktopInteractionAdapter;

  const budget = createRunBudgetLedger(
    {
      budgetId: "budget-interaction-001",
      runId: "run-001",
      createdAt: NOW,
      limits: budgetLimits(),
    },
    { now: () => new Date(NOW) },
  );

  return {
    ...observation,
    normalized,
    descriptor,
    registry,
    requirement,
    compatibility,
    invocation,
    replayFence,
    contractBinding,
    contractReady,
    lease,
    registration,
    adapter,
    budget,
    input: {
      lease,
      leaseRuntime: {
        now: () => new Date(NOW),
        resolveCurrentLeaseSha256: () =>
          lease.leaseSha256,
      },
      observationHeadRuntime:
        observation.observationHeadRuntime,
      sessionAuthority: policy("host:session"),
      actionAuthority: policy(capabilityId),
      invocation,
      contractBinding,
      contractReady,
      contractRequirement: requirement,
      contractRegistry: registry,
      replayFence,
      budget,
      observationRequest:
        observation.observationRequest,
      observationReceipt:
        observation.observationReceipt,
      request,
    },
  };
}

test("P17 installs five interaction capabilities separately and BLOCK by default", () => {
  for (const capabilityId of [
    "host:pointer-click",
    "host:pointer-move",
    "host:scroll",
    "host:text-input",
    "host:shortcut",
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

test("P17 successful element click crosses P15/P3/C1/H1/X1/Q1 and invalidates the old P16 head", async () => {
  const ctx = makeContext(clickRequest());
  const outcome = await interactGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "interaction-001",
    },
  );

  assert.equal(outcome.receipt.status, "OK");
  assert.equal(
    outcome.receipt.capabilityId,
    "host:pointer-click",
  );
  assert.equal(
    outcome.receipt.replayFenceSha256,
    ctx.replayFence.recordSha256,
  );
  assert.equal(
    outcome.receipt.intentSha256,
    INTENT_SHA,
  );
  assert.equal(
    outcome.receipt.observationReceiptSha256,
    ctx.observationReceipt.receiptSha256,
  );
  assert.equal(
    outcome.receipt.budget.reservedCost.toolCalls,
    1,
  );
  assert.match(
    outcome.receipt.preparationTicketSha256,
    /^[a-f0-9]{64}$/,
  );
  assert.equal(
    outcome.budget.record.usageReceipts.length,
    1,
  );

  const head =
    ctx.observationHeadRuntime
      .resolveCurrentObservationHead({
        hostId: "dell7920",
        sessionId: "host-session-001",
        windowId: "window-editor",
      });
  assert.equal(head?.status, "PENDING");
  assert.equal(
    head?.observationEpoch,
    "interaction-001",
  );
});

test("P17B typed provider refusal stays before dispatch without budget or observation mutation", async () => {
  const ctx = makeContext(clickRequest());
  let dispatchCalls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async prepare() {
      return {
        schemaVersion:
          "toadaid.desktop-interaction-prepare-result.v1",
        status: "REFUSED_BEFORE_DISPATCH",
        reasonCode: "TARGET_NOT_READY",
        evidenceSha256: "e".repeat(64),
      };
    },
    async dispatch(request) {
      dispatchCalls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-refused",
      },
    ),
    (error: unknown) => {
      assert.equal(
        (error as { status?: string }).status,
        "REFUSED_BEFORE_DISPATCH",
      );
      assert.equal(
        (error as { reasonCode?: string }).reasonCode,
        "TARGET_NOT_READY",
      );
      return true;
    },
  );
  assert.equal(dispatchCalls, 0);
  assert.equal(
    ctx.budget.record.usageReceipts.length,
    0,
  );
  const head =
    ctx.observationHeadRuntime
      .resolveCurrentObservationHead({
        hostId: "dell7920",
        sessionId: "host-session-001",
        windowId: "window-editor",
      });
  assert.equal(head?.status, "OK");
  assert.equal(
    head?.observationEpoch,
    "observation-001",
  );
});

test("P17B preparation identity mismatch refuses safely before dispatch", async () => {
  const ctx = makeContext(clickRequest());
  let dispatchCalls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async prepare(request) {
      return {
        schemaVersion:
          "toadaid.desktop-interaction-prepare-result.v1",
        status: "PREPARED",
        providerDescriptorSha256:
          request.providerDescriptorSha256,
        providerGenerationSha256:
          "0".repeat(64),
        implementationFingerprintSha256:
          request.implementationFingerprintSha256,
        providerNonce:
          "provider-nonce-mismatch",
        resolvedTargetIdentitySha256:
          "1".repeat(64),
      };
    },
    async dispatch(request) {
      dispatchCalls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () =>
          "interaction-prep-identity-mismatch",
      },
    ),
    (error: unknown) => {
      assert.equal(
        (error as { status?: string }).status,
        "REFUSED_BEFORE_DISPATCH",
      );
      assert.equal(
        (error as { reasonCode?: string }).reasonCode,
        "PREPARATION_IDENTITY_MISMATCH",
      );
      return true;
    },
  );
  assert.equal(dispatchCalls, 0);
  assert.equal(
    ctx.budget.record.usageReceipts.length,
    0,
  );
});

test("P17B preparation throw is a safe pre-dispatch refusal rather than X1 uncertainty", async () => {
  const ctx = makeContext(clickRequest());
  let dispatchCalls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async prepare() {
      throw new Error("focus check failed");
    },
    async dispatch(request) {
      dispatchCalls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () =>
          "interaction-prep-throw",
      },
    ),
    (error: unknown) => {
      assert.equal(
        (error as { status?: string }).status,
        "REFUSED_BEFORE_DISPATCH",
      );
      assert.equal(
        (error as { reasonCode?: string }).reasonCode,
        "PREPARATION_FAILED",
      );
      return true;
    },
  );
  assert.equal(dispatchCalls, 0);
  assert.equal(
    ctx.budget.record.usageReceipts.length,
    0,
  );
});

test("P17 refuses stale P16 observation before adapter entry", async () => {
  const ctx = makeContext(clickRequest());
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };
  ctx.observationHeadRuntime.publishCurrentObservationHead({
    schemaVersion:
      "toadaid.desktop-observation-head.v1",
    hostId: "dell7920",
    sessionId: "host-session-001",
    windowId: "window-editor",
    observationEpoch: "newer-observation",
    providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
    providerGenerationSha256: PROVIDER_GENERATION_SHA,
    evidenceNamespace: EVIDENCE_NAMESPACE,
    status: "OK",
    evidenceSha256: "3".repeat(64),
    receiptSha256: "4".repeat(64),
  });

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-stale",
      },
    ),
    /stale or not current/,
  );
  assert.equal(calls, 0);
});

test("P17 atomically claims the exact P16 head and refuses a freshness race before adapter entry", async () => {
  const ctx = makeContext(clickRequest());
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };
  const base = ctx.observationHeadRuntime;
  const racingRuntime = {
    resolveCurrentProviderIdentity:
      base.resolveCurrentProviderIdentity.bind(base),
    publishCurrentObservationHead:
      base.publishCurrentObservationHead.bind(base),
    resolveCurrentObservationHead:
      base.resolveCurrentObservationHead.bind(base),
    claimCurrentObservationHead(
      _expected: DesktopObservationHead,
      _next: DesktopObservationHead,
    ) {
      base.publishCurrentObservationHead({
        schemaVersion:
          "toadaid.desktop-observation-head.v1",
        hostId: "dell7920",
        sessionId: "host-session-001",
        windowId: "window-editor",
        observationEpoch:
          "racing-newer-observation",
        providerDescriptorSha256: PROVIDER_DESCRIPTOR_SHA,
        providerGenerationSha256: PROVIDER_GENERATION_SHA,
        evidenceNamespace: EVIDENCE_NAMESPACE,
        status: "OK",
        evidenceSha256: "a".repeat(64),
        receiptSha256: "b".repeat(64),
      });
      return false;
    },
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        observationHeadRuntime: racingRuntime,
      },
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-race",
      },
    ),
    /head changed before dispatch/,
  );
  assert.equal(calls, 0);
});

test("P16B/P17 coordinate click consumes exact coordinate-space and topology geometry", async () => {
  const fixture = observationFixture();
  const inside: DesktopPointerClickRequest = {
    kind: "POINTER_CLICK",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    observation: fixture.observation,
    target: {
      kind: "COORDINATE",
      coordinateSpace: "WINDOW_CLIENT_PHYSICAL",
      x: 799,
      y: 599,
    },
    button: "LEFT",
  };
  const insideCtx = makeContext(inside);
  const insideOutcome =
    await interactGovernedDesktop(
      insideCtx.adapter,
      insideCtx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-coordinate-ok",
      },
    );
  assert.equal(insideOutcome.receipt.status, "OK");

  const outside: DesktopPointerClickRequest = {
    ...inside,
    target: {
      kind: "COORDINATE",
      coordinateSpace: "WINDOW_CLIENT_PHYSICAL",
      x: 800,
      y: 599,
    },
  };
  const outsideCtx = makeContext(outside);
  await assert.rejects(
    interactGovernedDesktop(
      outsideCtx.adapter,
      outsideCtx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-coordinate-bad",
      },
    ),
    /outside authorized P16 geometry/,
  );

  const displayScope: DesktopObservationScope = {
    displayIds: [0],
    displayTopologyEpoch: "topology-001",
  };
  const displayFixture =
    observationFixture(displayScope);
  const displayRequest: DesktopPointerClickRequest = {
    kind: "POINTER_CLICK",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    observation: displayFixture.observation,
    target: {
      kind: "COORDINATE",
      displayId: 0,
      displayTopologyEpoch: "topology-001",
      coordinateSpace: "DESKTOP_PHYSICAL",
      x: 10,
      y: 10,
    },
    button: "LEFT",
  };
  const displayCtx = makeContext(
    displayRequest,
    "NON_REPLAYABLE",
    {},
    displayScope,
  );
  const displayOutcome = await interactGovernedDesktop(
      displayCtx.adapter,
      displayCtx.input,
      {
        now: () => new Date(NOW),
        randomId: () =>
          "interaction-display-without-geometry",
      },
  );
  assert.equal(displayOutcome.receipt.status, "OK");

  const wrongSpaceCtx = makeContext({
    ...inside,
    target: { kind: "COORDINATE", coordinateSpace: "DESKTOP_PHYSICAL", x: 10, y: 10 },
  });
  await assert.rejects(() => interactGovernedDesktop(wrongSpaceCtx.adapter, wrongSpaceCtx.input, {
    now: () => new Date(NOW), randomId: () => "interaction-wrong-space",
  }), /coordinate space mismatch/);

  const staleTopologyRequest: DesktopPointerClickRequest = {
    ...displayRequest,
    target: { kind: "COORDINATE", displayId: 0, displayTopologyEpoch: "topology-stale", coordinateSpace: "DESKTOP_PHYSICAL", x: 10, y: 10 },
  };
  const staleTopologyCtx = makeContext(staleTopologyRequest, "NON_REPLAYABLE", {}, displayScope);
  await assert.rejects(() => interactGovernedDesktop(staleTopologyCtx.adapter, staleTopologyCtx.input, {
    now: () => new Date(NOW), randomId: () => "interaction-stale-topology",
  }), /stale or not authorized by P16 topology evidence/);
});

test("P17 ordinary text input is separate from secret/password entry and receipts do not persist raw text", async () => {
  const fixture = observationFixture();
  const ordinaryText =
    "draft-title-that-must-not-enter-receipt";
  const request: DesktopTextInputRequest = {
    kind: "TEXT_INPUT",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    observation: fixture.observation,
    target: {
      kind: "ELEMENT",
      element: fixture.element,
    },
    text: ordinaryText,
    contentClass: "ORDINARY_TEXT",
    replace: false,
  };
  const ctx = makeContext(request);
  const outcome = await interactGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "interaction-text",
    },
  );
  assert.equal(outcome.receipt.status, "OK");
  assert.equal(
    JSON.stringify(outcome.receipt).includes(
      ordinaryText,
    ),
    false,
  );

  assert.throws(
    () =>
      normalizeDesktopInteractionRequest({
        ...request,
        contentClass: "SECRET",
      } as unknown as DesktopTextInputRequest),
    /refuses secret\/password content/,
  );

  assert.throws(
    () =>
      normalizeDesktopInteractionRequest({
        ...request,
        target: {
          kind: "ELEMENT",
          element: {
            ...fixture.element,
            inputSecurity:
              "SECRET_OR_PASSWORD",
          },
        },
      }),
    /requires P16 ORDINARY_TEXT target evidence/,
  );
});

test("P17 requires NON_REPLAYABLE X1 classification before adapter entry", async () => {
  const ctx = makeContext(
    clickRequest(),
    "SAFE_READ",
  );
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-safe-read",
      },
    ),
    /requires NON_REPLAYABLE X1 classification/,
  );
  assert.equal(calls, 0);
});

test("P17 adapter throw after entry opens X1 reconciliation instead of retrying", async () => {
  const ctx = makeContext(
    clickRequest(),
    "NON_REPLAYABLE",
    {
      async dispatch() {
        throw new Error("input dispatch uncertain");
      },
    },
  );

  const outcome = await interactGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "interaction-uncertain",
    },
  );

  assert.equal(
    outcome.receipt.status,
    "RECONCILIATION_REQUIRED",
  );
  assert.equal(
    outcome.reconciliation?.record.status,
    "OPEN",
  );
  assert.equal(
    outcome.reconciliation?.record.disposition,
    "BLOCKED_PENDING_RECONCILIATION",
  );
  assert.equal(
    outcome.reconciliation?.record.replayClass,
    "NON_REPLAYABLE",
  );
  assert.equal(outcome.result, null);
});

test("P17 malformed post-entry result also requires reconciliation", async () => {
  const ctx = makeContext(
    clickRequest(),
    "NON_REPLAYABLE",
    {
      async dispatch(adapterRequest) {
        return {
          schemaVersion:
            "toadaid.desktop-interaction-adapter-result.v1",
          preparationTicketSha256:
            adapterRequest.preparationTicket.ticketSha256,
          interactionEpoch: "wrong-epoch",
          hostId: adapterRequest.hostId,
          sessionId: adapterRequest.sessionId,
          windowId: adapterRequest.windowId,
          evidenceSha256: "1".repeat(64),
        };
      },
    },
  );

  const outcome = await interactGovernedDesktop(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "interaction-malformed",
    },
  );
  assert.equal(
    outcome.receipt.status,
    "RECONCILIATION_REQUIRED",
  );
  assert.equal(
    outcome.reconciliation?.record.status,
    "OPEN",
  );
});

test("P17 stale P15 lease head refuses before adapter entry", async () => {
  const ctx = makeContext(clickRequest());
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };
  const narrowed =
    narrowHostConnectorSessionLease(
      ctx.lease,
      {
        ownerId: "agent0",
        allowedCapabilities: [],
        updatedAt:
          "2026-09-27T03:10:01.000Z",
      },
      policy("host:session"),
      {
        now: () =>
          new Date(
            "2026-09-27T03:10:01.000Z",
          ),
      },
    );

  await assert.rejects(
    interactGovernedDesktop(
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
        randomId: () => "interaction-stale-lease",
      },
    ),
    /lease is stale/,
  );
  assert.equal(calls, 0);
});

test("P17 changed H1 arguments refuse before adapter entry", async () => {
  const ctx = makeContext(clickRequest());
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
    },
  };
  const changed: DesktopPointerClickRequest = {
    ...clickRequest(),
    clickCount: 2,
  };

  await assert.rejects(
    interactGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        request: changed,
      },
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-h1-mismatch",
      },
    ),
    /parameters do not match H1 argumentsSha256/,
  );
  assert.equal(calls, 0);
});

test("P17 Q1 preflight refuses insufficient budget before adapter entry", async () => {
  const ctx = makeContext(clickRequest());
  let calls = 0;
  const adapter: GovernedDesktopInteractionAdapter = {
    ...ctx.adapter,
    async dispatch(request) {
      calls += 1;
      return ctx.adapter.dispatch!(request);
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
    interactGovernedDesktop(
      adapter,
      {
        ...ctx.input,
        budget: tinyBudget,
      },
      {
        now: () => new Date(NOW),
        randomId: () => "interaction-no-budget",
      },
    ),
    /run budget exceeded/,
  );
  assert.equal(calls, 0);
});

test("P17 shortcut keys are bounded and normalized", () => {
  const fixture = observationFixture();
  const normalized =
    normalizeDesktopInteractionRequest({
      kind: "SHORTCUT",
      hostId: "dell7920",
      sessionId: "host-session-001",
      ownerId: "agent0",
      observation: fixture.observation,
      keys: ["ctrl", "shift", "s"],
    });
  assert.deepEqual(
    normalized.keys,
    ["CTRL", "SHIFT", "S"],
  );

  assert.throws(
    () =>
      normalizeDesktopInteractionRequest({
        kind: "SHORTCUT",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        observation: fixture.observation,
        keys: [
          "CTRL",
          "A",
          "B",
          "C",
          "D",
          "E",
          "F",
          "G",
          "H",
        ],
      }),
    /shortcut keys/,
  );

  assert.throws(
    () =>
      normalizeDesktopInteractionRequest({
        kind: "SHORTCUT",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        observation: fixture.observation,
        keys: ["A"],
      }),
    /shortcut keys/,
  );

  assert.throws(
    () =>
      normalizeDesktopInteractionRequest({
        kind: "SHORTCUT",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        observation: fixture.observation,
        keys: ["SHIFT", "A"],
      }),
    /explicit command modifier/,
  );
});
