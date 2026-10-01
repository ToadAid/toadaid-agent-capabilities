import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_CAPABILITY_MANIFEST,
  resolveCapabilityAuthority,
} from "../src/capabilityPolicy.js";
import type { CapabilityPolicyLayer } from "../src/capabilityPolicy.js";
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
  HOST_SERVICE_CONTRACT_IDS,
  HOST_SERVICE_TOOL_NAMES,
  hostServiceAdapterRegistrationSha256,
  hostServiceParametersSha256,
  invokeGovernedHostService,
  normalizeHostPathScope,
  normalizeHostRegistryScope,
  normalizeHostServiceRequest,
} from "../src/hostService.js";
import type {
  GovernedHostServiceAdapter,
  HostFileReadRequest,
  HostFileWriteRequest,
  HostServiceAdapterRegistration,
  HostServiceCapabilityId,
  HostServiceRequest,
} from "../src/hostServiceTypes.js";
import {
  createHostConnectorSessionLease,
  narrowHostConnectorSessionLease,
} from "../src/hostConnectorSessionLease.js";
import { createReplayFence } from "../src/replayFence.js";
import { createRunBudgetLedger } from "../src/runBudgetLedger.js";
import type { RunBudgetVector } from "../src/runBudgetTypes.js";

const NOW = "2026-09-27T04:00:00.000Z";
const IMPL_SHA = "a".repeat(64);
const INTENT_SHA = "b".repeat(64);

function policy(capabilityId: string, allow = true) {
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

function limits(): RunBudgetVector {
  return {
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 20,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 600_000,
    childTasks: 0,
  };
}

function requiredFeatures(request: HostServiceRequest): readonly string[] {
  const n = normalizeHostServiceRequest(request);
  const out = [
    "least-privilege-host-service",
    "bounded-result-evidence",
  ];
  if (n.mutation) out.push("x1-reconciled-mutation");
  if (n.kind === "FILE_READ" || n.kind === "FILE_WRITE") {
    out.push("realpath-scope-enforced");
  }
  if (n.kind === "APP_LAUNCH" || n.kind === "COMMAND_EXEC") {
    out.push(
      "structured-exec-no-shell",
      "structured-exec-explicit-context",
    );
  }
  if (n.kind === "PROCESS_STOP") {
    out.push("process-identity-evidence-enforced");
  }
  return out;
}

function fileRead(): HostFileReadRequest {
  return {
    kind: "FILE_READ",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: {
      root: "/home/tommy/projects",
      path: "/home/tommy/projects/demo/README.md",
    },
    maxBytes: 8_192,
    maxWallClockMs: 5_000,
  };
}

function fileWrite(): HostFileWriteRequest {
  return {
    kind: "FILE_WRITE",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: {
      root: "/home/tommy/projects",
      path: "/home/tommy/projects/demo/out.txt",
    },
    contentRef: "blob-ref-001",
    contentSha256: "6".repeat(64),
    byteLength: 12,
    mode: "CREATE_NEW",
    maxWallClockMs: 5_000,
  };
}

function context(
  request: HostServiceRequest,
  replayClass:
    | "SAFE_READ"
    | "IDEMPOTENT_WRITE"
    | "NON_REPLAYABLE"
    | null = null,
  adapterOverrides: Partial<GovernedHostServiceAdapter> = {},
  featureOverride?: readonly string[],
) {
  const n = normalizeHostServiceRequest(request);
  const capabilityId = n.capabilityId;
  const toolName = HOST_SERVICE_TOOL_NAMES[capabilityId];
  const contractId = HOST_SERVICE_CONTRACT_IDS[capabilityId];
  const features = featureOverride ?? requiredFeatures(request);

  const descriptor = {
    schemaVersion: "toadaid.capability-contract.v2" as const,
    capabilityId,
    contractId,
    version: { major: 1, minor: 0 },
    features,
    requestSchema: { schemaId: "toadaid.host-service-request", schemaSha256: "8".repeat(64) },
    resultSchema: { schemaId: "toadaid.host-service-result", schemaSha256: "9".repeat(64) },
    receiptSchema: { schemaId: "toadaid.host-service-receipt", schemaSha256: "a".repeat(64) },
  };
  const registration: HostServiceAdapterRegistration = {
    schemaVersion: "toadaid.host-service-adapter-registration.v1",
    adapterId: "host-service-test-adapter",
    capabilityId,
    toolName,
    contractId,
    descriptorSha256: capabilityContractDescriptorSha256(descriptor),
    implementationFingerprintSha256: IMPL_SHA,
  };
  const registry = createCapabilityContractRegistry([descriptor]);
  const requirement = {
    capabilityId,
    contractId,
    major: 1,
    minMinor: 0,
    requiredFeatures: features,
  };
  const compatibility =
    assertCapabilityContractCompatible(registry, requirement);

  const argsSha = hostServiceParametersSha256(request);
  const preStart = createCapabilityInvocation({
    invocationId: "host-service-invocation-001",
    runId: "run-001",
    capabilityId,
    toolName,
    intentSha256: INTENT_SHA,
    argumentsSha256: argsSha,
    createdAt: NOW,
  });
  const replayFence =
    replayClass === null
      ? undefined
      : createReplayFence(
          preStart,
          { replayClass, createdAt: NOW },
          { now: () => new Date(NOW) },
        );

  const invocation = sealCapabilityInvocationRecord({
    schemaVersion: "toadaid.capability-invocation.v1",
    invocationId: "host-service-invocation-001",
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
      argumentsSha256: argsSha,
    },
    authorization: {
      checkedAt: NOW,
      decision: "ALLOW",
      reason: "AUTHORIZED_BY_POLICY",
      decisionSha256: "c".repeat(64),
    },
    start: {
      startedAt: NOW,
      managerId: "host-service-manager",
    },
    cancellation: null,
    outcome: null,
    continuity: {
      previousRecordSha256: "d".repeat(64),
    },
  });

  const binding =
    createCapabilityInvocationContractBinding(
      invocation,
      requirement,
      registry,
      {
        providerDescriptorSha256: "b".repeat(64),
        adapterRegistrationSha256: hostServiceAdapterRegistrationSha256(registration),
        implementationFingerprintSha256: IMPL_SHA,
      },
    );
  const contractReady = {
    schemaVersion:
      "toadaid.capability-invocation-contract-ready.v1" as const,
    invocationId: invocation.record.invocationId,
    capabilityId,
    bindingSha256: binding.bindingSha256,
    provider: {
      providerDescriptorSha256: binding.providerDescriptorSha256,
      adapterRegistrationSha256: binding.adapterRegistrationSha256,
      implementationFingerprintSha256: binding.implementationFingerprintSha256,
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

  const baseAdapter: GovernedHostServiceAdapter = {
    registration,
    async invoke(req) {
      return {
        schemaVersion: "toadaid.host-service-adapter-result.v1",
        operationId: req.operationId,
        hostId: req.hostId,
        sessionId: req.sessionId,
        capabilityId: req.capabilityId,
        evidenceSha256: "1".repeat(64),
        payload: { ok: true },
      };
    },
  };
  const adapter = {
    ...baseAdapter,
    ...adapterOverrides,
  } as GovernedHostServiceAdapter;

  const budget = createRunBudgetLedger(
    {
      budgetId: "budget-host-service-001",
      runId: "run-001",
      createdAt: NOW,
      limits: limits(),
    },
    { now: () => new Date(NOW) },
  );

  return {
    lease,
    replayFence,
    adapter,
    budget,
    input: {
      lease,
      leaseRuntime: {
        now: () => new Date(NOW),
        resolveCurrentLeaseSha256: () => lease.leaseSha256,
      },
      sessionAuthority: policy("host:session"),
      actionAuthority: policy(capabilityId),
      invocation,
      contractBinding: binding,
      contractReady,
      contractRequirement: requirement,
      contractRegistry: registry,
      ...(replayFence === undefined ? {} : { replayFence }),
      budget,
      request,
    },
  };
}

test("P18 installs eleven narrow host-service capabilities BLOCK by default", () => {
  const ids: readonly HostServiceCapabilityId[] = [
    "host:app-launch",
    "host:clipboard-read",
    "host:clipboard-write",
    "host:process-read",
    "host:process-stop",
    "host:file-read",
    "host:file-write",
    "host:notification",
    "host:registry-read",
    "host:registry-write",
    "host:command-exec",
  ];
  for (const id of ids) {
    const decision = policy(id, false);
    assert.equal(decision.installed, true);
    assert.equal(decision.decision, "BLOCK");
    assert.equal(decision.reason, "MANIFEST_DEFAULT");
  }
});

test("P18 filesystem scope canonicalizes POSIX/Windows paths and refuses escape", () => {
  const posix = normalizeHostPathScope({
    root: "/home/tommy/projects",
    path: "/home/tommy/projects/demo/a.txt",
  }) as Record<string, unknown>;
  assert.equal(posix.style, "POSIX");
  assert.equal(posix.symlinkPolicy, "REFUSE_ESCAPE");

  const windows = normalizeHostPathScope({
    root: "C:\\Users\\Tommy\\Work",
    path: "C:\\Users\\Tommy\\Work\\Demo\\a.txt",
  }) as Record<string, unknown>;
  assert.equal(windows.style, "WINDOWS");

  assert.throws(
    () =>
      normalizeHostPathScope({
        root: "/home/tommy/projects",
        path: "/home/tommy/secrets.txt",
      }),
    /escapes/,
  );
});

test("P18 file read crosses P15/P3/C1/H1/Q1 and raw payload stays outside receipt", async () => {
  const ctx = context(fileRead());
  const outcome = await invokeGovernedHostService(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-read-001",
    },
  );
  assert.equal(outcome.receipt.status, "OK");
  assert.equal(outcome.receipt.capabilityId, "host:file-read");
  assert.equal(outcome.receipt.replayFenceSha256, null);
  assert.deepEqual(outcome.result?.payload, { ok: true });
  assert.equal(JSON.stringify(outcome.receipt).includes('"ok":true'), false);
  assert.equal(outcome.receipt.budget.reservedCost.toolCalls, 1);
});

test("P18 file contracts require realpath-scope C1 feature", async () => {
  const ctx = context(
    fileRead(),
    null,
    {},
    ["least-privilege-host-service", "bounded-result-evidence"],
  );
  let calls = 0;
  const adapter: GovernedHostServiceAdapter = {
    ...ctx.adapter,
    async invoke(req) {
      calls += 1;
      return ctx.adapter.invoke(req);
    },
  };
  await assert.rejects(
    invokeGovernedHostService(
      adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-missing-feature",
      },
    ),
    /missing mandatory feature: realpath-scope-enforced/,
  );
  assert.equal(calls, 0);
});

test("P18 mutations require X1 write classification and uncertain writes reconcile", async () => {
  const noFence = context(fileWrite());
  await assert.rejects(
    invokeGovernedHostService(
      noFence.adapter,
      noFence.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-write-no-fence",
      },
    ),
    /requires X1 replay fence/,
  );

  const safeRead = context(fileWrite(), "SAFE_READ");
  await assert.rejects(
    invokeGovernedHostService(
      safeRead.adapter,
      safeRead.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-write-safe-read",
      },
    ),
    /require NON_REPLAYABLE X1/,
  );

  const uncertain = context(
    fileWrite(),
    "NON_REPLAYABLE",
    {
      async invoke() {
        throw new Error("write outcome uncertain");
      },
    },
  );
  const outcome = await invokeGovernedHostService(
    uncertain.adapter,
    uncertain.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-write-uncertain",
    },
  );
  assert.equal(outcome.receipt.status, "RECONCILIATION_REQUIRED");
  assert.equal(outcome.reconciliation?.record.status, "OPEN");
});

test("P18 structured command exec has absolute executable, argv, bounded cwd/env, shell=false and no elevation", () => {
  const normalized = normalizeHostServiceRequest({
    kind: "COMMAND_EXEC",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    executable: "/usr/bin/git",
    argv: ["status", "--short"],
    cwd: {
      root: "/home/tommy/projects",
      path: "/home/tommy/projects/demo",
    },
    env: [
      {
        name: "LANG",
        valueRef: "env-ref-lang",
        valueSha256: "2".repeat(64),
      },
    ],
  });
  const details = normalized.details as Record<string, unknown>;
  assert.equal(details.executable, "/usr/bin/git");
  assert.equal(details.shell, false);
  assert.equal(details.elevation, "NONE");
  assert.equal(details.inheritEnv, false);

  assert.throws(
    () =>
      normalizeHostServiceRequest({
        kind: "COMMAND_EXEC",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        executable: "git",
        cwd: {
          root: "/home/tommy/projects",
          path: "/home/tommy/projects/demo",
        },
      }),
    /explicit absolute path/,
  );

  assert.throws(
    () =>
      normalizeHostServiceRequest({
        kind: "COMMAND_EXEC",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        executable: "\\\\server\\share\\tool.exe",
        cwd: {
          root: "C:\\Users\\Tommy\\Work",
          path: "C:\\Users\\Tommy\\Work\\Demo",
        },
      }),
    /refuses UNC\/device executable paths/,
  );
});

test("P18 process stop requires fresh identity evidence and adapter enforcement", async () => {
  assert.throws(
    () =>
      normalizeHostServiceRequest({
        kind: "PROCESS_STOP",
        hostId: "dell7920",
        sessionId: "host-session-001",
        ownerId: "agent0",
        pid: 42,
        processEvidenceSha256: "bad",
        processObservedAt: NOW,
      }),
    /processEvidenceSha256/,
  );

  const request: HostServiceRequest = {
    kind: "PROCESS_STOP",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    pid: 42,
    processEvidenceSha256: "3".repeat(64),
    processObservedAt: NOW,
    maxEvidenceAgeMs: 5_000,
  };
  const ctx = context(request, "NON_REPLAYABLE");
  const outcome = await invokeGovernedHostService(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-stop",
    },
  );
  assert.equal(outcome.receipt.status, "OK");

  const staleRequest: HostServiceRequest = {
    ...request,
    processObservedAt: "2026-09-27T03:59:50.000Z",
  };
  const stale = context(staleRequest, "NON_REPLAYABLE");
  await assert.rejects(
    invokeGovernedHostService(
      stale.adapter,
      stale.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-stop-stale",
      },
    ),
    /stale or from the future/,
  );

  const missingFeature = context(
    request,
    "NON_REPLAYABLE",
    {},
    [
      "least-privilege-host-service",
      "bounded-result-evidence",
      "x1-reconciled-mutation",
    ],
  );
  await assert.rejects(
    invokeGovernedHostService(
      missingFeature.adapter,
      missingFeature.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-stop-missing-feature",
      },
    ),
    /missing mandatory feature: process-identity-evidence-enforced/,
  );
});

test("P18 registry root scope is bounded and read/write authority is distinct", () => {
  const scope = normalizeHostRegistryScope({
    hive: "HKCU",
    rootKeyPath: "Software\\ToadAid",
    keyPath: "Software\\ToadAid\\Agent",
  }) as Record<string, unknown>;
  assert.equal(scope.relativeKeyPath, "Agent");

  assert.throws(
    () =>
      normalizeHostRegistryScope({
        hive: "HKCU",
        rootKeyPath: "Software\\ToadAid",
        keyPath: "Software\\Other",
      }),
    /escapes/,
  );

  const read = normalizeHostServiceRequest({
    kind: "REGISTRY_READ",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: {
      hive: "HKCU",
      rootKeyPath: "Software\\ToadAid",
      keyPath: "Software\\ToadAid\\Agent",
    },
  });
  const write = normalizeHostServiceRequest({
    kind: "REGISTRY_WRITE",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    scope: {
      hive: "HKCU",
      rootKeyPath: "Software\\ToadAid",
      keyPath: "Software\\ToadAid\\Agent",
    },
    valueName: "Mode",
    valueType: "STRING",
    valueRef: "registry-value-ref",
    valueSha256: "4".repeat(64),
    byteLength: 4,
  });
  assert.equal(read.capabilityId, "host:registry-read");
  assert.equal(write.capabilityId, "host:registry-write");
});

test("P18 clipboard read/write are distinct; adapter gets opaque ref while receipt stays hash-only", async () => {
  const read = normalizeHostServiceRequest({
    kind: "CLIPBOARD_READ",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    format: "text/plain",
  });
  const write = normalizeHostServiceRequest({
    kind: "CLIPBOARD_WRITE",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    format: "text/plain",
    contentRef: "clipboard-ref-001",
    contentSha256: "5".repeat(64),
    byteLength: 12,
    contentClass: "ORDINARY_TEXT",
  });
  assert.equal(read.capabilityId, "host:clipboard-read");
  assert.equal(write.capabilityId, "host:clipboard-write");
  assert.equal(JSON.stringify(write).includes("clipboard-ref-001"), true);

  const request: HostServiceRequest = {
    kind: "CLIPBOARD_WRITE",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    format: "text/plain",
    contentRef: "clipboard-ref-001",
    contentSha256: "5".repeat(64),
    byteLength: 12,
    contentClass: "ORDINARY_TEXT",
  };
  let adapterSawRef = false;
  const ctx = context(
    request,
    "NON_REPLAYABLE",
    {
      async invoke(req) {
        adapterSawRef =
          JSON.stringify(req.parameters).includes("clipboard-ref-001");
        return {
          schemaVersion: "toadaid.host-service-adapter-result.v1",
          operationId: req.operationId,
          hostId: req.hostId,
          sessionId: req.sessionId,
          capabilityId: req.capabilityId,
          evidenceSha256: "1".repeat(64),
          payload: { ok: true },
        };
      },
    },
  );
  const outcome = await invokeGovernedHostService(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-clipboard-write",
    },
  );
  assert.equal(adapterSawRef, true);
  assert.equal(
    JSON.stringify(outcome.receipt).includes("clipboard-ref-001"),
    false,
  );
});

test("P18 read adapter failure degrades without reconciliation", async () => {
  const ctx = context(fileRead(), null, {
    async invoke() {
      throw new Error("read failed");
    },
  });
  const outcome = await invokeGovernedHostService(
    ctx.adapter,
    ctx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-read-failed",
    },
  );
  assert.equal(outcome.receipt.status, "DEGRADED");
  assert.equal(outcome.reconciliation, null);
});

test("P18 optional read fence must be exact SAFE_READ for the same invocation", async () => {
  const ctx = context(fileRead(), "NON_REPLAYABLE");
  await assert.rejects(
    invokeGovernedHostService(
      ctx.adapter,
      ctx.input,
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-read-wrong-fence",
      },
    ),
    /read-only host service accepts only SAFE_READ/,
  );
});

test("P18 runtime payload preserves write refs and notification text while receipt keeps hashes only", async () => {
  const writeCtx = context(
    fileWrite(),
    "NON_REPLAYABLE",
    {
      async invoke(req) {
        const details = req.parameters.details as Record<string, unknown>;
        assert.equal(details.contentRef, "blob-ref-001");
        return {
          schemaVersion: "toadaid.host-service-adapter-result.v1",
          operationId: req.operationId,
          hostId: req.hostId,
          sessionId: req.sessionId,
          capabilityId: req.capabilityId,
          evidenceSha256: "1".repeat(64),
          payload: { ok: true },
        };
      },
    },
  );
  const writeOutcome = await invokeGovernedHostService(
    writeCtx.adapter,
    writeCtx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-file-write-ref",
    },
  );
  assert.equal(
    JSON.stringify(writeOutcome.receipt).includes("blob-ref-001"),
    false,
  );

  const notification: HostServiceRequest = {
    kind: "NOTIFICATION",
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
    title: "ToadAid",
    body: "Task finished",
  };
  const notificationCtx = context(
    notification,
    "NON_REPLAYABLE",
    {
      async invoke(req) {
        const details = req.parameters.details as Record<string, unknown>;
        assert.equal(details.title, "ToadAid");
        assert.equal(details.body, "Task finished");
        return {
          schemaVersion: "toadaid.host-service-adapter-result.v1",
          operationId: req.operationId,
          hostId: req.hostId,
          sessionId: req.sessionId,
          capabilityId: req.capabilityId,
          evidenceSha256: "1".repeat(64),
          payload: { ok: true },
        };
      },
    },
  );
  const notificationOutcome = await invokeGovernedHostService(
    notificationCtx.adapter,
    notificationCtx.input,
    {
      now: () => new Date(NOW),
      randomId: () => "host-service-notification",
    },
  );
  assert.equal(
    JSON.stringify(notificationOutcome.receipt).includes("Task finished"),
    false,
  );
});

test("P18 stale P15 lease refuses before adapter entry", async () => {
  const ctx = context(fileRead());
  let calls = 0;
  const adapter: GovernedHostServiceAdapter = {
    ...ctx.adapter,
    async invoke(req) {
      calls += 1;
      return ctx.adapter.invoke(req);
    },
  };
  const narrowed = narrowHostConnectorSessionLease(
    ctx.lease,
    {
      ownerId: "agent0",
      allowedCapabilities: [],
      updatedAt: "2026-09-27T04:00:01.000Z",
    },
    policy("host:session"),
    {
      now: () => new Date("2026-09-27T04:00:01.000Z"),
    },
  );

  await assert.rejects(
    invokeGovernedHostService(
      adapter,
      {
        ...ctx.input,
        leaseRuntime: {
          now: () => new Date(NOW),
          resolveCurrentLeaseSha256: () => narrowed.leaseSha256,
        },
      },
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-stale-lease",
      },
    ),
    /lease is stale/,
  );
  assert.equal(calls, 0);
});

test("P18 changed H1 arguments and insufficient Q1 budget refuse before adapter entry", async () => {
  const ctx = context(fileRead());
  let calls = 0;
  const adapter: GovernedHostServiceAdapter = {
    ...ctx.adapter,
    async invoke(req) {
      calls += 1;
      return ctx.adapter.invoke(req);
    },
  };

  await assert.rejects(
    invokeGovernedHostService(
      adapter,
      {
        ...ctx.input,
        request: {
          ...fileRead(),
          maxBytes: 4_096,
        },
      },
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-h1-mismatch",
      },
    ),
    /H1 identity\/arguments mismatch/,
  );

  const tiny = createRunBudgetLedger(
    {
      budgetId: "budget-host-service-tiny",
      runId: "run-001",
      createdAt: NOW,
      limits: {
        ...limits(),
        toolCalls: 0,
        wallClockMs: 0,
      },
    },
    { now: () => new Date(NOW) },
  );
  await assert.rejects(
    invokeGovernedHostService(
      adapter,
      {
        ...ctx.input,
        budget: tiny,
      },
      {
        now: () => new Date(NOW),
        randomId: () => "host-service-no-budget",
      },
    ),
    /run budget exceeded/,
  );
  assert.equal(calls, 0);
});

test("P18 app-launch and notification are mutations, process/clipboard/file/registry reads are reads", () => {
  const common = {
    hostId: "dell7920",
    sessionId: "host-session-001",
    ownerId: "agent0",
  } as const;

  assert.equal(
    normalizeHostServiceRequest({
      ...common,
      kind: "APP_LAUNCH",
      executable: "/usr/bin/xdg-open",
      cwd: {
        root: "/home/tommy/projects",
        path: "/home/tommy/projects/demo",
      },
    }).mutation,
    true,
  );
  assert.equal(
    normalizeHostServiceRequest({
      ...common,
      kind: "NOTIFICATION",
      title: "ToadAid",
      body: "Task finished",
    }).mutation,
    true,
  );
  assert.equal(
    normalizeHostServiceRequest({
      ...common,
      kind: "PROCESS_READ",
    }).mutation,
    false,
  );
  assert.equal(
    normalizeHostServiceRequest({
      ...common,
      kind: "CLIPBOARD_READ",
      format: "text/plain",
    }).mutation,
    false,
  );
});
