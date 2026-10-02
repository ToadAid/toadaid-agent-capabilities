import test from "node:test";
import assert from "node:assert/strict";

import {
  assertCapabilityInvocationContractReady,
  capabilityContractDescriptorSha256,
  createCapabilityContractRegistry,
  createCapabilityInvocationContractBinding,
} from "../src/capabilityContract.js";
import {
  authorizeCapabilityInvocation,
  createCapabilityInvocation,
  startCapabilityInvocation,
} from "../src/capabilityInvocation.js";
import {
  executeGovernedConnectorInvocation,
} from "../src/connectorExecution.js";
import { connectorAdapterRegistrationSha256 } from "../src/connectorAdapter.js";
import { createCapabilityManifest } from "../src/capabilityPolicy.js";
import { sha256 } from "../src/invocationSchema.js";
import { createReplayFence } from "../src/replayFence.js";
import type {
  ConnectorAdapterRegistration,
  ConnectorJsonValue,
  GovernedConnectorAdapter,
} from "../src/connectorAdapterTypes.js";
import type {
  CapabilityContractDescriptor,
  CapabilityContractRequirement,
} from "../src/capabilityContractTypes.js";

const IMPLEMENTATION = "a".repeat(64);
const INTENT = "b".repeat(64);

const descriptor = (): CapabilityContractDescriptor => ({
  schemaVersion: "toadaid.capability-contract.v2",
  capabilityId: "connector:lookup",
  contractId: "toadaid.connector.lookup",
  version: { major: 1, minor: 0 },
  features: ["lookup.read"],
  requestSchema: { schemaId: "toadaid.connector.lookup.request.v1", schemaSha256: IMPLEMENTATION },
  resultSchema: { schemaId: "toadaid.connector.lookup.result.v1", schemaSha256: INTENT },
  receiptSchema: { schemaId: "toadaid.connector.lookup.receipt.v1", schemaSha256: "c".repeat(64) },
});

const requirement = (): CapabilityContractRequirement => ({
  capabilityId: "connector:lookup",
  contractId: "toadaid.connector.lookup",
  major: 1,
  minMinor: 0,
  requiredFeatures: ["lookup.read"],
});

const policy = () => ({
  manifest: createCapabilityManifest([
    {
      id: "connector:lookup",
      description: "fixture governed connector",
      defaultDecision: "BLOCK",
    },
  ]),
  policyLayers: [
    {
      scope: "agent" as const,
      subject: "agent0",
      decisions: { "connector:lookup": "ALLOW" as const },
    },
  ],
});

function setup(
  invocationId = "inv-connector-execution-1",
  args: Readonly<Record<string, string>> = { query: "frog" },
) {
  const registry = createCapabilityContractRegistry([descriptor()]);
  const requested = createCapabilityInvocation({
    invocationId,
    runId: "run-connector-execution-1",
    capabilityId: "connector:lookup",
    toolName: "lookup",
    intentSha256: INTENT,
    argumentsSha256: sha256(args),
    createdAt: "2026-09-26T05:10:00.000Z",
  });
  const authorized = authorizeCapabilityInvocation(
    requested,
    policy(),
    { now: () => new Date("2026-09-26T05:10:01.000Z") },
  );
  const registration: ConnectorAdapterRegistration = {
    schemaVersion: "toadaid.connector-adapter-registration.v1",
    adapterId: "fixture-lookup-adapter",
    capabilityId: "connector:lookup",
    toolName: "lookup",
    contractId: "toadaid.connector.lookup",
    descriptorSha256: capabilityContractDescriptorSha256(descriptor()),
    implementationFingerprintSha256: IMPLEMENTATION,
  };
  const binding = createCapabilityInvocationContractBinding(
    authorized,
    requirement(),
    registry,
    {
      providerDescriptorSha256: "d".repeat(64),
      adapterRegistrationSha256: connectorAdapterRegistrationSha256(registration),
      implementationFingerprintSha256: IMPLEMENTATION,
    },
  );
  const provider = {
    providerDescriptorSha256: "d".repeat(64),
    adapterRegistrationSha256: connectorAdapterRegistrationSha256(registration),
    implementationFingerprintSha256: IMPLEMENTATION,
  };
  const ready = assertCapabilityInvocationContractReady(
    binding,
    authorized,
    requirement(),
    registry,
    provider,
  );
  const replayFence = createReplayFence(
    authorized,
    {
      replayClass: "NON_REPLAYABLE",
      createdAt: "2026-09-26T05:10:01.500Z",
    },
  );
  const started = startCapabilityInvocation(
    authorized,
    "connector-manager",
    policy(),
    { now: () => new Date("2026-09-26T05:10:02.000Z") },
  );

  let currentInvocation = started;
  const invocationHeadRuntime = {
    resolveCurrentInvocationHead(
      identity: Readonly<{
        runId: string;
        invocationId: string;
      }>,
    ) {
      if (
        identity.runId !== currentInvocation.record.runId ||
        identity.invocationId !==
          currentInvocation.record.invocationId
      ) {
        return null;
      }
      return currentInvocation;
    },
    claimCurrentInvocationHead(
      expected: typeof started,
      next: typeof started,
    ) {
      if (
        currentInvocation.recordSha256 !==
        expected.recordSha256
      ) {
        return false;
      }
      currentInvocation = next;
      return true;
    },
  };

  return {
    args,
    registry,
    binding,
    ready,
    replayFence,
    started,
    invocationHeadRuntime,
    registration,
  };
}

test("P13 returns replay-fence-bound success without completing H1", async () => {
  const ctx = setup();
  let calls = 0;
  const adapter: GovernedConnectorAdapter = {
    registration: ctx.registration,
    invoke() {
      calls += 1;
      return { ok: true, provider: "fixture" };
    },
  };

  const outcome = await executeGovernedConnectorInvocation(adapter, {
    invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
    contractBinding: ctx.binding,
    contractReady: ctx.ready,
    contractRequirement: requirement(),
    contractRegistry: ctx.registry,
    arguments: ctx.args,
    replayFence: ctx.replayFence,
  });

  assert.equal(calls, 1);
  if (outcome.status !== "SUCCEEDED") {
    throw new Error("fixture expected SUCCEEDED outcome");
  }
  assert.equal(outcome.replayFenceSha256, ctx.replayFence.recordSha256);
  assert.equal(
    outcome.invocationRecordSha256,
    ctx.started.recordSha256,
  );
  assert.equal(
    outcome.invocation.recordSha256,
    ctx.started.recordSha256,
  );
  assert.equal(
    outcome.adapterReceiptSha256,
    sha256(outcome.invocationResult.receipt),
  );
  assert.deepEqual(
    outcome.invocationResult.result,
    { ok: true, provider: "fixture" },
  );
  assert.equal(ctx.started.record.status, "STARTED");
});

test("P13 refuses mismatched replay fence before adapter entry", async () => {
  const ctx = setup("inv-connector-execution-a");
  const other = setup("inv-connector-execution-b");
  let called = false;

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: other.replayFence,
      },
    ),
    /replay fence does not match H1 invocation/,
  );

  assert.equal(called, false);
});

test("P13 preserves pre-dispatch P12 refusal without opening reconciliation", async () => {
  const ctx = setup();
  let called = false;

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: { query: "substituted" },
        replayFence: ctx.replayFence,
      },
    ),
    /arguments do not match H1 argumentsSha256/,
  );

  assert.equal(called, false);
});

test("P13 refuses invalid reconciliationId before adapter entry", async () => {
  const ctx = setup();
  let called = false;

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: ctx.replayFence,
        reconciliationId: "bad reconciliation id",
      },
    ),
    /reconciliationId is invalid/,
  );

  assert.equal(called, false);
});

test("P13 refuses invalid openedAt before adapter entry", async () => {
  const ctx = setup();
  let called = false;

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: ctx.replayFence,
        openedAt: "not-a-canonical-time",
      },
    ),
    /openedAt must be canonical ISO-8601/,
  );

  assert.equal(called, false);
});

test("H1/X1B-P2 connector refuses backward reconciliation time before provider entry", async () => {
  const ctx = setup();
  let called = false;

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: ctx.replayFence,
        openedAt: "2026-09-26T05:10:01.999Z",
      },
    ),
    /earlier than active H1 predecessor/,
  );

  assert.equal(called, false);
});

test("P13 converts post-entry provider exception into X1 reconciliation", async () => {
  const ctx = setup();
  let calls = 0;

  const outcome = await executeGovernedConnectorInvocation(
    {
      registration: ctx.registration,
      invoke() {
        calls += 1;
        throw new Error("provider timeout after dispatch may have occurred");
      },
    },
    {
      invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
      contractBinding: ctx.binding,
      contractReady: ctx.ready,
      contractRequirement: requirement(),
      contractRegistry: ctx.registry,
      arguments: ctx.args,
      replayFence: ctx.replayFence,
      reconciliationId: "recon-connector-1",
      openedAt: "2026-09-26T05:10:03.000Z",
    },
  );

  assert.equal(calls, 1);
  if (outcome.status !== "RECONCILIATION_REQUIRED") {
    throw new Error("fixture expected RECONCILIATION_REQUIRED outcome");
  }
  assert.equal(outcome.errorClass, "Error");
  assert.equal(outcome.replayFenceSha256, ctx.replayFence.recordSha256);
  assert.equal(
    outcome.invocation.record.status,
    "RECONCILIATION_REQUIRED",
  );
  assert.equal(
    outcome.invocationRecordSha256,
    outcome.invocation.recordSha256,
  );
  assert.equal(
    outcome.invocation.record.reconciliation
      ?.openReconciliationSha256,
    outcome.reconciliation.recordSha256,
  );
  assert.equal(
    outcome.invocation.record.continuity
      .previousRecordSha256,
    ctx.started.recordSha256,
  );
  assert.equal(outcome.reconciliation.record.status, "OPEN");
  assert.equal(
    outcome.reconciliation.record.disposition,
    "BLOCKED_PENDING_RECONCILIATION",
  );
  assert.equal(
    outcome.reconciliation.record.reasonCode,
    "CONNECTOR_OUTCOME_UNKNOWN",
  );
  assert.equal(outcome.reconciliation.record.replayClass, "NON_REPLAYABLE");
  assert.equal(
    outcome.reconciliation.record.evidenceRefs[0]?.sha256,
    outcome.errorFingerprintSha256,
  );
  assert.equal(ctx.started.record.status, "STARTED");

  let staleCalls = 0;
  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          staleCalls += 1;
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
        invocationHeadRuntime:
          ctx.invocationHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: ctx.replayFence,
      },
    ),
    /stale relative to current H1 head/,
  );
  assert.equal(staleCalls, 0);
});

test("H1/X1B-P2 connector makes post-dispatch H1 head CAS conflict explicit", async () => {
  const ctx = setup("inv-connector-head-conflict");
  let calls = 0;
  const conflictingHeadRuntime = {
    resolveCurrentInvocationHead:
      ctx.invocationHeadRuntime.resolveCurrentInvocationHead,
    claimCurrentInvocationHead() {
      return false;
    },
  };

  await assert.rejects(
    executeGovernedConnectorInvocation(
      {
        registration: ctx.registration,
        invoke() {
          calls += 1;
          throw new Error(
            "provider outcome unknown during head race",
          );
        },
      },
      {
        invocation: ctx.started,
        invocationHeadRuntime:
          conflictingHeadRuntime,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args,
        replayFence: ctx.replayFence,
        reconciliationId:
          "recon-connector-head-conflict",
        openedAt: "2026-09-26T05:10:03.000Z",
      },
    ),
    (error: unknown) => {
      assert.equal(
        (error as { name?: string }).name,
        "CapabilityInvocationHeadConflictError",
      );
      assert.equal(
        (error as { status?: string }).status,
        "RECONCILIATION_REQUIRED",
      );
      return true;
    },
  );
  assert.equal(calls, 1);
});

test("P13 treats malformed post-entry provider result as uncertain external outcome", async () => {
  const ctx = setup();

  const adapter: GovernedConnectorAdapter = {
    registration: ctx.registration,
    invoke() {
      return undefined as unknown as ConnectorJsonValue;
    },
  };

  const outcome = await executeGovernedConnectorInvocation(adapter, {
    invocation: ctx.started,
    invocationHeadRuntime: ctx.invocationHeadRuntime,
    contractBinding: ctx.binding,
    contractReady: ctx.ready,
    contractRequirement: requirement(),
    contractRegistry: ctx.registry,
    arguments: ctx.args,
    replayFence: ctx.replayFence,
    reconciliationId: "recon-connector-malformed",
    openedAt: "2026-09-26T05:10:03.000Z",
  });

  if (outcome.status !== "RECONCILIATION_REQUIRED") {
    throw new Error("fixture expected reconciliation for malformed result");
  }
  assert.equal(
    outcome.reconciliation.record.disposition,
    "BLOCKED_PENDING_RECONCILIATION",
  );
  assert.equal(outcome.reconciliation.record.replayClass, "NON_REPLAYABLE");
});
