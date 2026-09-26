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
  connectorAdapterRegistrationSha256,
  invokeGovernedConnectorAdapter,
} from "../src/connectorAdapter.js";
import { createCapabilityManifest } from "../src/capabilityPolicy.js";
import { sha256 } from "../src/invocationSchema.js";
import type {
  ConnectorAdapterRegistration,
  ConnectorJsonObject,
  GovernedConnectorAdapter,
} from "../src/connectorAdapterTypes.js";
import type {
  CapabilityContractDescriptor,
  CapabilityContractRequirement,
} from "../src/capabilityContractTypes.js";

const IMPLEMENTATION = "a".repeat(64);
const INTENT = "b".repeat(64);

const descriptor = (): CapabilityContractDescriptor => ({
  schemaVersion: "toadaid.capability-contract.v1",
  capabilityId: "connector:lookup",
  contractId: "toadaid.connector.lookup",
  version: { major: 1, minor: 0 },
  features: ["lookup.read"],
  requestSchemaId: "toadaid.connector.lookup.request.v1",
  receiptSchemaId: "toadaid.connector.lookup.receipt.v1",
  implementation: {
    implementationId: "fixture-lookup-adapter",
    fingerprintSha256: IMPLEMENTATION,
  },
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

function setup(args: Readonly<Record<string, unknown>> = { query: "frog" }) {
  const registry = createCapabilityContractRegistry([descriptor()]);
  const requested = createCapabilityInvocation({
    invocationId: "inv-connector-1",
    runId: "run-connector-1",
    capabilityId: "connector:lookup",
    toolName: "lookup",
    intentSha256: INTENT,
    argumentsSha256: sha256(args),
    createdAt: "2026-09-25T22:00:00.000Z",
  });
  const authorized = authorizeCapabilityInvocation(
    requested,
    policy(),
    { now: () => new Date("2026-09-25T22:00:01.000Z") },
  );
  const binding = createCapabilityInvocationContractBinding(
    authorized,
    requirement(),
    registry,
  );
  const ready = assertCapabilityInvocationContractReady(
    binding,
    authorized,
    requirement(),
    registry,
  );
  const started = startCapabilityInvocation(
    authorized,
    "connector-manager",
    policy(),
    { now: () => new Date("2026-09-25T22:00:02.000Z") },
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
  return { args, registry, authorized, binding, ready, started, registration };
}

test("P12 invokes exact STARTED H1 + current C1-bound adapter", async () => {
  const ctx = setup();
  let calls = 0;
  const adapter: GovernedConnectorAdapter = {
    registration: ctx.registration,
    invoke(request) {
      calls += 1;
      assert.equal(Object.isFrozen(request), true);
      assert.equal(Object.isFrozen(request.arguments), true);
      const query = (request.arguments as Readonly<Record<string, string>>).query;
      if (typeof query !== "string") throw new Error("fixture query must be a string");
      return {
        ok: true,
        query,
      };
    },
  };

  const output = await invokeGovernedConnectorAdapter(adapter, {
    invocation: ctx.started,
    contractBinding: ctx.binding,
    contractReady: ctx.ready,
    contractRequirement: requirement(),
    contractRegistry: ctx.registry,
    arguments: ctx.args as Readonly<Record<string, string>>,
  });

  assert.equal(calls, 1);
  assert.deepEqual(output.result, { ok: true, query: "frog" });
  assert.equal(output.receipt.invocationId, "inv-connector-1");
  assert.equal(output.receipt.bindingSha256, ctx.binding.bindingSha256);
  assert.equal(
    output.receipt.registrationSha256,
    connectorAdapterRegistrationSha256(ctx.registration),
  );
  assert.equal(output.receipt.resultSha256, sha256(output.result));
  assert.equal("rawResult" in output.receipt, false);
});

test("P12 preserves prototype-named JSON keys as inert data", async () => {
  const args = JSON.parse(
    '{"__proto__":{"polluted":true},"query":"frog"}',
  ) as ConnectorJsonObject;
  const ctx = setup(args);
  let sawPrototypeKey = false;

  const adapter: GovernedConnectorAdapter = {
    registration: ctx.registration,
    invoke(request) {
      assert.equal(Object.isFrozen(request.arguments), true);
      assert.equal(Object.prototype.hasOwnProperty.call(request.arguments, "__proto__"), true);
      assert.deepEqual(
        (request.arguments as Readonly<Record<string, unknown>>)["__proto__"],
        { polluted: true },
      );
      sawPrototypeKey = true;
      return JSON.parse('{"__proto__":{"provider":"ok"},"ok":true}');
    },
  };

  const output = await invokeGovernedConnectorAdapter(adapter, {
    invocation: ctx.started,
    contractBinding: ctx.binding,
    contractReady: ctx.ready,
    contractRequirement: requirement(),
    contractRegistry: ctx.registry,
    arguments: args,
  });

  assert.equal(sawPrototypeKey, true);
  assert.equal(Object.prototype.hasOwnProperty.call(output.result, "__proto__"), true);
  assert.deepEqual(
    (output.result as Readonly<Record<string, unknown>>)["__proto__"],
    { provider: "ok" },
  );
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
  assert.equal(output.receipt.resultSha256, sha256(output.result));
});

test("P12 refuses call before H1 STARTED", async () => {
  const ctx = setup();
  let called = false;
  await assert.rejects(
    invokeGovernedConnectorAdapter(
      {
        registration: ctx.registration,
        invoke() {
          called = true;
          return { ok: true };
        },
      },
      {
        invocation: ctx.authorized,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args as Readonly<Record<string, string>>,
      },
    ),
    /requires STARTED H1 invocation/,
  );
  assert.equal(called, false);
});

test("P12 refuses substituted tool identity", async () => {
  const ctx = setup();
  await assert.rejects(
    invokeGovernedConnectorAdapter(
      {
        registration: { ...ctx.registration, toolName: "other" },
        invoke() {
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args as Readonly<Record<string, string>>,
      },
    ),
    /does not match H1 capability\/tool identity/,
  );
});

test("P12 refuses argument substitution after H1 request binding", async () => {
  const ctx = setup();
  await assert.rejects(
    invokeGovernedConnectorAdapter(
      {
        registration: ctx.registration,
        invoke() {
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: { query: "different" },
      },
    ),
    /arguments do not match H1 argumentsSha256/,
  );
});

test("P12 refuses implementation drift after C1 proof", async () => {
  const ctx = setup();
  await assert.rejects(
    invokeGovernedConnectorAdapter(
      {
        registration: {
          ...ctx.registration,
          implementationFingerprintSha256: "c".repeat(64),
        },
        invoke() {
          return { ok: true };
        },
      },
      {
        invocation: ctx.started,
        contractBinding: ctx.binding,
        contractReady: ctx.ready,
        contractRequirement: requirement(),
        contractRegistry: ctx.registry,
        arguments: ctx.args as Readonly<Record<string, string>>,
      },
    ),
    /implementation fingerprint changed/,
  );
});
