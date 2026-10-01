import assert from "node:assert/strict";
import test from "node:test";

import {
  capabilityContractDescriptorSha256,
} from "../src/capabilityContract.js";
import {
  assertCapabilityAvailabilityProjectionCurrent,
  composeCapabilityProviderRegistry,
  composeCapabilityAvailabilityProjection,
  composeAvailableCapabilityRuntimeProviderRegistry,
  composeCapabilityRuntimeProviderRegistry,
  createCapabilityProviderHealthReport,
  createCapabilityProviderSelection,
  resolveAvailableCapabilityProvider,
  resolveAvailableCapabilityRuntimeProvider,
  resolveCapabilityProvider,
  resolveCapabilityRuntimeProvider,
  assertCapabilityProviderRegistryCurrent,
} from "../src/capabilityProviderRegistry.js";
import {
  createCapabilityModuleManifest,
  disableCapabilityModule,
  enableCapabilityModule,
  installCapabilityModule,
  removeCapabilityModule,
} from "../src/capabilityModuleLifecycle.js";
import {
  DESKTOP_OBSERVATION_CONTRACT_IDS,
  DESKTOP_OBSERVATION_TOOL_NAMES,
} from "../src/desktopObservation.js";
import {
  DESKTOP_INTERACTION_CONTRACT_IDS,
  DESKTOP_INTERACTION_TOOL_NAMES,
} from "../src/desktopInteraction.js";
import {
  HOST_SERVICE_CONTRACT_IDS,
  HOST_SERVICE_TOOL_NAMES,
} from "../src/hostService.js";
import type {
  CapabilityContractDescriptor,
} from "../src/capabilityContractTypes.js";
import type {
  CapabilityModuleAdapterRegistration,
  CapabilityModuleLifecycleEnvelope,
} from "../src/capabilityModuleLifecycleTypes.js";
import type {
  GovernedHostServiceAdapter,
  HostServiceAdapterRegistration,
} from "../src/hostServiceTypes.js";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const SHA_C = "c".repeat(64);
const SHA_D = "d".repeat(64);

function descriptor(
  capabilityId: string,
  contractId: string,
): CapabilityContractDescriptor {
  return {
    schemaVersion: "toadaid.capability-contract.v2",
    capabilityId,
    contractId,
    version: { major: 1, minor: 0 },
    features: [],
    requestSchema: { schemaId: `${contractId}.request.v1`, schemaSha256: "1".repeat(64) },
    resultSchema: { schemaId: `${contractId}.result.v1`, schemaSha256: "2".repeat(64) },
    receiptSchema: { schemaId: `${contractId}.receipt.v1`, schemaSha256: "3".repeat(64) },
  };
}

function enabledModule(
  moduleId: string,
  capabilityId: string,
  toolName: string,
  contractId: string,
  implementationFingerprintSha256: string,
  schemaVersion: CapabilityModuleAdapterRegistration["schemaVersion"] =
    "toadaid.connector-adapter-registration.v1",
  operatingSystems?: readonly string[],
): CapabilityModuleLifecycleEnvelope {
  const contract = descriptor(
    capabilityId,
    contractId,
  );
  const registration = {
    schemaVersion,
    adapterId: `${moduleId}-adapter`,
    capabilityId,
    toolName,
    contractId,
    descriptorSha256: capabilityContractDescriptorSha256(contract),
    implementationFingerprintSha256,
  } as CapabilityModuleAdapterRegistration;
  const installed = installCapabilityModule(
    createCapabilityModuleManifest({
      moduleId,
      version: "1.0.0",
      capabilities: [{
        id: capabilityId,
        description: `Fixture capability ${capabilityId}.`,
        defaultDecision: "BLOCK",
      }],
      contractDescriptors: [contract],
      adapters: [registration],
      ...(operatingSystems ? {
        providerPlatformRequirements: [{
          adapterId: `${moduleId}-adapter`,
          requirements: { operatingSystems },
        }],
      } : {}),
    }),
    { installedAt: "2026-09-30T12:00:00.000Z" },
  );
  return enableCapabilityModule(
    installed,
    "2026-09-30T12:01:00.000Z",
  );
}

const HOST = Object.freeze({
  hostId: "host-1",
  sessionId: "session-1",
  hostSessionLeaseSha256: SHA_D,
  operatingSystem: "linux",
  architecture: "x64",
  runtimeIds: ["node-24"],
});

function providerFor(module: CapabilityModuleLifecycleEnvelope) {
  return composeCapabilityProviderRegistry({ modules: [module] }).providers[0]!;
}

function healthy(
  module: CapabilityModuleLifecycleEnvelope,
  generation = SHA_C,
  status: "AVAILABLE_HEALTHY" | "AVAILABLE_DEGRADED" | "UNAVAILABLE" = "AVAILABLE_HEALTHY",
) {
  return createCapabilityProviderHealthReport(providerFor(module), HOST, {
    providerGenerationSha256: generation,
    status,
    observedAt: "2026-09-30T12:01:30.000Z",
    expiresAt: "2026-09-30T12:10:00.000Z",
  });
}

test("P14B composes every typed provider registration kind", () => {
  const specs = [
    {
      capabilityId: "connector:lookup",
      toolName: "lookup",
      contractId: "toadaid.connector.lookup",
      adapterId: "fixture-connector",
      schemaVersion: "toadaid.connector-adapter-registration.v1" as const,
      fingerprint: SHA_A,
    },
    {
      capabilityId: "host:screenshot",
      toolName: DESKTOP_OBSERVATION_TOOL_NAMES["host:screenshot"],
      contractId: DESKTOP_OBSERVATION_CONTRACT_IDS["host:screenshot"],
      adapterId: "fixture-observation",
      schemaVersion: "toadaid.desktop-observation-adapter-registration.v1" as const,
      fingerprint: SHA_B,
    },
    {
      capabilityId: "host:pointer-click",
      toolName: DESKTOP_INTERACTION_TOOL_NAMES["host:pointer-click"],
      contractId: DESKTOP_INTERACTION_CONTRACT_IDS["host:pointer-click"],
      adapterId: "fixture-interaction",
      schemaVersion: "toadaid.desktop-interaction-adapter-registration.v1" as const,
      fingerprint: SHA_C,
    },
    {
      capabilityId: "host:file-read",
      toolName: HOST_SERVICE_TOOL_NAMES["host:file-read"],
      contractId: HOST_SERVICE_CONTRACT_IDS["host:file-read"],
      adapterId: "fixture-host-service",
      schemaVersion: "toadaid.host-service-adapter-registration.v1" as const,
      fingerprint: SHA_D,
    },
  ];
  const descriptors = specs.map((item) =>
    descriptor(
      item.capabilityId,
      item.contractId,
    )
  );
  const manifest = createCapabilityModuleManifest({
    moduleId: "fixture.multi-provider",
    version: "1.0.0",
    capabilities: specs.map((item) => ({
      id: item.capabilityId,
      description: `Fixture capability ${item.capabilityId}.`,
      defaultDecision: "BLOCK" as const,
    })),
    contractDescriptors: descriptors,
    adapters: specs.map((item, index) => ({
      schemaVersion: item.schemaVersion,
      adapterId: item.adapterId,
      capabilityId: item.capabilityId,
      toolName: item.toolName,
      contractId: item.contractId,
      descriptorSha256: capabilityContractDescriptorSha256(descriptors[index]!),
      implementationFingerprintSha256: item.fingerprint,
    })) as readonly CapabilityModuleAdapterRegistration[],
  });
  const enabled = enableCapabilityModule(
    installCapabilityModule(manifest, {
      installedAt: "2026-09-30T12:00:00.000Z",
    }),
    "2026-09-30T12:01:00.000Z",
  );

  const registry = composeCapabilityProviderRegistry({ modules: [enabled] });
  assert.deepEqual(
    registry.providers.map((item) => item.adapterKind).sort(),
    [
      "CONNECTOR",
      "DESKTOP_INTERACTION",
      "DESKTOP_OBSERVATION",
      "HOST_SERVICE",
    ],
  );
  assert.equal(registry.enabledCapabilityManifest.capabilities.length, 4);
  assert.equal(
    resolveCapabilityProvider(
      registry,
      "host:file-read",
      HOST_SERVICE_TOOL_NAMES["host:file-read"],
      "HOST_SERVICE",
    ).adapterId,
    "fixture-host-service",
  );
});

test("P14B duplicate active bindings require an exact provider selection", () => {
  const first = enabledModule(
    "fixture.lookup-a",
    "connector:lookup",
    "lookup",
    "toadaid.connector.lookup",
    SHA_A,
  );
  const second = enabledModule(
    "fixture.lookup-b",
    "connector:lookup",
    "lookup",
    "toadaid.connector.lookup",
    SHA_B,
  );

  assert.throws(
    () => composeCapabilityProviderRegistry({ modules: [first, second] }),
    /require explicit selection/,
  );
  const selection = createCapabilityProviderSelection(second, "fixture.lookup-b-adapter");
  const registry = composeCapabilityProviderRegistry({
    modules: [first, second],
    selections: [selection],
  });
  assert.equal(registry.providers.length, 1);
  assert.equal(registry.providers[0]?.moduleId, "fixture.lookup-b");
});

test("P14B rejects stale selection and registry state after lifecycle change", () => {
  const enabled = enabledModule(
    "fixture.lookup",
    "connector:lookup",
    "lookup",
    "toadaid.connector.lookup",
    SHA_A,
  );
  const selection = createCapabilityProviderSelection(enabled, "fixture.lookup-adapter");
  const registry = composeCapabilityProviderRegistry({
    modules: [enabled],
    selections: [selection],
  });
  const disabled = disableCapabilityModule(
    enabled,
    "2026-09-30T12:02:00.000Z",
  );
  assert.throws(
    () => assertCapabilityProviderRegistryCurrent(registry, [disabled]),
    /no enabled candidate/,
  );
  const reenabled = enableCapabilityModule(
    disabled,
    "2026-09-30T12:03:00.000Z",
  );
  assert.throws(
    () => composeCapabilityProviderRegistry({
      modules: [reenabled],
      selections: [selection],
    }),
    /stale or mismatched/,
  );
});

test("P14B keeps known, installed, and enabled capability truth distinct", () => {
  const enabled = enabledModule(
    "fixture.enabled",
    "connector:enabled",
    "enabled",
    "toadaid.connector.enabled",
    SHA_A,
  );
  const disabled = disableCapabilityModule(
    enabledModule(
      "fixture.disabled",
      "connector:disabled",
      "disabled",
      "toadaid.connector.disabled",
      SHA_B,
    ),
    "2026-09-30T12:02:00.000Z",
  );
  const removedBase = disableCapabilityModule(
    enabledModule(
      "fixture.removed",
      "connector:removed",
      "removed",
      "toadaid.connector.removed",
      SHA_C,
    ),
    "2026-09-30T12:02:00.000Z",
  );
  const removed = removeCapabilityModule(
    removedBase,
    {
      observedOwnedResources: [],
      removedAt: "2026-09-30T12:03:00.000Z",
    },
  );
  const registry = composeCapabilityProviderRegistry({
    modules: [enabled, disabled, removed],
  });
  assert.deepEqual(
    registry.knownCapabilityManifest.capabilities.map((item) => item.id),
    ["connector:disabled", "connector:enabled", "connector:removed"],
  );
  assert.deepEqual(
    registry.installedCapabilityManifest.capabilities.map((item) => item.id),
    ["connector:disabled", "connector:enabled"],
  );
  assert.deepEqual(
    registry.enabledCapabilityManifest.capabilities.map((item) => item.id),
    ["connector:enabled"],
  );
  assert.equal(registry.providers.length, 1);
});

test("P14B refuses legacy and structured host aliases in one active registry", () => {
  const legacy = enabledModule(
    "fixture.legacy-file",
    "host:filesystem-read",
    "filesystem.read",
    "toadaid.host.filesystem-read",
    SHA_A,
  );
  const structured = enabledModule(
    "fixture.structured-file",
    "host:file-read",
    "host.file-read",
    "toadaid.host.file-read",
    SHA_B,
  );
  assert.throws(
    () => composeCapabilityProviderRegistry({ modules: [legacy, structured] }),
    /ambiguous legacy\/structured/,
  );
});

test("P14B dispatch resolution is kind-bound and integrity checked", () => {
  const enabled = enabledModule(
    "fixture.lookup",
    "connector:lookup",
    "lookup",
    "toadaid.connector.lookup",
    SHA_A,
  );
  const registry = composeCapabilityProviderRegistry({ modules: [enabled] });
  assert.throws(
    () => resolveCapabilityProvider(
      registry,
      "connector:lookup",
      "lookup",
      "HOST_SERVICE",
    ),
    /kind mismatch/,
  );
  assert.throws(
    () => resolveCapabilityProvider(
      { ...registry, registrySha256: SHA_D },
      "connector:lookup",
      "lookup",
    ),
    /integrity mismatch/,
  );
});

test("P14B composes exact typed runtime implementations for dispatch", () => {
  const enabled = enabledModule(
    "fixture.notification",
    "host:notification",
    HOST_SERVICE_TOOL_NAMES["host:notification"],
    HOST_SERVICE_CONTRACT_IDS["host:notification"],
    SHA_A,
    "toadaid.host-service-adapter-registration.v1",
  );
  const registry = composeCapabilityProviderRegistry({ modules: [enabled] });
  const registration = enabled.record.manifest.adapters[0] as
    HostServiceAdapterRegistration;
  const provider: GovernedHostServiceAdapter = {
    registration,
    async invoke(request) {
      return {
        schemaVersion: "toadaid.host-service-adapter-result.v1",
        operationId: request.operationId,
        hostId: request.hostId,
        sessionId: request.sessionId,
        capabilityId: request.capabilityId,
        evidenceSha256: SHA_D,
      };
    },
  };
  const runtimeRegistry = composeCapabilityRuntimeProviderRegistry(
    registry,
    [enabled],
    [{ moduleId: "fixture.notification", provider }],
  );
  assert.equal(
    resolveCapabilityRuntimeProvider(
      runtimeRegistry,
      registry,
      "host:notification",
      HOST_SERVICE_TOOL_NAMES["host:notification"],
      "HOST_SERVICE",
    ),
    provider,
  );
  assert.throws(
    () => composeCapabilityRuntimeProviderRegistry(registry, [enabled], []),
    /implementation is unavailable/,
  );
  assert.throws(
    () => composeCapabilityRuntimeProviderRegistry(
      registry,
      [enabled],
      [{ moduleId: "wrong.module", provider }],
    ),
    /not the exact selected provider/,
  );
});

test("P19 separates known, installed, enabled, available, and authorized truth", () => {
  const enabled = enabledModule(
    "fixture.available",
    "connector:available",
    "available",
    "toadaid.connector.available",
    SHA_A,
  );
  const disabled = disableCapabilityModule(enabledModule(
    "fixture.disabled-p19",
    "connector:disabled-p19",
    "disabled-p19",
    "toadaid.connector.disabled-p19",
    SHA_B,
  ), "2026-09-30T12:02:00.000Z");
  const projection = composeCapabilityAvailabilityProjection({
    modules: [enabled, disabled],
    knownCapabilities: [{ id: "connector:catalog-only", description: "Catalog only.", defaultDecision: "BLOCK" }],
    builtInCapabilities: [{ id: "browser:evidence", description: "Built-in browser evidence.", defaultDecision: "BLOCK" }],
    host: HOST,
    healthReports: [healthy(enabled)],
    policyLayers: [{ scope: "agent", subject: "agent0", decisions: { "connector:available": "ALLOW" } }],
    checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.deepEqual(projection.knownCapabilityManifest.capabilities.map((item) => item.id), [
    "browser:evidence", "connector:available", "connector:catalog-only", "connector:disabled-p19",
  ]);
  assert.deepEqual(projection.installedCapabilityManifest.capabilities.map((item) => item.id), [
    "browser:evidence", "connector:available", "connector:disabled-p19",
  ]);
  assert.deepEqual(projection.enabledCapabilityManifest.capabilities.map((item) => item.id), [
    "browser:evidence", "connector:available",
  ]);
  assert.deepEqual(projection.availableCapabilityManifest.capabilities.map((item) => item.id), ["connector:available"]);
  assert.deepEqual(projection.authorizedCapabilityManifest.capabilities.map((item) => item.id), ["connector:available"]);
  assert.equal(projection.providers[0]?.status, "AVAILABLE_HEALTHY");
  assert.equal(projection.providers[0]?.authority.decision, "ALLOW");
});

test("P19 filters for current host compatibility before requiring duplicate selection", () => {
  const linux = enabledModule(
    "fixture.linux", "connector:lookup", "lookup", "toadaid.connector.lookup", SHA_A,
    "toadaid.connector-adapter-registration.v1", ["linux"],
  );
  const windows = enabledModule(
    "fixture.windows", "connector:lookup", "lookup", "toadaid.connector.lookup", SHA_B,
    "toadaid.connector-adapter-registration.v1", ["windows"],
  );
  const oneCompatible = composeCapabilityAvailabilityProjection({
    modules: [linux, windows], host: HOST, healthReports: [healthy(linux)],
    checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.equal(resolveAvailableCapabilityProvider(oneCompatible, "connector:lookup", "lookup").provider.moduleId, "fixture.linux");
  assert.equal(oneCompatible.unavailableProviders[0]?.reason, "PLATFORM_INCOMPATIBLE");

  const linuxTwo = enabledModule(
    "fixture.linux-two", "connector:lookup", "lookup", "toadaid.connector.lookup", SHA_C,
    "toadaid.connector-adapter-registration.v1", ["linux"],
  );
  assert.throws(() => composeCapabilityAvailabilityProjection({
    modules: [linux, linuxTwo], host: HOST,
    healthReports: [healthy(linux), healthy(linuxTwo, SHA_D)],
    checkedAt: "2026-09-30T12:02:00.000Z",
  }), /require explicit selection/);
  const selection = createCapabilityProviderSelection(linuxTwo, "fixture.linux-two-adapter");
  const selected = composeCapabilityAvailabilityProjection({
    modules: [linux, linuxTwo], host: HOST, selections: [selection],
    healthReports: [healthy(linux), healthy(linuxTwo, SHA_D)],
    checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.equal(selected.providers[0]?.provider.moduleId, "fixture.linux-two");
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(selected, {
    modules: [linux, linuxTwo], host: HOST,
    selections: [createCapabilityProviderSelection(linux, "fixture.linux-adapter")],
    healthReports: [healthy(linux), healthy(linuxTwo, SHA_D)],
    checkedAt: "2026-09-30T12:02:00.000Z",
  }), /stale or mismatched/);
});

test("P19 provider health is non-authority and missing, expired, or unavailable health fails closed", () => {
  const enabled = enabledModule(
    "fixture.health", "connector:health", "health", "toadaid.connector.health", SHA_A,
  );
  const degraded = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [healthy(enabled, SHA_C, "AVAILABLE_DEGRADED")],
    checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.equal(degraded.providers[0]?.status, "AVAILABLE_DEGRADED");
  assert.equal(degraded.providers[0]?.authority.decision, "BLOCK");
  assert.equal(degraded.authorizedCapabilityManifest.capabilities.length, 0);

  const missing = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [], checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.equal(missing.providers.length, 0);
  assert.equal(missing.unavailableProviders[0]?.status, "UNAVAILABLE");
  assert.equal(missing.unavailableProviders[0]?.reason, "HEALTH_MISSING");
  const unavailable = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [healthy(enabled, SHA_C, "UNAVAILABLE")],
    checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.equal(unavailable.unavailableProviders[0]?.reason, "PROVIDER_REPORTED_UNAVAILABLE");
  const expired = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [healthy(enabled)],
    checkedAt: "2026-09-30T12:11:00.000Z",
  });
  assert.equal(expired.unavailableProviders[0]?.reason, "HEALTH_EXPIRED");
  assert.throws(() => composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST,
    healthReports: [{ ...healthy(enabled), providerGenerationSha256: SHA_B }],
    checkedAt: "2026-09-30T12:02:00.000Z",
  }), /health integrity mismatch/);
  assert.throws(() => composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [healthy(enabled)],
    checkedAt: "2026-09-30T12:01:00.000Z",
  }), /from the future/);
});

test("P19 restart, host-session change, health change, and module disable invalidate stale projections", () => {
  const enabled = enabledModule(
    "fixture.restart", "connector:restart", "restart", "toadaid.connector.restart", SHA_A,
  );
  const report = healthy(enabled, SHA_A);
  const input = {
    modules: [enabled], host: HOST, healthReports: [report],
    checkedAt: "2026-09-30T12:02:00.000Z",
  } as const;
  const projection = composeCapabilityAvailabilityProjection(input);
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    healthReports: [],
  }), /stale or mismatched/);
  assert.throws(() => composeCapabilityAvailabilityProjection({
    ...input,
    host: { ...HOST, sessionId: "session-2" },
  }), /no current enabled host-bound provider/);
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    healthReports: [healthy(enabled, SHA_B)],
  }), /stale or mismatched/);
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    healthReports: [healthy(enabled, SHA_A, "AVAILABLE_DEGRADED")],
  }), /stale or mismatched/);
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    host: { ...HOST, sessionId: "session-2" },
    healthReports: [],
  }), /stale or mismatched/);
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    modules: [disableCapabilityModule(enabled, "2026-09-30T12:03:00.000Z")],
    healthReports: [],
  }), /stale or mismatched/);
  const disabled = disableCapabilityModule(enabled, "2026-09-30T12:03:00.000Z");
  const removed = removeCapabilityModule(disabled, {
    observedOwnedResources: [],
    removedAt: "2026-09-30T12:04:00.000Z",
  });
  assert.throws(() => assertCapabilityAvailabilityProjectionCurrent(projection, {
    ...input,
    modules: [removed],
    healthReports: [],
  }), /stale or mismatched/);
});

test("P19 runtime dispatch is bound to availability projection and provider generation", () => {
  const enabled = enabledModule(
    "fixture.p19-notification", "host:notification",
    HOST_SERVICE_TOOL_NAMES["host:notification"], HOST_SERVICE_CONTRACT_IDS["host:notification"], SHA_A,
    "toadaid.host-service-adapter-registration.v1",
  );
  const report = healthy(enabled, SHA_A);
  const projection = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [report], checkedAt: "2026-09-30T12:02:00.000Z",
  });
  const registration = enabled.record.manifest.adapters[0] as HostServiceAdapterRegistration;
  const provider: GovernedHostServiceAdapter = {
    registration,
    async invoke(request) {
      return { schemaVersion: "toadaid.host-service-adapter-result.v1", operationId: request.operationId, hostId: request.hostId, sessionId: request.sessionId, capabilityId: request.capabilityId, evidenceSha256: SHA_D };
    },
  };
  const runtime = composeAvailableCapabilityRuntimeProviderRegistry(projection, [{ moduleId: "fixture.p19-notification", provider }]);
  assert.equal(resolveAvailableCapabilityRuntimeProvider(runtime, projection, "host:notification", HOST_SERVICE_TOOL_NAMES["host:notification"], "HOST_SERVICE"), provider);
  const restarted = composeCapabilityAvailabilityProjection({
    modules: [enabled], host: HOST, healthReports: [healthy(enabled, SHA_B)], checkedAt: "2026-09-30T12:02:00.000Z",
  });
  assert.throws(() => resolveAvailableCapabilityRuntimeProvider(runtime, restarted, "host:notification", HOST_SERVICE_TOOL_NAMES["host:notification"], "HOST_SERVICE"), /projection mismatch/);
});
