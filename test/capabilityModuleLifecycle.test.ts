import assert from "node:assert/strict";
import test from "node:test";

import {
  capabilityContractDescriptorSha256,
} from "../src/capabilityContract.js";
import {
  resolveCapabilityAuthority,
} from "../src/capabilityPolicy.js";
import {
  assertCapabilityModuleOwnedResourcesClean,
  assertCapabilityModulePredecessor,
  assertCapabilityModuleRegistrationProjectionCurrent,
  createCapabilityModuleManifest,
  disableCapabilityModule,
  enableCapabilityModule,
  installCapabilityModule,
  parseCapabilityModuleLifecycle,
  projectEnabledCapabilityModule,
  removeCapabilityModule,
  serializeCapabilityModuleLifecycle,
  updateCapabilityModule,
  validateCapabilityModuleLifecycleEnvelope,
} from "../src/capabilityModuleLifecycle.js";
import type {
  CapabilityContractDescriptor,
} from "../src/capabilityContractTypes.js";

const IMPLEMENTATION_V1 = "a".repeat(64);
const IMPLEMENTATION_V2 = "b".repeat(64);
const RESOURCE_V1 = "c".repeat(64);
const RESOURCE_V2 = "d".repeat(64);
const INSPECTION_SHA = "e".repeat(64);

function descriptor(
  implementationFingerprintSha256 = IMPLEMENTATION_V1,
): CapabilityContractDescriptor {
  return {
    schemaVersion: "toadaid.capability-contract.v1",
    capabilityId: "connector:lookup",
    contractId: "toadaid.connector.lookup",
    version: { major: 1, minor: 0 },
    features: ["lookup.read"],
    requestSchemaId: "toadaid.connector.lookup.request.v1",
    receiptSchemaId: "toadaid.connector.lookup.receipt.v1",
    implementation: {
      implementationId: "fixture-lookup-adapter",
      fingerprintSha256: implementationFingerprintSha256,
    },
  };
}

function moduleManifest(
  version = "1.0.0",
  implementationFingerprintSha256 = IMPLEMENTATION_V1,
  resourceFingerprintSha256 = RESOURCE_V1,
) {
  const contract = descriptor(implementationFingerprintSha256);
  return createCapabilityModuleManifest({
    moduleId: "fixture.lookup-module",
    version,
    capabilities: [
      {
        id: "connector:lookup",
        description: "Fixture lookup connector.",
        defaultDecision: "BLOCK",
      },
    ],
    contractDescriptors: [contract],
    adapters: [
      {
        schemaVersion: "toadaid.connector-adapter-registration.v1",
        adapterId: "fixture-lookup-adapter",
        capabilityId: "connector:lookup",
        toolName: "lookup",
        contractId: contract.contractId,
        descriptorSha256: capabilityContractDescriptorSha256(contract),
        implementationFingerprintSha256,
      },
    ],
    ownedResources: [
      {
        resourceId: "lookup-runtime",
        fingerprintSha256: resourceFingerprintSha256,
      },
    ],
  });
}

function cleanObserved(
  fingerprintSha256 = RESOURCE_V1,
) {
  return [
    {
      resourceId: "lookup-runtime",
      fingerprintSha256,
    },
  ] as const;
}

test("P14 installs disabled and installation does not grant P3 authority", () => {
  const manifest = moduleManifest();
  const installed = installCapabilityModule(manifest, {
    inspectionEvidenceRefs: [
      { id: "security-scan", sha256: INSPECTION_SHA },
    ],
    installedAt: "2026-09-26T05:50:00.000Z",
  });

  assert.equal(installed.record.state, "INSTALLED_DISABLED");
  assert.equal(installed.record.transition, "INSTALL");
  assert.equal(installed.record.inspectionEvidenceRefs.length, 1);

  const authority = resolveCapabilityAuthority(
    "connector:lookup",
    manifest.capabilityManifest,
    [],
  );
  assert.equal(authority.installed, true);
  assert.equal(authority.decision, "BLOCK");
});

test("P14 refuses module capability defaults that would grant ambient authority", () => {
  assert.throws(
    () => createCapabilityModuleManifest({
      moduleId: "unsafe.module",
      version: "1.0.0",
      capabilities: [
        {
          id: "connector:lookup",
          description: "Unsafe default.",
          defaultDecision: "ALLOW",
        },
      ],
    }),
    /defaults must be BLOCK/,
  );
});

test("P14 binds P12 adapter identity to exact C1 descriptor", () => {
  const contract = descriptor();
  assert.throws(
    () => createCapabilityModuleManifest({
      moduleId: "bad.adapter-module",
      version: "1.0.0",
      capabilities: [
        {
          id: "connector:lookup",
          description: "Fixture lookup connector.",
          defaultDecision: "BLOCK",
        },
      ],
      contractDescriptors: [contract],
      adapters: [
        {
          schemaVersion: "toadaid.connector-adapter-registration.v1",
          adapterId: "fixture-lookup-adapter",
          capabilityId: "connector:lookup",
          toolName: "lookup",
          contractId: contract.contractId,
          descriptorSha256: "f".repeat(64),
          implementationFingerprintSha256: IMPLEMENTATION_V1,
        },
      ],
    }),
    /does not match C1 descriptor/,
  );
});

test("P14 enabled projection still requires independent P3 ALLOW", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });
  const enabled = enableCapabilityModule(
    installed,
    "2026-09-26T05:51:00.000Z",
  );
  const projection = projectEnabledCapabilityModule(enabled);

  const blocked = resolveCapabilityAuthority(
    "connector:lookup",
    projection.capabilityManifest,
    [],
  );
  assert.equal(blocked.decision, "BLOCK");

  const allowed = resolveCapabilityAuthority(
    "connector:lookup",
    projection.capabilityManifest,
    [
      {
        scope: "agent",
        subject: "agent0",
        decisions: { "connector:lookup": "ALLOW" },
      },
    ],
  );
  assert.equal(allowed.decision, "ALLOW");
  assert.equal(projection.adapters.length, 1);
});

test("P14 enabled projection is exact-lifecycle-bound and stale after disable/re-enable", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });
  const enabled = enableCapabilityModule(
    installed,
    "2026-09-26T05:51:00.000Z",
  );
  const projection = projectEnabledCapabilityModule(enabled);

  assert.equal(projection.lifecycleRecordSha256, enabled.recordSha256);
  assert.doesNotThrow(
    () => assertCapabilityModuleRegistrationProjectionCurrent(
      projection,
      enabled,
    ),
  );

  const disabled = disableCapabilityModule(
    enabled,
    "2026-09-26T05:52:00.000Z",
  );
  assert.throws(
    () => assertCapabilityModuleRegistrationProjectionCurrent(
      projection,
      disabled,
    ),
    /requires current ENABLED state/,
  );

  const reenabled = enableCapabilityModule(
    disabled,
    "2026-09-26T05:53:00.000Z",
  );
  assert.throws(
    () => assertCapabilityModuleRegistrationProjectionCurrent(
      projection,
      reenabled,
    ),
    /stale or tampered/,
  );

  const freshProjection = projectEnabledCapabilityModule(reenabled);
  assert.doesNotThrow(
    () => assertCapabilityModuleRegistrationProjectionCurrent(
      freshProjection,
      reenabled,
    ),
  );
});

test("P14 canonical module capabilities strip misleading ambient metadata", () => {
  const contract = descriptor();
  const manifest = createCapabilityModuleManifest({
    moduleId: "canonical.lookup-module",
    version: "1.0.0",
    capabilities: [
      {
        id: "connector:lookup",
        description: "Fixture lookup connector.",
        defaultDecision: "BLOCK",
        authority: "ALLOW",
      } as unknown as {
        id: string;
        description: string;
        defaultDecision: "BLOCK";
      },
    ],
    contractDescriptors: [contract],
  });

  const capability = manifest.capabilityManifest.capabilities[0]!;
  assert.equal("authority" in capability, false);
  assert.deepEqual(Object.keys(capability).sort(), [
    "defaultDecision",
    "description",
    "id",
  ]);
});

test("P14 update requires disabled module and clean exact owned-resource state", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });
  const enabled = enableCapabilityModule(
    installed,
    "2026-09-26T05:51:00.000Z",
  );

  assert.throws(
    () => updateCapabilityModule(
      enabled,
      moduleManifest("1.1.0", IMPLEMENTATION_V2, RESOURCE_V2),
      {
        observedOwnedResources: cleanObserved(),
        updatedAt: "2026-09-26T05:52:00.000Z",
      },
    ),
    /must be disabled before update/,
  );

  const disabled = disableCapabilityModule(
    enabled,
    "2026-09-26T05:52:00.000Z",
  );
  assert.throws(
    () => updateCapabilityModule(
      disabled,
      moduleManifest("1.1.0", IMPLEMENTATION_V2, RESOURCE_V2),
      {
        observedOwnedResources: cleanObserved("9".repeat(64)),
        updatedAt: "2026-09-26T05:53:00.000Z",
      },
    ),
    /dirty or conflicted/,
  );
});

test("P14 clean update produces predecessor-bound disabled lifecycle state", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });
  const nextManifest = moduleManifest(
    "1.1.0",
    IMPLEMENTATION_V2,
    RESOURCE_V2,
  );

  const updated = updateCapabilityModule(
    installed,
    nextManifest,
    {
      observedOwnedResources: cleanObserved(),
      inspectionEvidenceRefs: [
        { id: "upgrade-scan", sha256: INSPECTION_SHA },
      ],
      updatedAt: "2026-09-26T05:51:00.000Z",
    },
  );

  assert.equal(updated.record.state, "INSTALLED_DISABLED");
  assert.equal(updated.record.transition, "UPDATE");
  assert.equal(updated.record.manifest.version, "1.1.0");
  assert.equal(updated.record.inspectionEvidenceRefs.length, 1);
  assert.doesNotThrow(
    () => assertCapabilityModulePredecessor(installed, updated),
  );
});

test("P14 removal exposes only exact module-owned resource ids", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });

  const removed = removeCapabilityModule(
    installed,
    {
      observedOwnedResources: cleanObserved(),
      removedAt: "2026-09-26T05:51:00.000Z",
    },
  );

  assert.equal(removed.record.state, "REMOVED");
  assert.deepEqual(
    removed.record.removalResourceIds,
    ["lookup-runtime"],
  );
  assert.throws(
    () => projectEnabledCapabilityModule(removed),
    /must be enabled/,
  );
  assert.throws(
    () => enableCapabilityModule(
      removed,
      "2026-09-26T05:52:00.000Z",
    ),
    /removed capability module cannot transition/,
  );
});

test("P14 exact owned-resource guard refuses missing or unrelated resources", () => {
  const manifest = moduleManifest();

  assert.throws(
    () => assertCapabilityModuleOwnedResourcesClean(manifest, []),
    /dirty or incomplete/,
  );

  assert.throws(
    () => assertCapabilityModuleOwnedResourcesClean(manifest, [
      ...cleanObserved(),
      {
        resourceId: "unrelated-host-state",
        fingerprintSha256: "1".repeat(64),
      },
    ]),
    /dirty or incomplete/,
  );
});

test("P14 lifecycle serialization preserves canonical state and strips unknown envelope fields", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });
  const serialized = JSON.stringify({
    ...JSON.parse(serializeCapabilityModuleLifecycle(installed)),
    authority: {
      capabilityId: "connector:lookup",
      decision: "ALLOW",
    },
  });

  const parsed = parseCapabilityModuleLifecycle(serialized);
  assert.equal("authority" in parsed, false);
  assert.deepEqual(parsed, installed);
});

test("P14 lifecycle tampering fails closed", () => {
  const installed = installCapabilityModule(moduleManifest(), {
    installedAt: "2026-09-26T05:50:00.000Z",
  });

  const tampered = {
    ...installed,
    record: {
      ...installed.record,
      state: "INSTALLED_ENABLED" as const,
    },
  };

  assert.throws(
    () => validateCapabilityModuleLifecycleEnvelope(tampered),
    /initial module lifecycle record is invalid/,
  );
});
