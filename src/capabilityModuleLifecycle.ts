import {
  createCapabilityManifest,
} from "./capabilityPolicy.js";
import {
  capabilityContractDescriptorSha256,
  createCapabilityProviderImplementationDescriptor,
  createCapabilityContractRegistry,
  validateCapabilityContractRegistry,
  validateCapabilityProviderImplementationDescriptor,
} from "./capabilityContract.js";
import {
  connectorAdapterRegistrationSha256,
  normalizeConnectorAdapterRegistration,
} from "./connectorAdapter.js";
import {
  desktopObservationAdapterRegistrationSha256,
  normalizeDesktopObservationAdapterRegistration,
} from "./desktopObservation.js";
import {
  desktopInteractionAdapterRegistrationSha256,
  normalizeDesktopInteractionAdapterRegistration,
} from "./desktopInteraction.js";
import {
  hostServiceAdapterRegistrationSha256,
  normalizeHostServiceAdapterRegistration,
} from "./hostService.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  CapabilityDefinition,
} from "./capabilityPolicy.js";
import type {
  CapabilityContractDescriptor,
  CapabilityImplementationAdapterKind,
  CapabilityProviderImplementationDescriptor,
} from "./capabilityContractTypes.js";
import type {
  CapabilityModuleAdapterRegistration,
  CapabilityModuleInspectionEvidenceRef,
  CapabilityModuleLifecycleEnvelope,
  CapabilityModuleLifecycleRecord,
  CapabilityModuleManifest,
  CapabilityModuleOwnedResource,
  CapabilityModuleProviderPlatformDeclaration,
  CapabilityModuleRegistrationProjection,
  CapabilityModuleRuntime,
  CapabilityModuleState,
  CapabilityModuleTransition,
  CreateCapabilityModuleManifestInput,
  InstallCapabilityModuleInput,
  RemoveCapabilityModuleInput,
  UpdateCapabilityModuleInput,
} from "./capabilityModuleLifecycleTypes.js";

export type * from "./capabilityModuleLifecycleTypes.js";

const MODULE_VERSION_PATTERN =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/;
const MAX_REVISION = 1_000_000;
const MAX_INSPECTION_REFS = 64;
const MAX_OWNED_RESOURCES = 256;

const MODULE_STATES: readonly CapabilityModuleState[] = [
  "INSTALLED_DISABLED",
  "INSTALLED_ENABLED",
  "REMOVED",
];
const MODULE_TRANSITIONS: readonly CapabilityModuleTransition[] = [
  "INSTALL",
  "ENABLE",
  "DISABLE",
  "UPDATE",
  "REMOVE",
];

function normalizeModuleVersion(version: string): string {
  if (typeof version !== "string" || !MODULE_VERSION_PATTERN.test(version)) {
    throw new TypeError("module version is invalid");
  }
  return version;
}

function normalizeCapabilityDefinitions(
  definitions: readonly CapabilityDefinition[],
): readonly CapabilityDefinition[] {
  const knownFields = definitions.map((definition) => Object.freeze({
    id: definition.id,
    description: definition.description,
    defaultDecision: definition.defaultDecision,
  }));
  const sorted = knownFields.sort((a, b) => a.id.localeCompare(b.id));
  for (const definition of sorted) {
    if (definition.defaultDecision !== "BLOCK") {
      throw new Error(
        `module capability defaults must be BLOCK: ${definition.id}`,
      );
    }
  }
  return createCapabilityManifest(sorted).capabilities;
}

function normalizeOwnedResources(
  resources: readonly CapabilityModuleOwnedResource[] | undefined,
): readonly CapabilityModuleOwnedResource[] {
  const values = resources ?? [];
  if (values.length > MAX_OWNED_RESOURCES) {
    throw new RangeError(
      `ownedResources exceeds ${MAX_OWNED_RESOURCES} entries`,
    );
  }

  const seen = new Set<string>();
  const normalized = values.map((resource, index) => {
    const resourceId = boundedId(
      resource.resourceId,
      `ownedResources[${index}].resourceId`,
    );
    if (seen.has(resourceId)) {
      throw new TypeError(`duplicate owned resource id: ${resourceId}`);
    }
    seen.add(resourceId);
    return Object.freeze({
      resourceId,
      fingerprintSha256: sha(
        resource.fingerprintSha256,
        `ownedResources[${index}].fingerprintSha256`,
      )!,
    });
  });

  normalized.sort((a, b) => a.resourceId.localeCompare(b.resourceId));
  return Object.freeze(normalized);
}

function normalizeInspectionEvidence(
  refs: readonly CapabilityModuleInspectionEvidenceRef[] | undefined,
): readonly CapabilityModuleInspectionEvidenceRef[] {
  const values = refs ?? [];
  if (values.length > MAX_INSPECTION_REFS) {
    throw new RangeError(
      `inspectionEvidenceRefs exceeds ${MAX_INSPECTION_REFS} entries`,
    );
  }

  const seen = new Set<string>();
  const normalized = values.map((ref, index) => {
    const id = boundedId(ref.id, `inspectionEvidenceRefs[${index}].id`);
    if (seen.has(id)) {
      throw new TypeError(`duplicate inspection evidence id: ${id}`);
    }
    seen.add(id);
    return Object.freeze({
      id,
      sha256: sha(
        ref.sha256,
        `inspectionEvidenceRefs[${index}].sha256`,
      )!,
    });
  });

  normalized.sort((a, b) => a.id.localeCompare(b.id));
  return Object.freeze(normalized);
}

export function normalizeCapabilityModuleAdapterRegistration(
  adapter: CapabilityModuleAdapterRegistration,
): CapabilityModuleAdapterRegistration {
  switch (adapter.schemaVersion) {
    case "toadaid.connector-adapter-registration.v1":
      return normalizeConnectorAdapterRegistration(adapter);
    case "toadaid.desktop-observation-adapter-registration.v1":
      return normalizeDesktopObservationAdapterRegistration(adapter);
    case "toadaid.desktop-interaction-adapter-registration.v1":
      return normalizeDesktopInteractionAdapterRegistration(adapter);
    case "toadaid.host-service-adapter-registration.v1":
      return normalizeHostServiceAdapterRegistration(adapter);
    default:
      throw new TypeError("unsupported capability module adapter registration schemaVersion");
  }
}

function moduleAdapterKind(
  adapter: CapabilityModuleAdapterRegistration,
): CapabilityImplementationAdapterKind {
  switch (adapter.schemaVersion) {
    case "toadaid.connector-adapter-registration.v1": return "CONNECTOR";
    case "toadaid.desktop-observation-adapter-registration.v1": return "DESKTOP_OBSERVATION";
    case "toadaid.desktop-interaction-adapter-registration.v1": return "DESKTOP_INTERACTION";
    case "toadaid.host-service-adapter-registration.v1": return "HOST_SERVICE";
  }
}

function moduleAdapterRegistrationSha256(
  adapter: CapabilityModuleAdapterRegistration,
): string {
  switch (adapter.schemaVersion) {
    case "toadaid.connector-adapter-registration.v1": return connectorAdapterRegistrationSha256(adapter);
    case "toadaid.desktop-observation-adapter-registration.v1": return desktopObservationAdapterRegistrationSha256(adapter);
    case "toadaid.desktop-interaction-adapter-registration.v1": return desktopInteractionAdapterRegistrationSha256(adapter);
    case "toadaid.host-service-adapter-registration.v1": return hostServiceAdapterRegistrationSha256(adapter);
  }
}

function createModuleProviderImplementations(
  moduleId: string,
  adapters: readonly CapabilityModuleAdapterRegistration[],
  descriptors: readonly CapabilityContractDescriptor[],
  declarations: readonly CapabilityModuleProviderPlatformDeclaration[] | undefined,
): readonly CapabilityProviderImplementationDescriptor[] {
  const requirementsByAdapter = new Map<string, CapabilityModuleProviderPlatformDeclaration["requirements"]>();
  for (const declaration of declarations ?? []) {
    const adapterId = boundedId(declaration.adapterId, "providerPlatformRequirements.adapterId");
    if (requirementsByAdapter.has(adapterId)) {
      throw new TypeError(`duplicate provider platform declaration: ${adapterId}`);
    }
    requirementsByAdapter.set(adapterId, declaration.requirements);
  }
  const descriptorByCapability = new Map(
    descriptors.map((descriptor) => [descriptor.capabilityId, descriptor]),
  );
  const providers = adapters.map((adapter) => {
    const descriptor = descriptorByCapability.get(adapter.capabilityId);
    if (!descriptor) throw new Error(`module adapter has no C1 descriptor: ${adapter.capabilityId}`);
    const requirements = requirementsByAdapter.get(adapter.adapterId);
    requirementsByAdapter.delete(adapter.adapterId);
    return createCapabilityProviderImplementationDescriptor({
      moduleId,
      providerId: `${moduleId}/${adapter.adapterId}`,
      adapterKind: moduleAdapterKind(adapter),
      adapterId: adapter.adapterId,
      capabilityId: adapter.capabilityId,
      contractId: adapter.contractId,
      contractVersion: descriptor.version,
      contractDescriptorSha256: capabilityContractDescriptorSha256(descriptor),
      supportedFeatures: descriptor.features,
      ...(requirements ? { platformRequirements: requirements } : {}),
      adapterRegistrationSha256: moduleAdapterRegistrationSha256(adapter),
      implementationFingerprintSha256: adapter.implementationFingerprintSha256,
    });
  });
  if (requirementsByAdapter.size > 0) {
    throw new Error(`provider platform declaration references unknown adapter: ${requirementsByAdapter.keys().next().value}`);
  }
  providers.sort((a, b) => a.providerId.localeCompare(b.providerId));
  return Object.freeze(providers);
}

function normalizeAdapters(
  adapters: readonly CapabilityModuleAdapterRegistration[] | undefined,
): readonly CapabilityModuleAdapterRegistration[] {
  const seenIds = new Set<string>();
  const seenBindings = new Set<string>();
  const normalized = (adapters ?? []).map((adapter) => {
    const value = normalizeCapabilityModuleAdapterRegistration(adapter);
    if (seenIds.has(value.adapterId)) {
      throw new TypeError(`duplicate module adapter id: ${value.adapterId}`);
    }
    seenIds.add(value.adapterId);

    const binding = `${value.capabilityId}\u0000${value.toolName}`;
    if (seenBindings.has(binding)) {
      throw new TypeError(
        `duplicate module capability/tool binding: ${value.capabilityId}/${value.toolName}`,
      );
    }
    seenBindings.add(binding);
    return value;
  });
  normalized.sort((a, b) => a.adapterId.localeCompare(b.adapterId));
  return Object.freeze(normalized);
}

function assertModuleCrossBindings(
  capabilities: readonly CapabilityDefinition[],
  descriptors: readonly CapabilityContractDescriptor[],
  adapters: readonly CapabilityModuleAdapterRegistration[],
): void {
  const capabilityIds = new Set(capabilities.map((item) => item.id));
  const descriptorByCapability = new Map(
    descriptors.map((descriptor) => [descriptor.capabilityId, descriptor]),
  );

  for (const descriptor of descriptors) {
    if (!capabilityIds.has(descriptor.capabilityId)) {
      throw new Error(
        `module contract references undeclared capability: ${descriptor.capabilityId}`,
      );
    }
  }

  for (const adapter of adapters) {
    if (!capabilityIds.has(adapter.capabilityId)) {
      throw new Error(
        `module adapter references undeclared capability: ${adapter.capabilityId}`,
      );
    }
    const descriptor = descriptorByCapability.get(adapter.capabilityId);
    if (!descriptor) {
      throw new Error(
        `module adapter has no C1 descriptor: ${adapter.capabilityId}`,
      );
    }
    if (
      adapter.contractId !== descriptor.contractId ||
      adapter.descriptorSha256 !==
        capabilityContractDescriptorSha256(descriptor)
    ) {
      throw new Error(
        `module adapter does not match C1 descriptor: ${adapter.adapterId}`,
      );
    }
  }
}

function capabilityModuleManifestCore(
  moduleId: string,
  version: string,
  capabilities: readonly CapabilityDefinition[],
  contractDescriptors: readonly CapabilityContractDescriptor[],
  adapters: readonly CapabilityModuleAdapterRegistration[],
  providerPlatformRequirements: readonly CapabilityModuleProviderPlatformDeclaration[] | undefined,
  ownedResources: readonly CapabilityModuleOwnedResource[],
): Omit<CapabilityModuleManifest, "manifestSha256"> {
  const normalizedCapabilities = normalizeCapabilityDefinitions(capabilities);
  const capabilityManifest = createCapabilityManifest(normalizedCapabilities);
  const contractRegistry = createCapabilityContractRegistry(
    [...contractDescriptors].sort((a, b) =>
      a.capabilityId.localeCompare(b.capabilityId),
    ),
  );
  const normalizedAdapters = normalizeAdapters(adapters);
  const moduleIdNormalized = boundedId(moduleId, "moduleId");
  const providerImplementations = createModuleProviderImplementations(
    moduleIdNormalized,
    normalizedAdapters,
    contractRegistry.descriptors,
    providerPlatformRequirements,
  );
  const normalizedResources = normalizeOwnedResources(ownedResources);

  assertModuleCrossBindings(
    capabilityManifest.capabilities,
    contractRegistry.descriptors,
    normalizedAdapters,
  );

  return Object.freeze({
    schemaVersion: "toadaid.capability-module-manifest.v1" as const,
    moduleId: moduleIdNormalized,
    version: normalizeModuleVersion(version),
    capabilityManifest,
    contractRegistry,
    adapters: normalizedAdapters,
    providerImplementations,
    ownedResources: normalizedResources,
  });
}

export function createCapabilityModuleManifest(
  input: CreateCapabilityModuleManifestInput,
): CapabilityModuleManifest {
  const core = capabilityModuleManifestCore(
    input.moduleId,
    input.version,
    input.capabilities,
    input.contractDescriptors ?? [],
    input.adapters ?? [],
    input.providerPlatformRequirements,
    input.ownedResources ?? [],
  );
  return Object.freeze({
    ...core,
    manifestSha256: sha256(core),
  });
}

export function validateCapabilityModuleManifest(
  input: CapabilityModuleManifest,
): CapabilityModuleManifest {
  if (input.schemaVersion !== "toadaid.capability-module-manifest.v1") {
    throw new TypeError("unsupported capability module manifest schemaVersion");
  }
  if (
    input.capabilityManifest.schemaVersion !== "toadaid.capability-manifest.v1"
  ) {
    throw new TypeError("unsupported embedded P3 capability manifest");
  }

  const registry = validateCapabilityContractRegistry(input.contractRegistry);
  const providerImplementations = input.providerImplementations.map(
    validateCapabilityProviderImplementationDescriptor,
  );
  const core = capabilityModuleManifestCore(
    input.moduleId,
    input.version,
    input.capabilityManifest.capabilities,
    registry.descriptors,
    input.adapters,
    providerImplementations.map((provider) => ({
      adapterId: provider.adapterId,
      requirements: provider.platformRequirements,
    })),
    input.ownedResources,
  );
  if (sha256(providerImplementations) !== sha256(core.providerImplementations)) {
    throw new Error("capability module provider implementation mismatch");
  }
  const digest = sha(input.manifestSha256, "manifestSha256")!;
  if (digest !== sha256(core)) {
    throw new Error("capability module manifest integrity mismatch");
  }

  return Object.freeze({
    ...core,
    manifestSha256: digest,
  });
}

export function capabilityModuleManifestSha256(
  input: CapabilityModuleManifest,
): string {
  return validateCapabilityModuleManifest(input).manifestSha256;
}

function normalizeRemovalResourceIds(
  ids: readonly string[],
): readonly string[] {
  const seen = new Set<string>();
  const values = ids.map((id, index) => {
    const normalized = boundedId(id, `removalResourceIds[${index}]`);
    if (seen.has(normalized)) {
      throw new TypeError(`duplicate removal resource id: ${normalized}`);
    }
    seen.add(normalized);
    return normalized;
  });
  values.sort();
  return Object.freeze(values);
}

function assertRemovalIdsMatchManifest(
  manifest: CapabilityModuleManifest,
  ids: readonly string[],
): void {
  const expected = manifest.ownedResources.map((item) => item.resourceId);
  if (JSON.stringify(expected) !== JSON.stringify([...ids].sort())) {
    throw new Error(
      "module removal resources must equal the exact module-owned resource set",
    );
  }
}

export function validateCapabilityModuleLifecycleRecord(
  record: CapabilityModuleLifecycleRecord,
): CapabilityModuleLifecycleRecord {
  if (record.schemaVersion !== "toadaid.capability-module-lifecycle.v1") {
    throw new TypeError("unsupported capability module lifecycle schemaVersion");
  }
  if (!MODULE_STATES.includes(record.state)) {
    throw new TypeError("capability module state is invalid");
  }
  if (!MODULE_TRANSITIONS.includes(record.transition)) {
    throw new TypeError("capability module transition is invalid");
  }
  if (
    !Number.isSafeInteger(record.revision) ||
    record.revision < 0 ||
    record.revision > MAX_REVISION
  ) {
    throw new RangeError("capability module revision is invalid");
  }

  const manifest = validateCapabilityModuleManifest(record.manifest);
  const moduleId = boundedId(record.moduleId, "moduleId");
  if (moduleId !== manifest.moduleId) {
    throw new Error("module lifecycle moduleId does not match manifest");
  }

  const manifestSha256 = sha(record.manifestSha256, "manifestSha256")!;
  if (manifestSha256 !== manifest.manifestSha256) {
    throw new Error("module lifecycle manifest SHA does not match manifest");
  }

  const inspectionEvidenceRefs = normalizeInspectionEvidence(
    record.inspectionEvidenceRefs,
  );
  const removalResourceIds = normalizeRemovalResourceIds(
    record.removalResourceIds,
  );
  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RangeError("module lifecycle updatedAt is earlier than createdAt");
  }

  const previousRecordSha256 =
    record.continuity.previousRecordSha256 === null
      ? null
      : sha(
          record.continuity.previousRecordSha256,
          "continuity.previousRecordSha256",
        )!;

  if (record.revision === 0) {
    if (
      record.transition !== "INSTALL" ||
      record.state !== "INSTALLED_DISABLED" ||
      previousRecordSha256 !== null
    ) {
      throw new Error("initial module lifecycle record is invalid");
    }
  } else {
    if (record.transition === "INSTALL" || previousRecordSha256 === null) {
      throw new Error("non-initial module lifecycle record is invalid");
    }
  }

  if (
    record.transition === "ENABLE" &&
    record.state !== "INSTALLED_ENABLED"
  ) {
    throw new Error("ENABLE transition must produce INSTALLED_ENABLED");
  }
  if (
    (record.transition === "DISABLE" || record.transition === "UPDATE") &&
    record.state !== "INSTALLED_DISABLED"
  ) {
    throw new Error(`${record.transition} transition must produce INSTALLED_DISABLED`);
  }
  if (record.transition === "REMOVE" && record.state !== "REMOVED") {
    throw new Error("REMOVE transition must produce REMOVED");
  }

  if (
    record.transition !== "INSTALL" &&
    record.transition !== "UPDATE" &&
    inspectionEvidenceRefs.length > 0
  ) {
    throw new Error(
      "inspection evidence belongs only to INSTALL or UPDATE transitions",
    );
  }

  if (record.transition === "REMOVE") {
    assertRemovalIdsMatchManifest(manifest, removalResourceIds);
  } else if (removalResourceIds.length > 0) {
    throw new Error("removal resource ids belong only to REMOVE transitions");
  }

  return Object.freeze({
    schemaVersion: "toadaid.capability-module-lifecycle.v1",
    moduleId,
    revision: record.revision,
    state: record.state,
    transition: record.transition,
    manifest,
    manifestSha256,
    inspectionEvidenceRefs,
    removalResourceIds,
    createdAt,
    updatedAt,
    continuity: Object.freeze({ previousRecordSha256 }),
  });
}

export function capabilityModuleLifecycleRecordSha256(
  record: CapabilityModuleLifecycleRecord,
): string {
  return sha256(validateCapabilityModuleLifecycleRecord(record));
}

export function sealCapabilityModuleLifecycleRecord(
  record: CapabilityModuleLifecycleRecord,
): CapabilityModuleLifecycleEnvelope {
  const normalized = validateCapabilityModuleLifecycleRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.capability-module-lifecycle-envelope.v1",
    record: normalized,
    recordSha256: sha256(normalized),
  });
}

export function validateCapabilityModuleLifecycleEnvelope(
  envelope: CapabilityModuleLifecycleEnvelope,
): CapabilityModuleLifecycleEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.capability-module-lifecycle-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported capability module lifecycle envelope schemaVersion",
    );
  }
  const record = validateCapabilityModuleLifecycleRecord(envelope.record);
  const recordSha256 = sha(envelope.recordSha256, "recordSha256")!;
  if (recordSha256 !== sha256(record)) {
    throw new Error("capability module lifecycle integrity mismatch");
  }
  return Object.freeze({
    schemaVersion: "toadaid.capability-module-lifecycle-envelope.v1",
    record,
    recordSha256,
  });
}

function transitionTime(
  value: string | undefined,
  label: string,
  runtime?: CapabilityModuleRuntime,
): string {
  return canonicalIso(value, label, runtime?.now ?? (() => new Date()));
}

export function assertCapabilityModulePredecessor(
  previous: CapabilityModuleLifecycleEnvelope,
  next: CapabilityModuleLifecycleEnvelope,
): void {
  const prior = validateCapabilityModuleLifecycleEnvelope(previous);
  const current = validateCapabilityModuleLifecycleEnvelope(next);

  if (prior.record.state === "REMOVED") {
    throw new Error("removed capability module cannot transition");
  }
  if (current.record.moduleId !== prior.record.moduleId) {
    throw new Error("capability module predecessor moduleId mismatch");
  }
  if (current.record.createdAt !== prior.record.createdAt) {
    throw new Error("capability module predecessor createdAt mismatch");
  }
  if (current.record.revision !== prior.record.revision + 1) {
    throw new Error("capability module revision is not contiguous");
  }
  if (
    current.record.continuity.previousRecordSha256 !== prior.recordSha256
  ) {
    throw new Error("capability module predecessor digest mismatch");
  }
  if (
    Date.parse(current.record.updatedAt) <
    Date.parse(prior.record.updatedAt)
  ) {
    throw new RangeError("capability module lifecycle time moved backwards");
  }

  if (current.record.transition === "ENABLE") {
    if (prior.record.state !== "INSTALLED_DISABLED") {
      throw new Error("ENABLE requires INSTALLED_DISABLED predecessor");
    }
    if (current.record.manifestSha256 !== prior.record.manifestSha256) {
      throw new Error("ENABLE cannot rewrite module manifest");
    }
  } else if (current.record.transition === "DISABLE") {
    if (prior.record.state !== "INSTALLED_ENABLED") {
      throw new Error("DISABLE requires INSTALLED_ENABLED predecessor");
    }
    if (current.record.manifestSha256 !== prior.record.manifestSha256) {
      throw new Error("DISABLE cannot rewrite module manifest");
    }
  } else if (current.record.transition === "UPDATE") {
    if (prior.record.state !== "INSTALLED_DISABLED") {
      throw new Error("UPDATE requires INSTALLED_DISABLED predecessor");
    }
    if (current.record.manifestSha256 === prior.record.manifestSha256) {
      throw new Error("UPDATE must change module manifest");
    }
    if (current.record.manifest.version === prior.record.manifest.version) {
      throw new Error("UPDATE must change module version");
    }
  } else if (current.record.transition === "REMOVE") {
    if (prior.record.state !== "INSTALLED_DISABLED") {
      throw new Error("REMOVE requires INSTALLED_DISABLED predecessor");
    }
    if (current.record.manifestSha256 !== prior.record.manifestSha256) {
      throw new Error("REMOVE cannot rewrite module manifest");
    }
  } else {
    throw new Error("non-initial predecessor cannot transition with INSTALL");
  }
}

export function installCapabilityModule(
  manifestInput: CapabilityModuleManifest,
  input: InstallCapabilityModuleInput = {},
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  const manifest = validateCapabilityModuleManifest(manifestInput);
  const installedAt = transitionTime(
    input.installedAt,
    "installedAt",
    runtime,
  );

  return sealCapabilityModuleLifecycleRecord({
    schemaVersion: "toadaid.capability-module-lifecycle.v1",
    moduleId: manifest.moduleId,
    revision: 0,
    state: "INSTALLED_DISABLED",
    transition: "INSTALL",
    manifest,
    manifestSha256: manifest.manifestSha256,
    inspectionEvidenceRefs: normalizeInspectionEvidence(
      input.inspectionEvidenceRefs,
    ),
    removalResourceIds: Object.freeze([]),
    createdAt: installedAt,
    updatedAt: installedAt,
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

function simpleTransition(
  envelope: CapabilityModuleLifecycleEnvelope,
  transition: "ENABLE" | "DISABLE",
  state: "INSTALLED_ENABLED" | "INSTALLED_DISABLED",
  at: string | undefined,
  label: string,
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  const current = validateCapabilityModuleLifecycleEnvelope(envelope);
  const updatedAt = transitionTime(at, label, runtime);

  const next = sealCapabilityModuleLifecycleRecord({
    schemaVersion: "toadaid.capability-module-lifecycle.v1",
    moduleId: current.record.moduleId,
    revision: current.record.revision + 1,
    state,
    transition,
    manifest: current.record.manifest,
    manifestSha256: current.record.manifestSha256,
    inspectionEvidenceRefs: Object.freeze([]),
    removalResourceIds: Object.freeze([]),
    createdAt: current.record.createdAt,
    updatedAt,
    continuity: Object.freeze({
      previousRecordSha256: current.recordSha256,
    }),
  });
  assertCapabilityModulePredecessor(current, next);
  return next;
}

export function enableCapabilityModule(
  envelope: CapabilityModuleLifecycleEnvelope,
  enabledAt?: string,
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  return simpleTransition(
    envelope,
    "ENABLE",
    "INSTALLED_ENABLED",
    enabledAt,
    "enabledAt",
    runtime,
  );
}

export function disableCapabilityModule(
  envelope: CapabilityModuleLifecycleEnvelope,
  disabledAt?: string,
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  return simpleTransition(
    envelope,
    "DISABLE",
    "INSTALLED_DISABLED",
    disabledAt,
    "disabledAt",
    runtime,
  );
}

export function assertCapabilityModuleOwnedResourcesClean(
  manifestInput: CapabilityModuleManifest,
  observedResources: readonly CapabilityModuleOwnedResource[],
): void {
  const manifest = validateCapabilityModuleManifest(manifestInput);
  const observed = normalizeOwnedResources(observedResources);

  if (observed.length !== manifest.ownedResources.length) {
    throw new Error("module owned-resource set is dirty or incomplete");
  }

  for (let index = 0; index < manifest.ownedResources.length; index += 1) {
    const expected = manifest.ownedResources[index]!;
    const actual = observed[index]!;
    if (
      expected.resourceId !== actual.resourceId ||
      expected.fingerprintSha256 !== actual.fingerprintSha256
    ) {
      throw new Error(
        `module owned resource is dirty or conflicted: ${expected.resourceId}`,
      );
    }
  }
}

export function updateCapabilityModule(
  envelope: CapabilityModuleLifecycleEnvelope,
  nextManifestInput: CapabilityModuleManifest,
  input: UpdateCapabilityModuleInput,
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  const current = validateCapabilityModuleLifecycleEnvelope(envelope);
  if (current.record.state !== "INSTALLED_DISABLED") {
    throw new Error("module must be disabled before update");
  }

  assertCapabilityModuleOwnedResourcesClean(
    current.record.manifest,
    input.observedOwnedResources,
  );

  const nextManifest = validateCapabilityModuleManifest(nextManifestInput);
  if (nextManifest.moduleId !== current.record.moduleId) {
    throw new Error("module update cannot change moduleId");
  }

  const updatedAt = transitionTime(input.updatedAt, "updatedAt", runtime);
  const next = sealCapabilityModuleLifecycleRecord({
    schemaVersion: "toadaid.capability-module-lifecycle.v1",
    moduleId: current.record.moduleId,
    revision: current.record.revision + 1,
    state: "INSTALLED_DISABLED",
    transition: "UPDATE",
    manifest: nextManifest,
    manifestSha256: nextManifest.manifestSha256,
    inspectionEvidenceRefs: normalizeInspectionEvidence(
      input.inspectionEvidenceRefs,
    ),
    removalResourceIds: Object.freeze([]),
    createdAt: current.record.createdAt,
    updatedAt,
    continuity: Object.freeze({
      previousRecordSha256: current.recordSha256,
    }),
  });
  assertCapabilityModulePredecessor(current, next);
  return next;
}

export function removeCapabilityModule(
  envelope: CapabilityModuleLifecycleEnvelope,
  input: RemoveCapabilityModuleInput,
  runtime?: CapabilityModuleRuntime,
): CapabilityModuleLifecycleEnvelope {
  const current = validateCapabilityModuleLifecycleEnvelope(envelope);
  if (current.record.state !== "INSTALLED_DISABLED") {
    throw new Error("module must be disabled before removal");
  }

  assertCapabilityModuleOwnedResourcesClean(
    current.record.manifest,
    input.observedOwnedResources,
  );

  const removedAt = transitionTime(input.removedAt, "removedAt", runtime);
  const removalResourceIds = Object.freeze(
    current.record.manifest.ownedResources.map((item) => item.resourceId),
  );
  const next = sealCapabilityModuleLifecycleRecord({
    schemaVersion: "toadaid.capability-module-lifecycle.v1",
    moduleId: current.record.moduleId,
    revision: current.record.revision + 1,
    state: "REMOVED",
    transition: "REMOVE",
    manifest: current.record.manifest,
    manifestSha256: current.record.manifestSha256,
    inspectionEvidenceRefs: Object.freeze([]),
    removalResourceIds,
    createdAt: current.record.createdAt,
    updatedAt: removedAt,
    continuity: Object.freeze({
      previousRecordSha256: current.recordSha256,
    }),
  });
  assertCapabilityModulePredecessor(current, next);
  return next;
}

export function projectEnabledCapabilityModule(
  envelope: CapabilityModuleLifecycleEnvelope,
): CapabilityModuleRegistrationProjection {
  const current = validateCapabilityModuleLifecycleEnvelope(envelope);
  if (current.record.state !== "INSTALLED_ENABLED") {
    throw new Error("module must be enabled before registration projection");
  }

  return Object.freeze({
    schemaVersion: "toadaid.capability-module-registration-projection.v1",
    moduleId: current.record.moduleId,
    version: current.record.manifest.version,
    manifestSha256: current.record.manifestSha256,
    lifecycleRecordSha256: current.recordSha256,
    capabilityManifest: current.record.manifest.capabilityManifest,
    contractRegistry: current.record.manifest.contractRegistry,
    adapters: current.record.manifest.adapters,
    providerImplementations: current.record.manifest.providerImplementations,
  });
}

export function assertCapabilityModuleRegistrationProjectionCurrent(
  projection: CapabilityModuleRegistrationProjection,
  envelope: CapabilityModuleLifecycleEnvelope,
): CapabilityModuleRegistrationProjection {
  const current = validateCapabilityModuleLifecycleEnvelope(envelope);
  if (current.record.state !== "INSTALLED_ENABLED") {
    throw new Error(
      "capability module registration projection requires current ENABLED state",
    );
  }

  if (
    projection.schemaVersion !==
    "toadaid.capability-module-registration-projection.v1"
  ) {
    throw new TypeError(
      "unsupported capability module registration projection schemaVersion",
    );
  }

  const canonical = projectEnabledCapabilityModule(current);
  if (
    sha(projection.lifecycleRecordSha256, "lifecycleRecordSha256") !==
      current.recordSha256 ||
    sha256(projection) !== sha256(canonical)
  ) {
    throw new Error(
      "capability module registration projection is stale or tampered",
    );
  }

  return canonical;
}

export function serializeCapabilityModuleLifecycle(
  envelope: CapabilityModuleLifecycleEnvelope,
): string {
  return JSON.stringify(validateCapabilityModuleLifecycleEnvelope(envelope));
}

export function parseCapabilityModuleLifecycle(
  serialized: string,
): CapabilityModuleLifecycleEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("capability module lifecycle envelope must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TypeError("capability module lifecycle envelope must be an object");
  }
  return validateCapabilityModuleLifecycleEnvelope(
    parsed as CapabilityModuleLifecycleEnvelope,
  );
}
