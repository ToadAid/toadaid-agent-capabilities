import {
  createCapabilityManifest,
} from "./capabilityPolicy.js";
import {
  capabilityContractDescriptorSha256,
} from "./capabilityContract.js";
import {
  connectorAdapterRegistrationSha256,
} from "./connectorAdapter.js";
import {
  desktopObservationAdapterRegistrationSha256,
} from "./desktopObservation.js";
import {
  desktopInteractionAdapterRegistrationSha256,
} from "./desktopInteraction.js";
import {
  hostServiceAdapterRegistrationSha256,
} from "./hostService.js";
import {
  projectEnabledCapabilityModule,
  validateCapabilityModuleLifecycleEnvelope,
} from "./capabilityModuleLifecycle.js";
import {
  boundedId,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  CapabilityDefinition,
  CapabilityManifest,
} from "./capabilityPolicy.js";
import type {
  CapabilityModuleAdapterRegistration,
  CapabilityModuleLifecycleEnvelope,
  CapabilityModuleRegistrationProjection,
} from "./capabilityModuleLifecycleTypes.js";
import type {
  CapabilityProviderAdapterKind,
  CapabilityProviderBinding,
  CapabilityProviderRegistry,
  CapabilityProviderSelection,
  CapabilityRuntimeProviderCandidate,
  CapabilityRuntimeProviderForKind,
  CapabilityRuntimeProviderRegistry,
  ComposeCapabilityProviderRegistryInput,
} from "./capabilityProviderRegistryTypes.js";

export type * from "./capabilityProviderRegistryTypes.js";

const LEGACY_HOST_CAPABILITY_ALIASES = Object.freeze({
  "host:filesystem-read": "host:file-read",
  "host:filesystem-write": "host:file-write",
  "host:command-execute": "host:command-exec",
} as const);

function adapterKind(
  registration: CapabilityModuleAdapterRegistration,
): CapabilityProviderAdapterKind {
  switch (registration.schemaVersion) {
    case "toadaid.connector-adapter-registration.v1":
      return "CONNECTOR";
    case "toadaid.desktop-observation-adapter-registration.v1":
      return "DESKTOP_OBSERVATION";
    case "toadaid.desktop-interaction-adapter-registration.v1":
      return "DESKTOP_INTERACTION";
    case "toadaid.host-service-adapter-registration.v1":
      return "HOST_SERVICE";
  }
}

function adapterRegistrationSha256(
  registration: CapabilityModuleAdapterRegistration,
): string {
  switch (registration.schemaVersion) {
    case "toadaid.connector-adapter-registration.v1":
      return connectorAdapterRegistrationSha256(registration);
    case "toadaid.desktop-observation-adapter-registration.v1":
      return desktopObservationAdapterRegistrationSha256(registration);
    case "toadaid.desktop-interaction-adapter-registration.v1":
      return desktopInteractionAdapterRegistrationSha256(registration);
    case "toadaid.host-service-adapter-registration.v1":
      return hostServiceAdapterRegistrationSha256(registration);
  }
}

function bindingKey(capabilityId: string, toolName: string): string {
  return `${capabilityId}\u0000${toolName}`;
}

function mergeCapabilityDefinitions(
  groups: readonly (readonly CapabilityDefinition[])[],
): CapabilityManifest {
  const definitions = new Map<string, CapabilityDefinition>();
  for (const group of groups) {
    for (const candidate of group) {
      const previous = definitions.get(candidate.id);
      if (previous) {
        if (
          previous.description !== candidate.description ||
          previous.defaultDecision !== candidate.defaultDecision
        ) {
          throw new Error(
            `conflicting capability definition: ${candidate.id}`,
          );
        }
        continue;
      }
      definitions.set(candidate.id, candidate);
    }
  }
  return createCapabilityManifest(
    [...definitions.values()].sort((a, b) => a.id.localeCompare(b.id)),
  );
}

function bindingFromProjection(
  projection: CapabilityModuleRegistrationProjection,
  registration: CapabilityModuleAdapterRegistration,
): CapabilityProviderBinding {
  const descriptor = projection.contractRegistry.descriptors.find(
    (item) => item.capabilityId === registration.capabilityId,
  );
  if (!descriptor) {
    throw new Error(
      `provider adapter has no C1 descriptor: ${registration.capabilityId}`,
    );
  }
  const descriptorSha256 = capabilityContractDescriptorSha256(descriptor);
  if (
    registration.contractId !== descriptor.contractId ||
    registration.descriptorSha256 !== descriptorSha256 ||
    registration.implementationFingerprintSha256 !==
      descriptor.implementation.fingerprintSha256
  ) {
    throw new Error(
      `provider adapter does not match module descriptor: ${registration.adapterId}`,
    );
  }
  return Object.freeze({
    schemaVersion: "toadaid.capability-provider-binding.v1" as const,
    capabilityId: registration.capabilityId,
    toolName: registration.toolName,
    moduleId: projection.moduleId,
    moduleVersion: projection.version,
    moduleManifestSha256: projection.manifestSha256,
    lifecycleRecordSha256: projection.lifecycleRecordSha256,
    adapterId: registration.adapterId,
    adapterKind: adapterKind(registration),
    adapterRegistrationSha256: adapterRegistrationSha256(registration),
    descriptorSha256,
    implementationFingerprintSha256:
      registration.implementationFingerprintSha256,
    registration,
  });
}

function selectionFromBinding(
  binding: CapabilityProviderBinding,
): CapabilityProviderSelection {
  return Object.freeze({
    schemaVersion: "toadaid.capability-provider-selection.v1" as const,
    capabilityId: binding.capabilityId,
    toolName: binding.toolName,
    moduleId: binding.moduleId,
    adapterId: binding.adapterId,
    adapterKind: binding.adapterKind,
    lifecycleRecordSha256: binding.lifecycleRecordSha256,
    adapterRegistrationSha256: binding.adapterRegistrationSha256,
    descriptorSha256: binding.descriptorSha256,
    implementationFingerprintSha256:
      binding.implementationFingerprintSha256,
  });
}

function normalizeSelection(
  selection: CapabilityProviderSelection,
): CapabilityProviderSelection {
  if (
    selection.schemaVersion !==
    "toadaid.capability-provider-selection.v1"
  ) {
    throw new TypeError("unsupported capability provider selection schemaVersion");
  }
  const kinds: readonly CapabilityProviderAdapterKind[] = [
    "CONNECTOR",
    "DESKTOP_OBSERVATION",
    "DESKTOP_INTERACTION",
    "HOST_SERVICE",
  ];
  if (!kinds.includes(selection.adapterKind)) {
    throw new TypeError("capability provider selection adapterKind is invalid");
  }
  return Object.freeze({
    schemaVersion: "toadaid.capability-provider-selection.v1",
    capabilityId: boundedId(selection.capabilityId, "selection.capabilityId"),
    toolName: boundedId(selection.toolName, "selection.toolName"),
    moduleId: boundedId(selection.moduleId, "selection.moduleId"),
    adapterId: boundedId(selection.adapterId, "selection.adapterId"),
    adapterKind: selection.adapterKind,
    lifecycleRecordSha256:
      sha(selection.lifecycleRecordSha256, "selection.lifecycleRecordSha256")!,
    adapterRegistrationSha256:
      sha(selection.adapterRegistrationSha256, "selection.adapterRegistrationSha256")!,
    descriptorSha256:
      sha(selection.descriptorSha256, "selection.descriptorSha256")!,
    implementationFingerprintSha256:
      sha(
        selection.implementationFingerprintSha256,
        "selection.implementationFingerprintSha256",
      )!,
  });
}

function selectionMatchesBinding(
  selection: CapabilityProviderSelection,
  binding: CapabilityProviderBinding,
): boolean {
  return sha256(selection) === sha256(selectionFromBinding(binding));
}

function assertNoLegacyStructuredAliasCollision(
  bindings: readonly CapabilityProviderBinding[],
): void {
  const capabilityIds = new Set(bindings.map((binding) => binding.capabilityId));
  for (const [legacy, structured] of Object.entries(
    LEGACY_HOST_CAPABILITY_ALIASES,
  )) {
    if (capabilityIds.has(legacy) && capabilityIds.has(structured)) {
      throw new Error(
        `ambiguous legacy/structured host capability aliases: ${legacy}/${structured}`,
      );
    }
  }
}

function registryCore(
  registry: Omit<CapabilityProviderRegistry, "registrySha256"> |
    CapabilityProviderRegistry,
): Omit<CapabilityProviderRegistry, "registrySha256"> {
  const { registrySha256: _ignored, ...core } =
    registry as CapabilityProviderRegistry;
  return core;
}

export function createCapabilityProviderSelection(
  envelope: CapabilityModuleLifecycleEnvelope,
  adapterId: string,
): CapabilityProviderSelection {
  const projection = projectEnabledCapabilityModule(envelope);
  const normalizedAdapterId = boundedId(adapterId, "adapterId");
  const registration = projection.adapters.find(
    (item) => item.adapterId === normalizedAdapterId,
  );
  if (!registration) {
    throw new Error(`enabled module adapter is not registered: ${normalizedAdapterId}`);
  }
  return selectionFromBinding(
    bindingFromProjection(projection, registration),
  );
}

export function composeCapabilityProviderRegistry(
  input: ComposeCapabilityProviderRegistryInput,
): CapabilityProviderRegistry {
  const moduleIds = new Set<string>();
  const modules = input.modules.map((item) => {
    const current = validateCapabilityModuleLifecycleEnvelope(item);
    if (moduleIds.has(current.record.moduleId)) {
      throw new TypeError(
        `duplicate current capability module head: ${current.record.moduleId}`,
      );
    }
    moduleIds.add(current.record.moduleId);
    return current;
  }).sort((a, b) => a.record.moduleId.localeCompare(b.record.moduleId));

  const installed = modules.filter(
    (item) => item.record.state !== "REMOVED",
  );
  const enabled = modules.filter(
    (item) => item.record.state === "INSTALLED_ENABLED",
  );
  const enabledModules = Object.freeze(
    enabled.map(projectEnabledCapabilityModule),
  );

  const knownCapabilityManifest = mergeCapabilityDefinitions([
    input.knownCapabilities ?? [],
    ...modules.map((item) => item.record.manifest.capabilityManifest.capabilities),
  ]);
  const installedCapabilityManifest = mergeCapabilityDefinitions(
    installed.map((item) => item.record.manifest.capabilityManifest.capabilities),
  );
  const enabledCapabilityManifest = mergeCapabilityDefinitions(
    enabled.map((item) => item.record.manifest.capabilityManifest.capabilities),
  );

  const candidates = enabledModules.flatMap((projection) =>
    projection.adapters.map((registration) =>
      bindingFromProjection(projection, registration)
    )
  );
  assertNoLegacyStructuredAliasCollision(candidates);

  const selections = Object.freeze(
    [...(input.selections ?? [])]
      .map(normalizeSelection)
      .sort((a, b) =>
        bindingKey(a.capabilityId, a.toolName).localeCompare(
          bindingKey(b.capabilityId, b.toolName),
        )
      ),
  );
  const selectionByKey = new Map<string, CapabilityProviderSelection>();
  for (const selection of selections) {
    const key = bindingKey(selection.capabilityId, selection.toolName);
    if (selectionByKey.has(key)) {
      throw new TypeError(
        `duplicate provider selection: ${selection.capabilityId}/${selection.toolName}`,
      );
    }
    selectionByKey.set(key, selection);
  }

  const candidatesByKey = new Map<string, CapabilityProviderBinding[]>();
  for (const candidate of candidates) {
    const key = bindingKey(candidate.capabilityId, candidate.toolName);
    const group = candidatesByKey.get(key) ?? [];
    group.push(candidate);
    candidatesByKey.set(key, group);
  }

  const consumedSelections = new Set<string>();
  const providers: CapabilityProviderBinding[] = [];
  for (const [key, unsorted] of [...candidatesByKey.entries()].sort()) {
    const group = unsorted.sort((a, b) =>
      `${a.moduleId}\u0000${a.adapterId}`.localeCompare(
        `${b.moduleId}\u0000${b.adapterId}`,
      )
    );
    const selection = selectionByKey.get(key);
    if (group.length > 1 && !selection) {
      throw new Error(
        `duplicate active capability/tool providers require explicit selection: ${group[0]!.capabilityId}/${group[0]!.toolName}`,
      );
    }
    if (selection) {
      const selected = group.find((candidate) =>
        selectionMatchesBinding(selection, candidate)
      );
      if (!selected) {
        throw new Error(
          `provider selection is stale or mismatched: ${selection.capabilityId}/${selection.toolName}`,
        );
      }
      providers.push(selected);
      consumedSelections.add(key);
    } else {
      providers.push(group[0]!);
    }
  }

  for (const key of selectionByKey.keys()) {
    if (!consumedSelections.has(key)) {
      const selection = selectionByKey.get(key)!;
      throw new Error(
        `provider selection has no enabled candidate: ${selection.capabilityId}/${selection.toolName}`,
      );
    }
  }

  const core: Omit<CapabilityProviderRegistry, "registrySha256"> =
    Object.freeze({
      schemaVersion: "toadaid.capability-provider-registry.v1",
      knownCapabilityManifest,
      installedCapabilityManifest,
      enabledCapabilityManifest,
      enabledModules,
      selections,
      providers: Object.freeze(providers),
    });
  return Object.freeze({
    ...core,
    registrySha256: sha256(core),
  });
}

export function capabilityProviderRegistrySha256(
  registry: CapabilityProviderRegistry,
): string {
  if (registry.schemaVersion !== "toadaid.capability-provider-registry.v1") {
    throw new TypeError("unsupported capability provider registry schemaVersion");
  }
  const digest = sha(registry.registrySha256, "registrySha256")!;
  if (digest !== sha256(registryCore(registry))) {
    throw new Error("capability provider registry integrity mismatch");
  }
  return digest;
}

export function assertCapabilityProviderRegistryCurrent(
  registry: CapabilityProviderRegistry,
  modules: readonly CapabilityModuleLifecycleEnvelope[],
): CapabilityProviderRegistry {
  capabilityProviderRegistrySha256(registry);
  const current = composeCapabilityProviderRegistry({
    modules,
    knownCapabilities: registry.knownCapabilityManifest.capabilities,
    selections: registry.selections,
  });
  if (current.registrySha256 !== registry.registrySha256) {
    throw new Error("capability provider registry is stale or mismatched");
  }
  return current;
}

export function composeCapabilityRuntimeProviderRegistry(
  registry: CapabilityProviderRegistry,
  modules: readonly CapabilityModuleLifecycleEnvelope[],
  candidates: readonly CapabilityRuntimeProviderCandidate[],
): CapabilityRuntimeProviderRegistry {
  const current = assertCapabilityProviderRegistryCurrent(registry, modules);
  const candidateByIdentity = new Map<string, CapabilityRuntimeProviderCandidate>();
  for (const candidate of candidates) {
    const moduleId = boundedId(candidate.moduleId, "runtimeProvider.moduleId");
    const registration = candidate.provider.registration;
    const identity = `${moduleId}\u0000${registration.adapterId}`;
    if (candidateByIdentity.has(identity)) {
      throw new TypeError(
        `duplicate runtime provider candidate: ${moduleId}/${registration.adapterId}`,
      );
    }
    const selected = current.providers.find(
      (binding) =>
        binding.moduleId === moduleId &&
        binding.adapterId === registration.adapterId,
    );
    if (
      !selected ||
      selected.adapterKind !== adapterKind(registration) ||
      selected.adapterRegistrationSha256 !==
        adapterRegistrationSha256(registration)
    ) {
      throw new Error(
        `runtime provider is not the exact selected provider: ${moduleId}/${registration.adapterId}`,
      );
    }
    candidateByIdentity.set(identity, Object.freeze({
      moduleId,
      provider: candidate.provider,
    }));
  }

  const providers = current.providers.map((binding) => {
    const identity = `${binding.moduleId}\u0000${binding.adapterId}`;
    const candidate = candidateByIdentity.get(identity);
    if (!candidate) {
      throw new Error(
        `selected provider implementation is unavailable: ${binding.moduleId}/${binding.adapterId}`,
      );
    }
    return candidate;
  });
  return Object.freeze({
    schemaVersion: "toadaid.capability-runtime-provider-registry.v1",
    providerRegistrySha256: current.registrySha256,
    providers: Object.freeze(providers),
  });
}

export function resolveCapabilityProvider(
  registry: CapabilityProviderRegistry,
  capabilityId: string,
  toolName: string,
  expectedKind?: CapabilityProviderAdapterKind,
): CapabilityProviderBinding {
  capabilityProviderRegistrySha256(registry);
  const normalizedCapabilityId = boundedId(capabilityId, "capabilityId");
  const normalizedToolName = boundedId(toolName, "toolName");
  const provider = registry.providers.find(
    (item) =>
      item.capabilityId === normalizedCapabilityId &&
      item.toolName === normalizedToolName,
  );
  if (!provider) {
    throw new Error(
      `no selected enabled provider: ${normalizedCapabilityId}/${normalizedToolName}`,
    );
  }
  if (expectedKind !== undefined && provider.adapterKind !== expectedKind) {
    throw new Error(
      `selected provider kind mismatch: expected ${expectedKind}, received ${provider.adapterKind}`,
    );
  }
  return provider;
}

export function resolveCapabilityRuntimeProvider<
  Kind extends CapabilityProviderAdapterKind,
>(
  runtimeRegistry: CapabilityRuntimeProviderRegistry,
  providerRegistry: CapabilityProviderRegistry,
  capabilityId: string,
  toolName: string,
  expectedKind: Kind,
): CapabilityRuntimeProviderForKind<Kind> {
  if (
    runtimeRegistry.schemaVersion !==
    "toadaid.capability-runtime-provider-registry.v1" ||
    runtimeRegistry.providerRegistrySha256 !==
      capabilityProviderRegistrySha256(providerRegistry)
  ) {
    throw new Error("runtime provider registry projection mismatch");
  }
  const selected = resolveCapabilityProvider(
    providerRegistry,
    capabilityId,
    toolName,
    expectedKind,
  );
  const binding = runtimeRegistry.providers.find(
    (item) =>
      item.moduleId === selected.moduleId &&
      item.provider.registration.adapterId === selected.adapterId,
  );
  if (!binding) {
    throw new Error("selected runtime provider implementation is unavailable");
  }
  if (
    adapterKind(binding.provider.registration) !== expectedKind ||
    adapterRegistrationSha256(binding.provider.registration) !==
      selected.adapterRegistrationSha256
  ) {
    throw new Error("selected runtime provider implementation drifted");
  }
  return binding.provider as CapabilityRuntimeProviderForKind<Kind>;
}
