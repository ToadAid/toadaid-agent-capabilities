import {
  createCapabilityManifest,
  resolveCapabilityAuthority,
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
  canonicalIso,
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
  CapabilityAvailabilityProjection,
  CapabilityAvailableRuntimeProviderRegistry,
  CapabilityProviderAvailabilityBinding,
  CapabilityProviderBinding,
  CapabilityProviderHealthReport,
  CapabilityProviderHostIdentity,
  CapabilityProviderRegistry,
  CapabilityProviderSelection,
  CapabilityRuntimeProviderCandidate,
  CapabilityRuntimeProviderForKind,
  CapabilityRuntimeProviderRegistry,
  ComposeCapabilityAvailabilityProjectionInput,
  ComposeCapabilityProviderRegistryInput,
  CreateCapabilityProviderHealthReportInput,
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
  const providerImplementation = projection.providerImplementations.find(
    (item) => item.adapterId === registration.adapterId,
  );
  if (!providerImplementation) {
    throw new Error(`provider implementation descriptor is missing: ${registration.adapterId}`);
  }
  if (
    registration.contractId !== descriptor.contractId ||
    registration.descriptorSha256 !== descriptorSha256 ||
    registration.implementationFingerprintSha256 !==
      providerImplementation.implementationFingerprintSha256 ||
    providerImplementation.contractDescriptorSha256 !== descriptorSha256 ||
    providerImplementation.adapterRegistrationSha256 !==
      adapterRegistrationSha256(registration)
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
    providerDescriptorSha256: providerImplementation.providerDescriptorSha256,
    implementationFingerprintSha256:
      registration.implementationFingerprintSha256,
    registration,
    providerImplementation,
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
    providerDescriptorSha256: binding.providerDescriptorSha256,
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
    providerDescriptorSha256:
      sha(selection.providerDescriptorSha256, "selection.providerDescriptorSha256")!,
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

const PLATFORM_VALUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function normalizeHostIdentity(
  input: CapabilityProviderHostIdentity,
): CapabilityProviderHostIdentity {
  const platformValue = (value: string, label: string): string => {
    if (!PLATFORM_VALUE_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
    return value.toLowerCase();
  };
  const runtimeIds = [...input.runtimeIds].map((value, index) =>
    platformValue(value, `host.runtimeIds[${index}]`)
  ).sort();
  if (new Set(runtimeIds).size !== runtimeIds.length) {
    throw new TypeError("host.runtimeIds contains duplicates");
  }
  return Object.freeze({
    hostId: boundedId(input.hostId, "host.hostId"),
    sessionId: boundedId(input.sessionId, "host.sessionId"),
    hostSessionLeaseSha256: sha(
      input.hostSessionLeaseSha256,
      "host.hostSessionLeaseSha256",
    )!,
    operatingSystem: platformValue(input.operatingSystem, "host.operatingSystem"),
    architecture: platformValue(input.architecture, "host.architecture"),
    runtimeIds: Object.freeze(runtimeIds),
  });
}

function healthReportCore(
  report: Omit<CapabilityProviderHealthReport, "reportSha256"> |
    CapabilityProviderHealthReport,
): Omit<CapabilityProviderHealthReport, "reportSha256"> {
  const { reportSha256: _ignored, ...core } = report as CapabilityProviderHealthReport;
  return core;
}

export function createCapabilityProviderHealthReport(
  provider: CapabilityProviderBinding,
  hostInput: CapabilityProviderHostIdentity,
  input: CreateCapabilityProviderHealthReportInput,
): CapabilityProviderHealthReport {
  const statuses = ["AVAILABLE_HEALTHY", "AVAILABLE_DEGRADED", "UNAVAILABLE"] as const;
  if (!statuses.includes(input.status)) throw new TypeError("provider health status is invalid");
  const observedAt = canonicalIso(input.observedAt, "health.observedAt");
  const expiresAt = canonicalIso(input.expiresAt, "health.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) {
    throw new RangeError("provider health expiresAt must be later than observedAt");
  }
  const core = Object.freeze({
    schemaVersion: "toadaid.capability-provider-health.v1" as const,
    moduleId: boundedId(provider.moduleId, "health.moduleId"),
    adapterId: boundedId(provider.adapterId, "health.adapterId"),
    lifecycleRecordSha256: sha(provider.lifecycleRecordSha256, "health.lifecycleRecordSha256")!,
    providerDescriptorSha256: sha(provider.providerDescriptorSha256, "health.providerDescriptorSha256")!,
    adapterRegistrationSha256: sha(provider.adapterRegistrationSha256, "health.adapterRegistrationSha256")!,
    implementationFingerprintSha256: sha(provider.implementationFingerprintSha256, "health.implementationFingerprintSha256")!,
    host: normalizeHostIdentity(hostInput),
    providerGenerationSha256: sha(input.providerGenerationSha256, "health.providerGenerationSha256")!,
    status: input.status,
    observedAt,
    expiresAt,
    evidenceSha256: sha(input.evidenceSha256, "health.evidenceSha256", true),
  });
  return Object.freeze({ ...core, reportSha256: sha256(core) });
}

export function validateCapabilityProviderHealthReport(
  input: CapabilityProviderHealthReport,
): CapabilityProviderHealthReport {
  if (input.schemaVersion !== "toadaid.capability-provider-health.v1") {
    throw new TypeError("unsupported capability provider health schemaVersion");
  }
  const rebuilt = createCapabilityProviderHealthReport({
    moduleId: input.moduleId,
    adapterId: input.adapterId,
    lifecycleRecordSha256: input.lifecycleRecordSha256,
    providerDescriptorSha256: input.providerDescriptorSha256,
    adapterRegistrationSha256: input.adapterRegistrationSha256,
    implementationFingerprintSha256: input.implementationFingerprintSha256,
  } as CapabilityProviderBinding, input.host, {
    providerGenerationSha256: input.providerGenerationSha256,
    status: input.status,
    observedAt: input.observedAt,
    expiresAt: input.expiresAt,
    ...(input.evidenceSha256 === null ? {} : { evidenceSha256: input.evidenceSha256 }),
  });
  if (rebuilt.reportSha256 !== input.reportSha256 ||
      sha256(healthReportCore(input)) !== input.reportSha256) {
    throw new Error("capability provider health integrity mismatch");
  }
  return rebuilt;
}

function availabilityProjectionCore(
  projection: Omit<CapabilityAvailabilityProjection, "projectionSha256"> |
    CapabilityAvailabilityProjection,
): Omit<CapabilityAvailabilityProjection, "projectionSha256"> {
  const { projectionSha256: _ignored, ...core } =
    projection as CapabilityAvailabilityProjection;
  return core;
}

export function capabilityAvailabilityProjectionSha256(
  projection: CapabilityAvailabilityProjection,
): string {
  if (projection.schemaVersion !== "toadaid.capability-availability-projection.v1") {
    throw new TypeError("unsupported capability availability projection schemaVersion");
  }
  const digest = sha(projection.projectionSha256, "projectionSha256")!;
  if (digest !== sha256(availabilityProjectionCore(projection))) {
    throw new Error("capability availability projection integrity mismatch");
  }
  return digest;
}

function platformCompatible(
  provider: CapabilityProviderBinding,
  host: CapabilityProviderHostIdentity,
): boolean {
  const requirements = provider.providerImplementation.platformRequirements;
  return (requirements.operatingSystems.length === 0 || requirements.operatingSystems.includes(host.operatingSystem)) &&
    (requirements.architectures.length === 0 || requirements.architectures.includes(host.architecture)) &&
    requirements.runtimeIds.every((runtimeId) => host.runtimeIds.includes(runtimeId));
}

function healthMatches(
  report: CapabilityProviderHealthReport,
  provider: CapabilityProviderBinding,
  host: CapabilityProviderHostIdentity,
): boolean {
  return report.moduleId === provider.moduleId &&
    report.adapterId === provider.adapterId &&
    report.lifecycleRecordSha256 === provider.lifecycleRecordSha256 &&
    report.providerDescriptorSha256 === provider.providerDescriptorSha256 &&
    report.adapterRegistrationSha256 === provider.adapterRegistrationSha256 &&
    report.implementationFingerprintSha256 === provider.implementationFingerprintSha256 &&
    sha256(report.host) === sha256(host);
}

export function composeCapabilityAvailabilityProjection(
  input: ComposeCapabilityAvailabilityProjectionInput,
): CapabilityAvailabilityProjection {
  const checkedAt = canonicalIso(input.checkedAt, "checkedAt");
  const host = normalizeHostIdentity(input.host);
  const moduleIds = new Set<string>();
  const heads = input.modules.map((item) => {
    const head = validateCapabilityModuleLifecycleEnvelope(item);
    if (moduleIds.has(head.record.moduleId)) throw new TypeError(`duplicate current capability module head: ${head.record.moduleId}`);
    moduleIds.add(head.record.moduleId);
    return head;
  }).sort((a, b) => a.record.moduleId.localeCompare(b.record.moduleId));
  const builtIns = input.builtInCapabilities ?? [];
  const knownCapabilityManifest = mergeCapabilityDefinitions([
    input.knownCapabilities ?? [], builtIns,
    ...heads.map((item) => item.record.manifest.capabilityManifest.capabilities),
  ]);
  const installedCapabilityManifest = mergeCapabilityDefinitions([
    builtIns,
    ...heads.filter((item) => item.record.state !== "REMOVED")
      .map((item) => item.record.manifest.capabilityManifest.capabilities),
  ]);
  const enabledHeads = heads.filter((item) => item.record.state === "INSTALLED_ENABLED");
  const enabledCapabilityManifest = mergeCapabilityDefinitions([
    builtIns,
    ...enabledHeads.map((item) => item.record.manifest.capabilityManifest.capabilities),
  ]);
  const candidates = enabledHeads.flatMap((item) => {
    const projection = projectEnabledCapabilityModule(item);
    return projection.adapters.map((registration) => bindingFromProjection(projection, registration));
  });
  assertNoLegacyStructuredAliasCollision(candidates);
  const reports = input.healthReports.map(validateCapabilityProviderHealthReport);
  const matchedReports = new Set<string>();
  const eligible: Array<{ provider: CapabilityProviderBinding; report: CapabilityProviderHealthReport }> = [];
  const unavailableProviders: Array<{ status: "UNAVAILABLE"; provider: CapabilityProviderBinding; reason: "PLATFORM_INCOMPATIBLE" | "HEALTH_MISSING" | "HEALTH_EXPIRED" | "PROVIDER_REPORTED_UNAVAILABLE"; providerGenerationSha256: string | null; healthReportSha256: string | null }> = [];
  for (const provider of candidates) {
    if (!platformCompatible(provider, host)) {
      unavailableProviders.push(Object.freeze({ status: "UNAVAILABLE", provider, reason: "PLATFORM_INCOMPATIBLE", providerGenerationSha256: null, healthReportSha256: null }));
      continue;
    }
    const matches = reports.filter((report) => healthMatches(report, provider, host));
    if (matches.length > 1) throw new TypeError(`duplicate provider health report: ${provider.moduleId}/${provider.adapterId}`);
    const report = matches[0];
    if (!report) {
      unavailableProviders.push(Object.freeze({ status: "UNAVAILABLE", provider, reason: "HEALTH_MISSING", providerGenerationSha256: null, healthReportSha256: null }));
      continue;
    }
    matchedReports.add(report.reportSha256);
    if (Date.parse(report.observedAt) > Date.parse(checkedAt)) {
      throw new Error(`provider health report is from the future: ${provider.moduleId}/${provider.adapterId}`);
    }
    if (Date.parse(report.expiresAt) <= Date.parse(checkedAt)) {
      unavailableProviders.push(Object.freeze({ status: "UNAVAILABLE", provider, reason: "HEALTH_EXPIRED", providerGenerationSha256: report.providerGenerationSha256, healthReportSha256: report.reportSha256 }));
    } else if (report.status === "UNAVAILABLE") {
      unavailableProviders.push(Object.freeze({ status: "UNAVAILABLE", provider, reason: "PROVIDER_REPORTED_UNAVAILABLE", providerGenerationSha256: report.providerGenerationSha256, healthReportSha256: report.reportSha256 }));
    } else {
      eligible.push({ provider, report });
    }
  }
  for (const report of reports) {
    if (!matchedReports.has(report.reportSha256)) throw new Error(`provider health report has no current enabled host-bound provider: ${report.moduleId}/${report.adapterId}`);
  }
  const selections = Object.freeze([...(input.selections ?? [])].map(normalizeSelection).sort((a, b) => bindingKey(a.capabilityId, a.toolName).localeCompare(bindingKey(b.capabilityId, b.toolName))));
  const selectionByKey = new Map<string, CapabilityProviderSelection>();
  for (const selection of selections) {
    const key = bindingKey(selection.capabilityId, selection.toolName);
    if (selectionByKey.has(key)) throw new TypeError(`duplicate provider selection: ${selection.capabilityId}/${selection.toolName}`);
    selectionByKey.set(key, selection);
  }
  const eligibleByKey = new Map<string, typeof eligible>();
  for (const candidate of eligible) {
    const key = bindingKey(candidate.provider.capabilityId, candidate.provider.toolName);
    const group = eligibleByKey.get(key) ?? [];
    group.push(candidate);
    eligibleByKey.set(key, group);
  }
  const consumedSelections = new Set<string>();
  const providers: CapabilityProviderAvailabilityBinding[] = [];
  for (const [key, group] of [...eligibleByKey.entries()].sort()) {
    const selection = selectionByKey.get(key);
    if (group.length > 1 && !selection) throw new Error(`duplicate compatible providers require explicit selection: ${group[0]!.provider.capabilityId}/${group[0]!.provider.toolName}`);
    const selected = selection ? group.find((candidate) => selectionMatchesBinding(selection, candidate.provider)) : group[0];
    if (!selected) throw new Error(`provider selection is unavailable, stale, or mismatched: ${selection!.capabilityId}/${selection!.toolName}`);
    if (selection) consumedSelections.add(key);
    const authority = resolveCapabilityAuthority(selected.provider.capabilityId, installedCapabilityManifest, input.policyLayers ?? []);
    const availableStatus = selected.report.status;
    if (availableStatus === "UNAVAILABLE") throw new Error("unavailable provider entered eligible provider set");
    providers.push(Object.freeze({
      schemaVersion: "toadaid.capability-provider-availability-binding.v1",
      status: availableStatus,
      provider: selected.provider,
      host,
      providerGenerationSha256: selected.report.providerGenerationSha256,
      healthReportSha256: selected.report.reportSha256,
      authority,
    }));
  }
  for (const [key, selection] of selectionByKey) {
    if (!consumedSelections.has(key)) throw new Error(`provider selection has no available compatible candidate: ${selection.capabilityId}/${selection.toolName}`);
  }
  const availableIds = new Set(providers.map((item) => item.provider.capabilityId));
  const authorizedIds = new Set(providers.filter((item) => item.authority.decision === "ALLOW").map((item) => item.provider.capabilityId));
  const availableCapabilityManifest = mergeCapabilityDefinitions([enabledCapabilityManifest.capabilities.filter((item) => availableIds.has(item.id))]);
  const authorizedCapabilityManifest = mergeCapabilityDefinitions([availableCapabilityManifest.capabilities.filter((item) => authorizedIds.has(item.id))]);
  const core = Object.freeze({
    schemaVersion: "toadaid.capability-availability-projection.v1" as const,
    checkedAt, host, knownCapabilityManifest, installedCapabilityManifest,
    enabledCapabilityManifest, availableCapabilityManifest,
    authorizedCapabilityManifest, selections,
    providers: Object.freeze(providers),
    unavailableProviders: Object.freeze(unavailableProviders),
  });
  return Object.freeze({ ...core, projectionSha256: sha256(core) });
}

export function assertCapabilityAvailabilityProjectionCurrent(
  projection: CapabilityAvailabilityProjection,
  input: ComposeCapabilityAvailabilityProjectionInput,
): CapabilityAvailabilityProjection {
  capabilityAvailabilityProjectionSha256(projection);
  const current = composeCapabilityAvailabilityProjection(input);
  if (current.projectionSha256 !== projection.projectionSha256) {
    throw new Error("capability availability projection is stale or mismatched");
  }
  return current;
}

export function resolveAvailableCapabilityProvider(
  projection: CapabilityAvailabilityProjection,
  capabilityIdInput: string,
  toolNameInput: string,
  expectedKind?: CapabilityProviderAdapterKind,
): CapabilityProviderAvailabilityBinding {
  capabilityAvailabilityProjectionSha256(projection);
  const capabilityId = boundedId(capabilityIdInput, "capabilityId");
  const toolName = boundedId(toolNameInput, "toolName");
  const binding = projection.providers.find((item) => item.provider.capabilityId === capabilityId && item.provider.toolName === toolName);
  if (!binding) throw new Error(`no available selected provider: ${capabilityId}/${toolName}`);
  if (expectedKind && binding.provider.adapterKind !== expectedKind) throw new Error(`available provider kind mismatch: expected ${expectedKind}, received ${binding.provider.adapterKind}`);
  return binding;
}

export function composeAvailableCapabilityRuntimeProviderRegistry(
  projection: CapabilityAvailabilityProjection,
  candidates: readonly CapabilityRuntimeProviderCandidate[],
): CapabilityAvailableRuntimeProviderRegistry {
  capabilityAvailabilityProjectionSha256(projection);
  const candidateByIdentity = new Map<string, CapabilityRuntimeProviderCandidate>();
  for (const candidate of candidates) {
    const moduleId = boundedId(candidate.moduleId, "runtimeProvider.moduleId");
    const identity = `${moduleId}\u0000${candidate.provider.registration.adapterId}`;
    if (candidateByIdentity.has(identity)) throw new TypeError(`duplicate runtime provider candidate: ${moduleId}/${candidate.provider.registration.adapterId}`);
    candidateByIdentity.set(identity, candidate);
  }
  const providers = projection.providers.map((available) => {
    const selected = available.provider;
    const identity = `${selected.moduleId}\u0000${selected.adapterId}`;
    const candidate = candidateByIdentity.get(identity);
    if (!candidate || adapterKind(candidate.provider.registration) !== selected.adapterKind || adapterRegistrationSha256(candidate.provider.registration) !== selected.adapterRegistrationSha256) {
      throw new Error(`available runtime provider is missing or drifted: ${selected.moduleId}/${selected.adapterId}`);
    }
    candidateByIdentity.delete(identity);
    return Object.freeze({ moduleId: selected.moduleId, adapterId: selected.adapterId, providerGenerationSha256: available.providerGenerationSha256, provider: candidate.provider });
  });
  if (candidateByIdentity.size > 0) throw new Error("runtime provider candidate is not selected and available");
  return Object.freeze({
    schemaVersion: "toadaid.capability-available-runtime-provider-registry.v1",
    availabilityProjectionSha256: projection.projectionSha256,
    providers: Object.freeze(providers),
  });
}

export function resolveAvailableCapabilityRuntimeProvider<Kind extends CapabilityProviderAdapterKind>(
  runtimeRegistry: CapabilityAvailableRuntimeProviderRegistry,
  projection: CapabilityAvailabilityProjection,
  capabilityId: string,
  toolName: string,
  expectedKind: Kind,
): CapabilityRuntimeProviderForKind<Kind> {
  if (runtimeRegistry.schemaVersion !== "toadaid.capability-available-runtime-provider-registry.v1" || runtimeRegistry.availabilityProjectionSha256 !== capabilityAvailabilityProjectionSha256(projection)) {
    throw new Error("available runtime provider registry projection mismatch");
  }
  const available = resolveAvailableCapabilityProvider(projection, capabilityId, toolName, expectedKind);
  const binding = runtimeRegistry.providers.find((item) => item.moduleId === available.provider.moduleId && item.adapterId === available.provider.adapterId);
  if (!binding || binding.providerGenerationSha256 !== available.providerGenerationSha256 || adapterRegistrationSha256(binding.provider.registration) !== available.provider.adapterRegistrationSha256) {
    throw new Error("available runtime provider binding is stale or drifted");
  }
  return binding.provider as CapabilityRuntimeProviderForKind<Kind>;
}
