import type {
  CapabilityDefinition,
  CapabilityAuthorityDecision,
  CapabilityManifest,
  CapabilityPolicyLayer,
} from "./capabilityPolicy.js";
import type {
  CapabilityProviderImplementationDescriptor,
} from "./capabilityContractTypes.js";
import type {
  CapabilityModuleAdapterRegistration,
  CapabilityModuleLifecycleEnvelope,
  CapabilityModuleRegistrationProjection,
} from "./capabilityModuleLifecycleTypes.js";
import type {
  GovernedConnectorAdapter,
} from "./connectorAdapterTypes.js";
import type {
  GovernedDesktopObservationAdapter,
} from "./desktopObservationTypes.js";
import type {
  GovernedDesktopInteractionAdapter,
} from "./desktopInteractionTypes.js";
import type {
  GovernedHostServiceAdapter,
} from "./hostServiceTypes.js";

export type CapabilityProviderAdapterKind =
  | "CONNECTOR"
  | "DESKTOP_OBSERVATION"
  | "DESKTOP_INTERACTION"
  | "HOST_SERVICE";

export interface CapabilityProviderSelection {
  readonly schemaVersion: "toadaid.capability-provider-selection.v1";
  readonly capabilityId: string;
  readonly toolName: string;
  readonly moduleId: string;
  readonly adapterId: string;
  readonly adapterKind: CapabilityProviderAdapterKind;
  readonly lifecycleRecordSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly descriptorSha256: string;
  readonly providerDescriptorSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface CapabilityProviderBinding {
  readonly schemaVersion: "toadaid.capability-provider-binding.v1";
  readonly capabilityId: string;
  readonly toolName: string;
  readonly moduleId: string;
  readonly moduleVersion: string;
  readonly moduleManifestSha256: string;
  readonly lifecycleRecordSha256: string;
  readonly adapterId: string;
  readonly adapterKind: CapabilityProviderAdapterKind;
  readonly adapterRegistrationSha256: string;
  readonly descriptorSha256: string;
  readonly providerDescriptorSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly registration: CapabilityModuleAdapterRegistration;
  readonly providerImplementation: CapabilityProviderImplementationDescriptor;
}

export interface ComposeCapabilityProviderRegistryInput {
  readonly modules: readonly CapabilityModuleLifecycleEnvelope[];
  readonly knownCapabilities?: readonly CapabilityDefinition[];
  readonly selections?: readonly CapabilityProviderSelection[];
}

export interface CapabilityProviderRegistry {
  readonly schemaVersion: "toadaid.capability-provider-registry.v1";
  readonly knownCapabilityManifest: CapabilityManifest;
  readonly installedCapabilityManifest: CapabilityManifest;
  readonly enabledCapabilityManifest: CapabilityManifest;
  readonly enabledModules: readonly CapabilityModuleRegistrationProjection[];
  readonly selections: readonly CapabilityProviderSelection[];
  readonly providers: readonly CapabilityProviderBinding[];
  readonly registrySha256: string;
}

export type GovernedCapabilityRuntimeProvider =
  | GovernedConnectorAdapter
  | GovernedDesktopObservationAdapter
  | GovernedDesktopInteractionAdapter
  | GovernedHostServiceAdapter;

export interface CapabilityRuntimeProviderCandidate {
  readonly moduleId: string;
  readonly provider: GovernedCapabilityRuntimeProvider;
}

export interface CapabilityRuntimeProviderBinding {
  readonly moduleId: string;
  readonly provider: GovernedCapabilityRuntimeProvider;
}

export interface CapabilityRuntimeProviderRegistry {
  readonly schemaVersion: "toadaid.capability-runtime-provider-registry.v1";
  readonly providerRegistrySha256: string;
  readonly providers: readonly CapabilityRuntimeProviderBinding[];
}

export type CapabilityProviderAvailabilityStatus =
  | "AVAILABLE_HEALTHY"
  | "AVAILABLE_DEGRADED"
  | "UNAVAILABLE";

export interface CapabilityProviderHostIdentity {
  readonly hostId: string;
  readonly sessionId: string;
  readonly hostSessionLeaseSha256: string;
  readonly operatingSystem: string;
  readonly architecture: string;
  readonly runtimeIds: readonly string[];
}

export interface CapabilityProviderHealthReport {
  readonly schemaVersion: "toadaid.capability-provider-health.v1";
  readonly moduleId: string;
  readonly adapterId: string;
  readonly lifecycleRecordSha256: string;
  readonly providerDescriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly host: CapabilityProviderHostIdentity;
  readonly providerGenerationSha256: string;
  readonly status: CapabilityProviderAvailabilityStatus;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly evidenceSha256: string | null;
  readonly reportSha256: string;
}

export interface CreateCapabilityProviderHealthReportInput {
  readonly providerGenerationSha256: string;
  readonly status: CapabilityProviderAvailabilityStatus;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly evidenceSha256?: string;
}

export type CapabilityProviderUnavailabilityReason =
  | "PLATFORM_INCOMPATIBLE"
  | "HEALTH_MISSING"
  | "HEALTH_EXPIRED"
  | "PROVIDER_REPORTED_UNAVAILABLE";

export interface CapabilityProviderAvailabilityBinding {
  readonly schemaVersion: "toadaid.capability-provider-availability-binding.v1";
  readonly status: "AVAILABLE_HEALTHY" | "AVAILABLE_DEGRADED";
  readonly provider: CapabilityProviderBinding;
  readonly host: CapabilityProviderHostIdentity;
  readonly providerGenerationSha256: string;
  readonly healthReportSha256: string;
  readonly authority: CapabilityAuthorityDecision;
}

export interface CapabilityProviderUnavailableBinding {
  readonly status: "UNAVAILABLE";
  readonly provider: CapabilityProviderBinding;
  readonly reason: CapabilityProviderUnavailabilityReason;
  readonly providerGenerationSha256: string | null;
  readonly healthReportSha256: string | null;
}

export interface ComposeCapabilityAvailabilityProjectionInput {
  readonly modules: readonly CapabilityModuleLifecycleEnvelope[];
  readonly knownCapabilities?: readonly CapabilityDefinition[];
  readonly builtInCapabilities?: readonly CapabilityDefinition[];
  readonly selections?: readonly CapabilityProviderSelection[];
  readonly host: CapabilityProviderHostIdentity;
  readonly healthReports: readonly CapabilityProviderHealthReport[];
  readonly policyLayers?: readonly CapabilityPolicyLayer[];
  readonly checkedAt: string;
}

export interface CapabilityAvailabilityProjection {
  readonly schemaVersion: "toadaid.capability-availability-projection.v1";
  readonly checkedAt: string;
  readonly host: CapabilityProviderHostIdentity;
  readonly knownCapabilityManifest: CapabilityManifest;
  readonly installedCapabilityManifest: CapabilityManifest;
  readonly enabledCapabilityManifest: CapabilityManifest;
  readonly availableCapabilityManifest: CapabilityManifest;
  readonly authorizedCapabilityManifest: CapabilityManifest;
  readonly selections: readonly CapabilityProviderSelection[];
  readonly providers: readonly CapabilityProviderAvailabilityBinding[];
  readonly unavailableProviders: readonly CapabilityProviderUnavailableBinding[];
  readonly projectionSha256: string;
}

export interface CapabilityAvailableRuntimeProviderBinding {
  readonly moduleId: string;
  readonly adapterId: string;
  readonly providerGenerationSha256: string;
  readonly provider: GovernedCapabilityRuntimeProvider;
}

export interface CapabilityAvailableRuntimeProviderRegistry {
  readonly schemaVersion: "toadaid.capability-available-runtime-provider-registry.v1";
  readonly availabilityProjectionSha256: string;
  readonly providers: readonly CapabilityAvailableRuntimeProviderBinding[];
}

export type CapabilityRuntimeProviderForKind<
  Kind extends CapabilityProviderAdapterKind,
> = Kind extends "CONNECTOR" ? GovernedConnectorAdapter
  : Kind extends "DESKTOP_OBSERVATION" ? GovernedDesktopObservationAdapter
  : Kind extends "DESKTOP_INTERACTION" ? GovernedDesktopInteractionAdapter
  : GovernedHostServiceAdapter;
