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
  readonly implementationFingerprintSha256: string;
  readonly registration: CapabilityModuleAdapterRegistration;
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

export type CapabilityRuntimeProviderForKind<
  Kind extends CapabilityProviderAdapterKind,
> = Kind extends "CONNECTOR" ? GovernedConnectorAdapter
  : Kind extends "DESKTOP_OBSERVATION" ? GovernedDesktopObservationAdapter
  : Kind extends "DESKTOP_INTERACTION" ? GovernedDesktopInteractionAdapter
  : GovernedHostServiceAdapter;
