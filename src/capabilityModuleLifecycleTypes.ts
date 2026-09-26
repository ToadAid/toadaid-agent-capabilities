import type {
  CapabilityDefinition,
  CapabilityManifest,
} from "./capabilityPolicy.js";
import type {
  CapabilityContractDescriptor,
  CapabilityContractRegistry,
} from "./capabilityContractTypes.js";
import type {
  ConnectorAdapterRegistration,
} from "./connectorAdapterTypes.js";

export interface CapabilityModuleOwnedResource {
  readonly resourceId: string;
  readonly fingerprintSha256: string;
}

export interface CapabilityModuleInspectionEvidenceRef {
  readonly id: string;
  readonly sha256: string;
}

export interface CreateCapabilityModuleManifestInput {
  readonly moduleId: string;
  readonly version: string;
  readonly capabilities: readonly CapabilityDefinition[];
  readonly contractDescriptors?: readonly CapabilityContractDescriptor[];
  readonly adapters?: readonly ConnectorAdapterRegistration[];
  readonly ownedResources?: readonly CapabilityModuleOwnedResource[];
}

export interface CapabilityModuleManifest {
  readonly schemaVersion: "toadaid.capability-module-manifest.v1";
  readonly moduleId: string;
  readonly version: string;
  readonly capabilityManifest: CapabilityManifest;
  readonly contractRegistry: CapabilityContractRegistry;
  readonly adapters: readonly ConnectorAdapterRegistration[];
  readonly ownedResources: readonly CapabilityModuleOwnedResource[];
  readonly manifestSha256: string;
}

export type CapabilityModuleState =
  | "INSTALLED_DISABLED"
  | "INSTALLED_ENABLED"
  | "REMOVED";

export type CapabilityModuleTransition =
  | "INSTALL"
  | "ENABLE"
  | "DISABLE"
  | "UPDATE"
  | "REMOVE";

export interface CapabilityModuleLifecycleRecord {
  readonly schemaVersion: "toadaid.capability-module-lifecycle.v1";
  readonly moduleId: string;
  readonly revision: number;
  readonly state: CapabilityModuleState;
  readonly transition: CapabilityModuleTransition;
  readonly manifest: CapabilityModuleManifest;
  readonly manifestSha256: string;
  readonly inspectionEvidenceRefs: readonly CapabilityModuleInspectionEvidenceRef[];
  readonly removalResourceIds: readonly string[];
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly continuity: {
    readonly previousRecordSha256: string | null;
  };
}

export interface CapabilityModuleLifecycleEnvelope {
  readonly schemaVersion: "toadaid.capability-module-lifecycle-envelope.v1";
  readonly record: CapabilityModuleLifecycleRecord;
  readonly recordSha256: string;
}

export interface CapabilityModuleRuntime {
  readonly now?: () => Date;
}

export interface InstallCapabilityModuleInput {
  readonly inspectionEvidenceRefs?: readonly CapabilityModuleInspectionEvidenceRef[];
  readonly installedAt?: string;
}

export interface UpdateCapabilityModuleInput {
  readonly observedOwnedResources: readonly CapabilityModuleOwnedResource[];
  readonly inspectionEvidenceRefs?: readonly CapabilityModuleInspectionEvidenceRef[];
  readonly updatedAt?: string;
}

export interface RemoveCapabilityModuleInput {
  readonly observedOwnedResources: readonly CapabilityModuleOwnedResource[];
  readonly removedAt?: string;
}

export interface CapabilityModuleRegistrationProjection {
  readonly schemaVersion: "toadaid.capability-module-registration-projection.v1";
  readonly moduleId: string;
  readonly version: string;
  readonly manifestSha256: string;
  readonly lifecycleRecordSha256: string;
  readonly capabilityManifest: CapabilityManifest;
  readonly contractRegistry: CapabilityContractRegistry;
  readonly adapters: readonly ConnectorAdapterRegistration[];
}
