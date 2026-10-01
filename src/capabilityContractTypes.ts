import type { CompileGovernedRecipeOptions, GovernedRecipeDefinition, GovernedRecipePlan, RecipeCurrentAuthorityReceipt } from "./recipeTypes.js";
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";

export interface CapabilityContractVersion {
  readonly major: number;
  readonly minor: number;
}

export interface CapabilityContractSchemaBinding {
  readonly schemaId: string;
  readonly schemaSha256: string;
}

export interface CapabilityContractDeprecation {
  readonly sinceVersion: CapabilityContractVersion;
  readonly replacementContractId?: string;
}

export interface CapabilityContractDescriptor {
  readonly schemaVersion: "toadaid.capability-contract.v2";
  readonly capabilityId: string;
  readonly contractId: string;
  readonly version: CapabilityContractVersion;
  readonly features: readonly string[];
  readonly requestSchema: CapabilityContractSchemaBinding;
  readonly resultSchema: CapabilityContractSchemaBinding;
  readonly receiptSchema: CapabilityContractSchemaBinding;
  readonly deprecation?: CapabilityContractDeprecation;
}

export type CapabilityImplementationAdapterKind =
  | "CONNECTOR"
  | "DESKTOP_OBSERVATION"
  | "DESKTOP_INTERACTION"
  | "HOST_SERVICE";

export interface CapabilityProviderPlatformRequirements {
  readonly operatingSystems: readonly string[];
  readonly architectures: readonly string[];
  readonly runtimeIds: readonly string[];
}

export interface CapabilityProviderImplementationDescriptor {
  readonly schemaVersion: "toadaid.capability-provider-implementation.v1";
  readonly moduleId: string;
  readonly providerId: string;
  readonly adapterKind: CapabilityImplementationAdapterKind;
  readonly adapterId: string;
  readonly capabilityId: string;
  readonly contractId: string;
  readonly contractVersion: CapabilityContractVersion;
  readonly contractDescriptorSha256: string;
  readonly supportedFeatures: readonly string[];
  readonly platformRequirements: CapabilityProviderPlatformRequirements;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly providerDescriptorSha256: string;
}

export interface CreateCapabilityProviderImplementationDescriptorInput {
  readonly moduleId: string;
  readonly providerId: string;
  readonly adapterKind: CapabilityImplementationAdapterKind;
  readonly adapterId: string;
  readonly capabilityId: string;
  readonly contractId: string;
  readonly contractVersion: CapabilityContractVersion;
  readonly contractDescriptorSha256: string;
  readonly supportedFeatures: readonly string[];
  readonly platformRequirements?: Partial<CapabilityProviderPlatformRequirements>;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface CapabilityContractRegistry {
  readonly schemaVersion: "toadaid.capability-contract-registry.v1";
  readonly descriptors: readonly CapabilityContractDescriptor[];
  readonly registrySha256: string;
}

export interface CapabilityContractRequirement {
  readonly capabilityId: string;
  readonly contractId: string;
  readonly major: number;
  readonly minMinor: number;
  readonly requiredFeatures?: readonly string[];
  readonly allowDeprecated?: boolean;
}

export type CapabilityContractCompatibilityReason =
  | "COMPATIBLE"
  | "CAPABILITY_NOT_DISCOVERED"
  | "CONTRACT_ID_MISMATCH"
  | "MAJOR_VERSION_MISMATCH"
  | "MINOR_VERSION_TOO_OLD"
  | "MISSING_REQUIRED_FEATURE"
  | "DEPRECATED_CONTRACT";

export interface CapabilityContractCompatibilityReceipt {
  readonly schemaVersion: "toadaid.capability-contract-compatibility.v1";
  readonly capabilityId: string;
  readonly contractId: string;
  readonly requirementSha256: string;
  readonly descriptorSha256: string;
  readonly registrySha256: string;
  readonly version: CapabilityContractVersion;
  readonly features: readonly string[];
  readonly requestSchemaSha256: string;
  readonly resultSchemaSha256: string;
  readonly receiptSchemaSha256: string;
  readonly compatible: true;
  readonly reason: "COMPATIBLE";
}

export interface CapabilityContractDiscovery {
  readonly schemaVersion: "toadaid.capability-contract-discovery.v1";
  readonly registrySha256: string;
  readonly descriptors: readonly CapabilityContractDescriptor[];
}

export interface RecipeContractProfile {
  readonly schemaVersion: "toadaid.recipe-contract-profile.v1";
  readonly recipeId: string;
  readonly recipeVersion: string;
  readonly requirements: readonly CapabilityContractRequirement[];
}

export interface ContractBoundRecipePlan {
  readonly schemaVersion: "toadaid.contract-bound-recipe-plan.v1";
  readonly basePlan: GovernedRecipePlan;
  readonly profileSha256: string;
  readonly contractBindings: readonly CapabilityContractCompatibilityReceipt[];
  readonly skippedOptionalContracts: readonly string[];
  readonly planSha256: string;
}

export interface ContractBoundRecipeCurrentReceipt {
  readonly schemaVersion: "toadaid.contract-bound-recipe-current.v1";
  readonly recipeId: string;
  readonly checkedAt: string;
  readonly authority: RecipeCurrentAuthorityReceipt;
  readonly contractBindings: readonly CapabilityContractCompatibilityReceipt[];
}

export interface CompileGovernedRecipeWithContractsOptions extends CompileGovernedRecipeOptions {
  readonly contractRegistry: CapabilityContractRegistry;
  readonly contractProfile: RecipeContractProfile;
}

export interface CapabilityInvocationContractBinding {
  readonly schemaVersion: "toadaid.capability-invocation-contract-binding.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly capabilityId: string;
  readonly intentSha256: string;
  readonly requirementSha256: string;
  readonly descriptorSha256: string;
  readonly contractId: string;
  readonly version: CapabilityContractVersion;
  readonly providerDescriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly bindingSha256: string;
}

export interface CapabilityInvocationProviderBinding {
  readonly providerDescriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface CapabilityInvocationContractReadyReceipt {
  readonly schemaVersion: "toadaid.capability-invocation-contract-ready.v1";
  readonly invocationId: string;
  readonly capabilityId: string;
  readonly bindingSha256: string;
  readonly provider: CapabilityInvocationProviderBinding;
  readonly compatibility: CapabilityContractCompatibilityReceipt;
}

export interface CompileGovernedRecipeWithContractsInput {
  readonly recipe: GovernedRecipeDefinition;
  readonly rawInputs: Readonly<Record<string, unknown>>;
  readonly options: CompileGovernedRecipeWithContractsOptions;
}

export type CapabilityInvocationLike = CapabilityInvocationEnvelope;
