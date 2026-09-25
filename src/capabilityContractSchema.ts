import { createHash } from "node:crypto";
import type {
  CapabilityContractDescriptor,
  CapabilityContractRegistry,
  CapabilityContractRequirement,
  CapabilityContractVersion,
  CapabilityInvocationContractBinding,
  ContractBoundRecipePlan,
  RecipeContractProfile,
} from "./capabilityContractTypes.js";

const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const CONTRACT_ID_PATTERN = /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/;
const FEATURE_PATTERN = /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*$/;
const IMPLEMENTATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const MAX_DESCRIPTORS = 256;
const MAX_FEATURES = 128;
const MAX_REQUIREMENTS = 256;

export function contractCanonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => contractCanonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${contractCanonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("capability contract contains a non-serializable value");
}

export function contractSha256(value: unknown): string {
  return createHash("sha256").update(contractCanonicalJson(value)).digest("hex");
}

function boundedVersion(input: CapabilityContractVersion, label: string): CapabilityContractVersion {
  if (typeof input !== "object" || input === null) throw new TypeError(`${label} must be an object`);
  if (!Number.isSafeInteger(input.major) || input.major < 1 || input.major > 10_000) throw new RangeError(`${label}.major must be in [1, 10000]`);
  if (!Number.isSafeInteger(input.minor) || input.minor < 0 || input.minor > 1_000_000) throw new RangeError(`${label}.minor must be in [0, 1000000]`);
  return Object.freeze({ major: input.major, minor: input.minor });
}

function capabilityId(value: string, label: string): string {
  if (!CAPABILITY_ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function contractId(value: string, label: string): string {
  if (!CONTRACT_ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function sha(value: string, label: string): string {
  if (!SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be lowercase SHA-256`);
  return value;
}

function normalizeFeatures(values: readonly string[] | undefined, label: string): readonly string[] {
  const list = values ?? [];
  if (!Array.isArray(list) || list.length > MAX_FEATURES) throw new RangeError(`${label} exceeds ${MAX_FEATURES}`);
  const seen = new Set<string>();
  const normalized = list.map((value, index) => {
    if (!FEATURE_PATTERN.test(value)) throw new TypeError(`${label}[${index}] is invalid`);
    if (seen.has(value)) throw new TypeError(`${label} contains duplicate feature: ${value}`);
    seen.add(value);
    return value;
  }).sort();
  return Object.freeze(normalized);
}

export function normalizeCapabilityContractDescriptor(input: CapabilityContractDescriptor): CapabilityContractDescriptor {
  if (input.schemaVersion !== "toadaid.capability-contract.v1") throw new TypeError("unsupported capability contract schemaVersion");
  const normalized: CapabilityContractDescriptor = {
    schemaVersion: "toadaid.capability-contract.v1",
    capabilityId: capabilityId(input.capabilityId, "capabilityId"),
    contractId: contractId(input.contractId, "contractId"),
    version: boundedVersion(input.version, "version"),
    features: normalizeFeatures(input.features, "features"),
    requestSchemaId: contractId(input.requestSchemaId, "requestSchemaId"),
    receiptSchemaId: contractId(input.receiptSchemaId, "receiptSchemaId"),
    implementation: Object.freeze({
      implementationId: (() => {
        if (!IMPLEMENTATION_ID_PATTERN.test(input.implementation.implementationId)) throw new TypeError("implementation.implementationId is invalid");
        return input.implementation.implementationId;
      })(),
      fingerprintSha256: sha(input.implementation.fingerprintSha256, "implementation.fingerprintSha256"),
    }),
    ...(input.deprecation ? (() => {
      const sinceVersion = boundedVersion(input.deprecation.sinceVersion, "deprecation.sinceVersion");
      if (sinceVersion.major > input.version.major || (sinceVersion.major === input.version.major && sinceVersion.minor > input.version.minor)) throw new RangeError("deprecation.sinceVersion cannot be newer than descriptor version");
      const replacementContractId = input.deprecation.replacementContractId ? contractId(input.deprecation.replacementContractId, "deprecation.replacementContractId") : undefined;
      if (replacementContractId === input.contractId) throw new TypeError("deprecation replacementContractId must differ from contractId");
      return { deprecation: Object.freeze({ sinceVersion, ...(replacementContractId ? { replacementContractId } : {}) }) };
    })() : {}),
  };
  return Object.freeze(normalized);
}

export function capabilityContractDescriptorSha256(input: CapabilityContractDescriptor): string {
  return contractSha256(normalizeCapabilityContractDescriptor(input));
}

export function normalizeCapabilityContractRequirement(input: CapabilityContractRequirement): Required<CapabilityContractRequirement> {
  const major = input.major;
  const minMinor = input.minMinor;
  if (!Number.isSafeInteger(major) || major < 1 || major > 10_000) throw new RangeError("requirement.major must be in [1, 10000]");
  if (!Number.isSafeInteger(minMinor) || minMinor < 0 || minMinor > 1_000_000) throw new RangeError("requirement.minMinor must be in [0, 1000000]");
  if (input.allowDeprecated !== undefined && typeof input.allowDeprecated !== "boolean") throw new TypeError("requirement.allowDeprecated must be boolean");
  return Object.freeze({
    capabilityId: capabilityId(input.capabilityId, "requirement.capabilityId"),
    contractId: contractId(input.contractId, "requirement.contractId"),
    major,
    minMinor,
    requiredFeatures: normalizeFeatures(input.requiredFeatures, "requirement.requiredFeatures"),
    allowDeprecated: input.allowDeprecated ?? false,
  });
}

export function capabilityContractRequirementSha256(input: CapabilityContractRequirement): string {
  return contractSha256(normalizeCapabilityContractRequirement(input));
}

function registryCore(registry: Omit<CapabilityContractRegistry, "registrySha256"> | CapabilityContractRegistry): Omit<CapabilityContractRegistry, "registrySha256"> {
  const { registrySha256: _ignored, ...core } = registry as CapabilityContractRegistry;
  return core;
}

export function capabilityContractRegistrySha256(registry: Omit<CapabilityContractRegistry, "registrySha256"> | CapabilityContractRegistry): string {
  return contractSha256(registryCore(registry));
}

export function createCapabilityContractRegistry(descriptorsInput: readonly CapabilityContractDescriptor[]): CapabilityContractRegistry {
  if (!Array.isArray(descriptorsInput) || descriptorsInput.length > MAX_DESCRIPTORS) throw new RangeError(`contract descriptors exceed ${MAX_DESCRIPTORS}`);
  const seenCapabilities = new Set<string>();
  const descriptors = descriptorsInput.map(normalizeCapabilityContractDescriptor).sort((a, b) => a.capabilityId.localeCompare(b.capabilityId));
  for (const descriptor of descriptors) {
    if (seenCapabilities.has(descriptor.capabilityId)) throw new TypeError(`duplicate capability contract descriptor: ${descriptor.capabilityId}`);
    seenCapabilities.add(descriptor.capabilityId);
  }
  const core = Object.freeze({ schemaVersion: "toadaid.capability-contract-registry.v1" as const, descriptors: Object.freeze(descriptors) });
  return Object.freeze({ ...core, registrySha256: capabilityContractRegistrySha256(core) });
}

export function validateCapabilityContractRegistry(registry: CapabilityContractRegistry): CapabilityContractRegistry {
  if (registry.schemaVersion !== "toadaid.capability-contract-registry.v1") throw new TypeError("unsupported capability contract registry schemaVersion");
  const rebuilt = createCapabilityContractRegistry(registry.descriptors);
  if (!SHA256_PATTERN.test(registry.registrySha256) || rebuilt.registrySha256 !== registry.registrySha256) throw new Error("capability contract registry integrity mismatch");
  return registry;
}

export function normalizeRecipeContractProfile(input: RecipeContractProfile): RecipeContractProfile {
  if (input.schemaVersion !== "toadaid.recipe-contract-profile.v1") throw new TypeError("unsupported recipe contract profile schemaVersion");
  if (typeof input.recipeId !== "string" || !/^[a-z][a-z0-9-]{1,63}$/.test(input.recipeId)) throw new TypeError("contract profile recipeId is invalid");
  if (typeof input.recipeVersion !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(input.recipeVersion)) throw new TypeError("contract profile recipeVersion is invalid");
  if (!Array.isArray(input.requirements) || input.requirements.length > MAX_REQUIREMENTS) throw new RangeError(`contract profile requirements exceed ${MAX_REQUIREMENTS}`);
  const seen = new Set<string>();
  const requirements = input.requirements.map(normalizeCapabilityContractRequirement).sort((a, b) => a.capabilityId.localeCompare(b.capabilityId));
  for (const requirement of requirements) {
    if (seen.has(requirement.capabilityId)) throw new TypeError(`duplicate contract requirement: ${requirement.capabilityId}`);
    seen.add(requirement.capabilityId);
  }
  return Object.freeze({ schemaVersion: "toadaid.recipe-contract-profile.v1", recipeId: input.recipeId, recipeVersion: input.recipeVersion, requirements: Object.freeze(requirements) });
}

export function recipeContractProfileSha256(input: RecipeContractProfile): string {
  return contractSha256(normalizeRecipeContractProfile(input));
}

function contractPlanCore(plan: Omit<ContractBoundRecipePlan, "planSha256"> | ContractBoundRecipePlan): Omit<ContractBoundRecipePlan, "planSha256"> {
  const { planSha256: _ignored, ...core } = plan as ContractBoundRecipePlan;
  return core;
}

export function contractBoundRecipePlanSha256(plan: Omit<ContractBoundRecipePlan, "planSha256"> | ContractBoundRecipePlan): string {
  return contractSha256(contractPlanCore(plan));
}

export function validateContractBoundRecipePlan(plan: ContractBoundRecipePlan): ContractBoundRecipePlan {
  if (plan.schemaVersion !== "toadaid.contract-bound-recipe-plan.v1") throw new TypeError("unsupported contract-bound recipe plan schemaVersion");
  if (!SHA256_PATTERN.test(plan.planSha256) || contractBoundRecipePlanSha256(plan) !== plan.planSha256) throw new Error("contract-bound recipe plan integrity mismatch");
  return plan;
}

function invocationBindingCore(binding: Omit<CapabilityInvocationContractBinding, "bindingSha256"> | CapabilityInvocationContractBinding): Omit<CapabilityInvocationContractBinding, "bindingSha256"> {
  const { bindingSha256: _ignored, ...core } = binding as CapabilityInvocationContractBinding;
  return core;
}

export function capabilityInvocationContractBindingSha256(binding: Omit<CapabilityInvocationContractBinding, "bindingSha256"> | CapabilityInvocationContractBinding): string {
  return contractSha256(invocationBindingCore(binding));
}

export function validateCapabilityInvocationContractBinding(binding: CapabilityInvocationContractBinding): CapabilityInvocationContractBinding {
  if (binding.schemaVersion !== "toadaid.capability-invocation-contract-binding.v1") throw new TypeError("unsupported invocation contract binding schemaVersion");
  if (!SHA256_PATTERN.test(binding.bindingSha256) || capabilityInvocationContractBindingSha256(binding) !== binding.bindingSha256) throw new Error("capability invocation contract binding integrity mismatch");
  return binding;
}
