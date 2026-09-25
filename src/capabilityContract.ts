import type { GovernedRecipeDefinition } from "./recipeTypes.js";
import { resolveCapabilityAuthority } from "./capabilityPolicy.js";
import { assertGovernedRecipePlanCurrent, compileGovernedRecipe } from "./recipeCompiler.js";
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";
import {
  capabilityContractDescriptorSha256,
  capabilityContractRequirementSha256,
  capabilityInvocationContractBindingSha256,
  contractBoundRecipePlanSha256,
  createCapabilityContractRegistry,
  normalizeCapabilityContractDescriptor,
  normalizeCapabilityContractRequirement,
  normalizeRecipeContractProfile,
  recipeContractProfileSha256,
  validateCapabilityContractRegistry,
  validateCapabilityInvocationContractBinding,
  validateContractBoundRecipePlan,
} from "./capabilityContractSchema.js";
import type {
  CapabilityContractCompatibilityReason,
  CapabilityContractCompatibilityReceipt,
  CapabilityContractDescriptor,
  CapabilityContractDiscovery,
  CapabilityContractRegistry,
  CapabilityContractRequirement,
  CapabilityInvocationContractBinding,
  CapabilityInvocationContractReadyReceipt,
  CompileGovernedRecipeWithContractsOptions,
  ContractBoundRecipeCurrentReceipt,
  ContractBoundRecipePlan,
  RecipeContractProfile,
} from "./capabilityContractTypes.js";

export {
  capabilityContractDescriptorSha256,
  capabilityContractRegistrySha256,
  capabilityContractRequirementSha256,
  capabilityInvocationContractBindingSha256,
  contractBoundRecipePlanSha256,
  createCapabilityContractRegistry,
  normalizeCapabilityContractDescriptor,
  normalizeCapabilityContractRequirement,
  normalizeRecipeContractProfile,
  recipeContractProfileSha256,
  validateCapabilityContractRegistry,
  validateCapabilityInvocationContractBinding,
  validateContractBoundRecipePlan,
} from "./capabilityContractSchema.js";
export type * from "./capabilityContractTypes.js";

export class CapabilityContractCompatibilityError extends Error {
  readonly reason: Exclude<CapabilityContractCompatibilityReason, "COMPATIBLE">;
  readonly capabilityId: string;
  constructor(capabilityId: string, reason: Exclude<CapabilityContractCompatibilityReason, "COMPATIBLE">, detail: string) {
    super(`capability contract incompatible: ${capabilityId} (${reason}): ${detail}`);
    this.name = "CapabilityContractCompatibilityError";
    this.capabilityId = capabilityId;
    this.reason = reason;
  }
}

function descriptorFor(registryInput: CapabilityContractRegistry, capabilityId: string): CapabilityContractDescriptor | undefined {
  const registry = validateCapabilityContractRegistry(registryInput);
  return registry.descriptors.find((descriptor) => descriptor.capabilityId === capabilityId);
}

export function discoverCapabilityContracts(registryInput: CapabilityContractRegistry, capabilityIds?: readonly string[]): CapabilityContractDiscovery {
  const registry = validateCapabilityContractRegistry(registryInput);
  const filter = capabilityIds === undefined ? null : new Set(capabilityIds);
  const descriptors = filter === null ? registry.descriptors : registry.descriptors.filter((descriptor) => filter.has(descriptor.capabilityId));
  return Object.freeze({ schemaVersion: "toadaid.capability-contract-discovery.v1", registrySha256: registry.registrySha256, descriptors: Object.freeze([...descriptors]) });
}

export function assertCapabilityContractCompatible(
  registryInput: CapabilityContractRegistry,
  requirementInput: CapabilityContractRequirement,
): CapabilityContractCompatibilityReceipt {
  const registry = validateCapabilityContractRegistry(registryInput);
  const requirement = normalizeCapabilityContractRequirement(requirementInput);
  const descriptor = descriptorFor(registry, requirement.capabilityId);
  if (!descriptor) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "CAPABILITY_NOT_DISCOVERED", "no descriptor is registered");
  if (descriptor.contractId !== requirement.contractId) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "CONTRACT_ID_MISMATCH", `${descriptor.contractId} != ${requirement.contractId}`);
  if (descriptor.version.major !== requirement.major) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "MAJOR_VERSION_MISMATCH", `${descriptor.version.major} != ${requirement.major}`);
  if (descriptor.version.minor < requirement.minMinor) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "MINOR_VERSION_TOO_OLD", `${descriptor.version.minor} < ${requirement.minMinor}`);
  const missing = requirement.requiredFeatures.filter((feature) => !descriptor.features.includes(feature));
  if (missing.length > 0) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "MISSING_REQUIRED_FEATURE", missing.join(","));
  if (descriptor.deprecation && !requirement.allowDeprecated) throw new CapabilityContractCompatibilityError(requirement.capabilityId, "DEPRECATED_CONTRACT", `deprecated since ${descriptor.deprecation.sinceVersion.major}.${descriptor.deprecation.sinceVersion.minor}`);
  return Object.freeze({
    schemaVersion: "toadaid.capability-contract-compatibility.v1",
    capabilityId: descriptor.capabilityId,
    contractId: descriptor.contractId,
    requirementSha256: capabilityContractRequirementSha256(requirement),
    descriptorSha256: capabilityContractDescriptorSha256(descriptor),
    registrySha256: registry.registrySha256,
    version: descriptor.version,
    features: descriptor.features,
    implementationFingerprintSha256: descriptor.implementation.fingerprintSha256,
    compatible: true,
    reason: "COMPATIBLE",
  });
}

function validateProfileCoverage(recipe: GovernedRecipeDefinition, profileInput: RecipeContractProfile): RecipeContractProfile {
  const profile = normalizeRecipeContractProfile(profileInput);
  if (profile.recipeId !== recipe.recipeId || profile.recipeVersion !== recipe.version) throw new Error("recipe contract profile does not match recipe identity/version");
  const expected = new Set([...(recipe.capabilities.required ?? []), ...(recipe.capabilities.optional ?? [])]);
  const actual = new Set(profile.requirements.map((item) => item.capabilityId));
  for (const capabilityId of expected) if (!actual.has(capabilityId)) throw new Error(`recipe contract profile is missing capability: ${capabilityId}`);
  for (const capabilityId of actual) if (!expected.has(capabilityId)) throw new Error(`recipe contract profile contains undeclared/forbidden capability: ${capabilityId}`);
  return profile;
}

export function compileGovernedRecipeWithContracts(
  recipe: GovernedRecipeDefinition,
  rawInputs: Readonly<Record<string, unknown>>,
  options: CompileGovernedRecipeWithContractsOptions,
): ContractBoundRecipePlan {
  const profile = validateProfileCoverage(recipe, options.contractProfile);
  const optional = new Set(recipe.capabilities.optional ?? []);
  const prechecked = new Map<string, CapabilityContractCompatibilityReceipt>();
  const skippedForAbsentRuntime = new Set<string>();
  for (const requirement of profile.requirements) {
    const descriptor = descriptorFor(options.contractRegistry, requirement.capabilityId);
    if (!descriptor && optional.has(requirement.capabilityId)) {
      const authority = resolveCapabilityAuthority(requirement.capabilityId, options.manifest, options.policyLayers);
      if (!authority.installed) { skippedForAbsentRuntime.add(requirement.capabilityId); continue; }
    }
    prechecked.set(requirement.capabilityId, assertCapabilityContractCompatible(options.contractRegistry, requirement));
  }
  const basePlan = compileGovernedRecipe(recipe, rawInputs, options);
  const enabled = new Set(basePlan.effectiveCapabilities);
  const bindings = profile.requirements.filter((requirement) => enabled.has(requirement.capabilityId)).map((requirement) => {
    const receipt = prechecked.get(requirement.capabilityId);
    if (!receipt) throw new Error(`enabled recipe capability has no compatible contract: ${requirement.capabilityId}`);
    return receipt;
  });
  const skippedOptionalContracts = [...optional].filter((capabilityId) => !enabled.has(capabilityId)).sort();
  for (const capabilityId of skippedForAbsentRuntime) if (!skippedOptionalContracts.includes(capabilityId)) throw new Error(`absent optional contract unexpectedly became enabled: ${capabilityId}`);
  const core = Object.freeze({
    schemaVersion: "toadaid.contract-bound-recipe-plan.v1" as const,
    basePlan,
    profileSha256: recipeContractProfileSha256(profile),
    contractBindings: Object.freeze(bindings),
    skippedOptionalContracts: Object.freeze(skippedOptionalContracts),
  });
  return Object.freeze({ ...core, planSha256: contractBoundRecipePlanSha256(core) });
}

export function assertContractBoundRecipePlanCurrent(
  planInput: ContractBoundRecipePlan,
  recipe: GovernedRecipeDefinition,
  options: CompileGovernedRecipeWithContractsOptions,
): ContractBoundRecipeCurrentReceipt {
  const plan = validateContractBoundRecipePlan(planInput);
  const profile = validateProfileCoverage(recipe, options.contractProfile);
  if (plan.profileSha256 !== recipeContractProfileSha256(profile)) throw new Error("contract-bound recipe profile changed; recompile required");
  const authority = assertGovernedRecipePlanCurrent(plan.basePlan, recipe, options);
  const priorByCapability = new Map(plan.contractBindings.map((binding) => [binding.capabilityId, binding]));
  const enabled = new Set(plan.basePlan.effectiveCapabilities);
  const expectedSkipped = [...(recipe.capabilities.optional ?? [])].filter((capabilityId) => !enabled.has(capabilityId)).sort();
  if (JSON.stringify(expectedSkipped) !== JSON.stringify([...plan.skippedOptionalContracts].sort())) throw new Error("compiled skipped optional contract set mismatch");
  const current = profile.requirements.filter((requirement) => enabled.has(requirement.capabilityId)).map((requirement) => {
    const receipt = assertCapabilityContractCompatible(options.contractRegistry, requirement);
    const prior = priorByCapability.get(requirement.capabilityId);
    if (!prior) throw new Error(`compiled contract binding missing: ${requirement.capabilityId}`);
    if (prior.requirementSha256 !== receipt.requirementSha256) throw new Error(`capability contract requirement changed; recompile required: ${requirement.capabilityId}`);
    if (prior.descriptorSha256 !== receipt.descriptorSha256) throw new Error(`capability contract descriptor changed; recompile required: ${requirement.capabilityId}`);
    return receipt;
  });
  if (current.length !== plan.contractBindings.length) throw new Error("compiled contract binding count mismatch");
  return Object.freeze({
    schemaVersion: "toadaid.contract-bound-recipe-current.v1",
    recipeId: recipe.recipeId,
    checkedAt: authority.checkedAt,
    authority,
    contractBindings: Object.freeze(current),
  });
}

function assertInvocationShape(envelope: CapabilityInvocationEnvelope): void {
  if (envelope.schemaVersion !== "toadaid.capability-invocation-envelope.v1") throw new TypeError("unsupported capability invocation envelope schemaVersion");
  if (envelope.record.schemaVersion !== "toadaid.capability-invocation.v1") throw new TypeError("unsupported capability invocation schemaVersion");
}

export function createCapabilityInvocationContractBinding(
  envelope: CapabilityInvocationEnvelope,
  requirementInput: CapabilityContractRequirement,
  registry: CapabilityContractRegistry,
): CapabilityInvocationContractBinding {
  assertInvocationShape(envelope);
  const requirement = normalizeCapabilityContractRequirement(requirementInput);
  if (requirement.capabilityId !== envelope.record.capabilityId) throw new Error("invocation capability does not match contract requirement");
  const compatibility = assertCapabilityContractCompatible(registry, requirement);
  const core = Object.freeze({
    schemaVersion: "toadaid.capability-invocation-contract-binding.v1" as const,
    invocationId: envelope.record.invocationId,
    runId: envelope.record.runId,
    capabilityId: envelope.record.capabilityId,
    intentSha256: envelope.record.request.intentSha256,
    requirementSha256: compatibility.requirementSha256,
    descriptorSha256: compatibility.descriptorSha256,
    contractId: compatibility.contractId,
    version: compatibility.version,
  });
  return Object.freeze({ ...core, bindingSha256: capabilityInvocationContractBindingSha256(core) });
}

export function assertCapabilityInvocationContractReady(
  bindingInput: CapabilityInvocationContractBinding,
  envelope: CapabilityInvocationEnvelope,
  requirementInput: CapabilityContractRequirement,
  registry: CapabilityContractRegistry,
): CapabilityInvocationContractReadyReceipt {
  const binding = validateCapabilityInvocationContractBinding(bindingInput);
  assertInvocationShape(envelope);
  if (envelope.record.status !== "AUTHORIZED") throw new Error("capability invocation must be AUTHORIZED before contract-ready check");
  if (binding.invocationId !== envelope.record.invocationId || binding.runId !== envelope.record.runId || binding.capabilityId !== envelope.record.capabilityId || binding.intentSha256 !== envelope.record.request.intentSha256) {
    throw new Error("capability invocation contract binding does not match current invocation identity/intent");
  }
  const requirement = normalizeCapabilityContractRequirement(requirementInput);
  if (binding.requirementSha256 !== capabilityContractRequirementSha256(requirement)) throw new Error("capability invocation contract requirement changed; create a new binding");
  const compatibility = assertCapabilityContractCompatible(registry, requirement);
  if (binding.descriptorSha256 !== compatibility.descriptorSha256) throw new Error("capability invocation contract descriptor changed; create a new binding");
  return Object.freeze({
    schemaVersion: "toadaid.capability-invocation-contract-ready.v1",
    invocationId: binding.invocationId,
    capabilityId: binding.capabilityId,
    bindingSha256: binding.bindingSha256,
    compatibility,
  });
}
