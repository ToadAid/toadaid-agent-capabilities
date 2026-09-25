import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import { resolveCapabilityAuthority } from "./capabilityPolicy.js";
import {
  canonicalIso,
  normalizeGovernedRecipeDefinition,
  normalizeRecipeInputs,
  normalizeRecipeResponseSchema,
  sha256,
  validateRecipeResponse,
} from "./recipeSchema.js";
import type {
  CompileGovernedRecipeOptions,
  GovernedRecipeDefinition,
  GovernedRecipePlan,
  RecipeCapabilityEvidence,
  RecipeCapabilityRole,
  RecipeCurrentAuthorityReceipt,
  RecipeScalar,
} from "./recipeTypes.js";

export {
  normalizeGovernedRecipeDefinition,
  normalizeRecipeInputs,
  normalizeRecipeResponseSchema,
  validateRecipeResponse,
} from "./recipeSchema.js";
export type {
  CompileGovernedRecipeOptions,
  CompiledRecipeStep,
  CompiledRecipeStepStatus,
  GovernedRecipeDefinition,
  GovernedRecipePlan,
  RecipeBooleanSchema,
  RecipeCapabilityCompileDecision,
  RecipeCapabilityEvidence,
  RecipeCapabilityRole,
  RecipeCapabilitySet,
  RecipeCurrentAuthorityCheck,
  RecipeCurrentAuthorityReceipt,
  RecipeIntegerSchema,
  RecipeObjectSchema,
  RecipeParameterDefinition,
  RecipeResponseSchema,
  RecipeScalar,
  RecipeScalarSchema,
  RecipeScalarType,
  RecipeStep,
  RecipeStringSchema,
  RecipeUnavailablePolicy,
} from "./recipeTypes.js";

function compactAuthority(decision: CapabilityAuthorityDecision, role: RecipeCapabilityRole): RecipeCapabilityEvidence {
  let compileDecision: RecipeCapabilityEvidence["compileDecision"];
  if (role === "FORBIDDEN") compileDecision = "FORBIDDEN";
  else compileDecision = decision.decision === "ALLOW" ? "ENABLED" : "UNAVAILABLE";
  return Object.freeze({
    capabilityId: decision.capabilityId,
    role,
    currentDecision: decision.decision,
    currentReason: decision.reason,
    compileDecision,
  });
}

export function governedRecipeSha256(recipeInput: GovernedRecipeDefinition): string {
  return sha256(normalizeGovernedRecipeDefinition(recipeInput));
}

function planCore(plan: Omit<GovernedRecipePlan, "planSha256"> | GovernedRecipePlan): Omit<GovernedRecipePlan, "planSha256"> {
  const { planSha256: _ignored, ...core } = plan as GovernedRecipePlan;
  return core;
}

export function governedRecipePlanSha256(plan: Omit<GovernedRecipePlan, "planSha256"> | GovernedRecipePlan): string {
  return sha256(planCore(plan));
}

export function validateGovernedRecipePlanIntegrity(plan: GovernedRecipePlan): GovernedRecipePlan {
  if (plan.schemaVersion !== "toadaid.governed-recipe-plan.v1") throw new TypeError("unsupported governed recipe plan schemaVersion");
  if (!/^[0-9a-f]{64}$/.test(plan.planSha256) || governedRecipePlanSha256(plan) !== plan.planSha256) {
    throw new Error("governed recipe plan integrity mismatch");
  }
  return plan;
}

export function compileGovernedRecipe(
  recipeInput: GovernedRecipeDefinition,
  rawInputs: Readonly<Record<string, unknown>>,
  options: CompileGovernedRecipeOptions,
): GovernedRecipePlan {
  const recipe = normalizeGovernedRecipeDefinition(recipeInput);
  const inputs = normalizeRecipeInputs(recipe, rawInputs);
  const compiledAt = canonicalIso(options.compiledAt, "compiledAt");
  const evidence: RecipeCapabilityEvidence[] = [];
  const enabled = new Set<string>();
  const unavailableOptional = new Set<string>();

  const process = (capabilityId: string, role: RecipeCapabilityRole): void => {
    const decision = resolveCapabilityAuthority(capabilityId, options.manifest, options.policyLayers);
    const row = compactAuthority(decision, role);
    evidence.push(row);
    if (role === "REQUIRED") {
      if (!decision.installed) throw new Error(`recipe required capability is not installed: ${capabilityId}`);
      if (decision.decision !== "ALLOW") throw new Error(`recipe required capability is not authorized: ${capabilityId} (${decision.reason})`);
      enabled.add(capabilityId);
    } else if (role === "OPTIONAL") {
      if (decision.installed && decision.decision === "ALLOW") enabled.add(capabilityId);
      else unavailableOptional.add(capabilityId);
    }
  };

  for (const capabilityId of recipe.capabilities.required ?? []) process(capabilityId, "REQUIRED");
  for (const capabilityId of recipe.capabilities.optional ?? []) process(capabilityId, "OPTIONAL");
  for (const capabilityId of recipe.capabilities.forbidden ?? []) process(capabilityId, "FORBIDDEN");

  const steps = recipe.steps.map((step) => Object.freeze({
    id: step.id,
    summary: step.summary,
    capabilityId: step.capabilityId,
    status: unavailableOptional.has(step.capabilityId) ? "SKIPPED_OPTIONAL" as const : "ENABLED" as const,
  }));

  const core = Object.freeze({
    schemaVersion: "toadaid.governed-recipe-plan.v1" as const,
    recipeId: recipe.recipeId,
    recipeVersion: recipe.version,
    recipeSha256: sha256(recipe),
    compiledAt,
    inputs,
    responseSchema: recipe.responseSchema,
    maxTurns: recipe.maxTurns,
    maxRetries: recipe.maxRetries,
    effectiveCapabilities: Object.freeze([...enabled].sort()),
    capabilityEvidence: Object.freeze(evidence.sort((a, b) => a.capabilityId.localeCompare(b.capabilityId))),
    steps: Object.freeze(steps),
  });
  return Object.freeze({ ...core, planSha256: governedRecipePlanSha256(core) });
}

export function assertGovernedRecipePlanCurrent(
  plan: GovernedRecipePlan,
  recipeInput: GovernedRecipeDefinition,
  options: CompileGovernedRecipeOptions,
): RecipeCurrentAuthorityReceipt {
  validateGovernedRecipePlanIntegrity(plan);
  const recipe = normalizeGovernedRecipeDefinition(recipeInput);
  const digest = sha256(recipe);
  if (plan.recipeId !== recipe.recipeId || plan.recipeVersion !== recipe.version || plan.recipeSha256 !== digest) {
    throw new Error("governed recipe plan does not match recipe definition");
  }
  const checkedAt = canonicalIso(options.compiledAt, "checkedAt");
  const enabled = new Set(plan.effectiveCapabilities);
  const declared = new Set([...(recipe.capabilities.required ?? []), ...(recipe.capabilities.optional ?? [])]);
  for (const capabilityId of enabled) if (!declared.has(capabilityId)) throw new Error(`compiled plan contains undeclared capability: ${capabilityId}`);

  const checks = [...declared].sort().map((capabilityId) => {
    const current = resolveCapabilityAuthority(capabilityId, options.manifest, options.policyLayers);
    const compiledEnabled = enabled.has(capabilityId);
    if (compiledEnabled && current.decision !== "ALLOW") throw new Error(`compiled recipe capability is no longer authorized: ${capabilityId}`);
    return Object.freeze({ capabilityId, compiledEnabled, currentDecision: current.decision });
  });

  for (const step of plan.steps) {
    if (step.status === "ENABLED" && !enabled.has(step.capabilityId)) throw new Error(`enabled recipe step is missing compiled capability: ${step.id}`);
    if (step.status === "SKIPPED_OPTIONAL" && enabled.has(step.capabilityId)) throw new Error(`skipped recipe step conflicts with compiled capability set: ${step.id}`);
  }

  return Object.freeze({
    schemaVersion: "toadaid.governed-recipe-authority-check.v1" as const,
    recipeId: plan.recipeId,
    recipeSha256: plan.recipeSha256,
    checkedAt,
    checks: Object.freeze(checks),
  });
}

export function validateGovernedRecipeResult(
  plan: GovernedRecipePlan,
  result: unknown,
): RecipeScalar | Readonly<Record<string, RecipeScalar>> {
  validateGovernedRecipePlanIntegrity(plan);
  return validateRecipeResponse(result, plan.responseSchema);
}
