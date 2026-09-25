import type { CapabilityAuthorityDecision, CapabilityManifest, CapabilityPolicyLayer } from "./capabilityPolicy.js";

export type RecipeScalar = string | boolean | number;
export type RecipeScalarType = "STRING" | "BOOLEAN" | "INTEGER";

export interface RecipeStringSchema {
  readonly type: "STRING";
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly enum?: readonly string[];
}

export interface RecipeBooleanSchema {
  readonly type: "BOOLEAN";
}

export interface RecipeIntegerSchema {
  readonly type: "INTEGER";
  readonly minimum?: number;
  readonly maximum?: number;
}

export type RecipeScalarSchema = RecipeStringSchema | RecipeBooleanSchema | RecipeIntegerSchema;

export interface RecipeObjectSchema {
  readonly type: "OBJECT";
  readonly properties: Readonly<Record<string, RecipeScalarSchema>>;
  readonly required?: readonly string[];
}

export type RecipeResponseSchema = RecipeScalarSchema | RecipeObjectSchema;

export interface RecipeParameterDefinition {
  readonly schema: RecipeScalarSchema;
  readonly required?: boolean;
  readonly default?: RecipeScalar;
}

export interface RecipeCapabilitySet {
  readonly required?: readonly string[];
  readonly optional?: readonly string[];
  readonly forbidden?: readonly string[];
}

export type RecipeUnavailablePolicy = "FAIL" | "SKIP";

export interface RecipeStep {
  readonly id: string;
  readonly summary: string;
  readonly capabilityId: string;
  readonly onUnavailable: RecipeUnavailablePolicy;
}

export interface GovernedRecipeDefinition {
  readonly schemaVersion: "toadaid.governed-recipe.v1";
  readonly recipeId: string;
  readonly version: string;
  readonly description: string;
  readonly parameters?: Readonly<Record<string, RecipeParameterDefinition>>;
  readonly responseSchema: RecipeResponseSchema;
  readonly maxTurns: number;
  readonly maxRetries: number;
  readonly capabilities: RecipeCapabilitySet;
  readonly steps: readonly RecipeStep[];
}

export type RecipeCapabilityRole = "REQUIRED" | "OPTIONAL" | "FORBIDDEN";
export type RecipeCapabilityCompileDecision = "ENABLED" | "UNAVAILABLE" | "FORBIDDEN";

export interface RecipeCapabilityEvidence {
  readonly capabilityId: string;
  readonly role: RecipeCapabilityRole;
  readonly currentDecision: "ALLOW" | "BLOCK";
  readonly currentReason: CapabilityAuthorityDecision["reason"];
  readonly compileDecision: RecipeCapabilityCompileDecision;
}

export type CompiledRecipeStepStatus = "ENABLED" | "SKIPPED_OPTIONAL";

export interface CompiledRecipeStep {
  readonly id: string;
  readonly summary: string;
  readonly capabilityId: string;
  readonly status: CompiledRecipeStepStatus;
}

export interface GovernedRecipePlan {
  readonly schemaVersion: "toadaid.governed-recipe-plan.v1";
  readonly recipeId: string;
  readonly recipeVersion: string;
  readonly recipeSha256: string;
  readonly planSha256: string;
  readonly compiledAt: string;
  readonly inputs: Readonly<Record<string, RecipeScalar>>;
  readonly responseSchema: RecipeResponseSchema;
  readonly maxTurns: number;
  readonly maxRetries: number;
  readonly effectiveCapabilities: readonly string[];
  readonly capabilityEvidence: readonly RecipeCapabilityEvidence[];
  readonly steps: readonly CompiledRecipeStep[];
}

export interface CompileGovernedRecipeOptions {
  readonly manifest: CapabilityManifest;
  readonly policyLayers: readonly CapabilityPolicyLayer[];
  readonly compiledAt?: string;
}

export interface RecipeCurrentAuthorityCheck {
  readonly capabilityId: string;
  readonly compiledEnabled: boolean;
  readonly currentDecision: "ALLOW" | "BLOCK";
}

export interface RecipeCurrentAuthorityReceipt {
  readonly schemaVersion: "toadaid.governed-recipe-authority-check.v1";
  readonly recipeId: string;
  readonly recipeSha256: string;
  readonly checkedAt: string;
  readonly checks: readonly RecipeCurrentAuthorityCheck[];
}
