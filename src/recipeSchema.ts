import { createHash } from "node:crypto";
import type {
  GovernedRecipeDefinition,
  RecipeCapabilitySet,
  RecipeObjectSchema,
  RecipeParameterDefinition,
  RecipeResponseSchema,
  RecipeScalar,
  RecipeScalarSchema,
} from "./recipeTypes.js";

export const RECIPE_ID_PATTERN = /^[a-z][a-z0-9-]{1,63}$/;
export const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
export const PARAMETER_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const STEP_ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const MAX_DESCRIPTION_CHARS = 2_000;
const MAX_STEP_SUMMARY_CHARS = 1_000;
const MAX_PARAMETERS = 64;
const MAX_PROPERTIES = 64;
const MAX_CAPABILITIES_PER_ROLE = 128;
const MAX_STEPS = 256;
const MAX_STRING_CHARS = 16_384;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("recipe contains a non-serializable value");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function canonicalIso(value: string | undefined, label: string, now = () => new Date()): string {
  const resolved = value ?? now().toISOString();
  if (typeof resolved !== "string" || !resolved.trim()) throw new TypeError(`${label} must not be empty`);
  const parsed = new Date(resolved);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== resolved) throw new TypeError(`${label} must be canonical ISO-8601`);
  return resolved;
}

function boundedString(value: string, label: string, max: number): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must not be empty`);
  if (value.length > max) throw new RangeError(`${label} exceeds ${max} characters`);
  return value;
}

function exactInteger(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) throw new RangeError(`${label} must be a safe integer in [${min}, ${max}]`);
  return resolved;
}

function normalizeStringSchema(schema: RecipeScalarSchema, label: string): RecipeScalarSchema {
  if (schema.type !== "STRING") return schema;
  const minLength = exactInteger(schema.minLength, 0, 0, MAX_STRING_CHARS, `${label}.minLength`);
  const maxLength = exactInteger(schema.maxLength, MAX_STRING_CHARS, 1, MAX_STRING_CHARS, `${label}.maxLength`);
  if (minLength > maxLength) throw new RangeError(`${label}.minLength exceeds maxLength`);
  let values: readonly string[] | undefined;
  if (schema.enum !== undefined) {
    if (!Array.isArray(schema.enum) || schema.enum.length === 0 || schema.enum.length > 128) throw new RangeError(`${label}.enum must contain 1..128 values`);
    const seen = new Set<string>();
    values = Object.freeze(schema.enum.map((value, index) => {
      const normalized = boundedString(value, `${label}.enum[${index}]`, maxLength);
      if (normalized.length < minLength) throw new RangeError(`${label}.enum[${index}] is shorter than minLength`);
      if (seen.has(normalized)) throw new TypeError(`${label}.enum contains duplicate value`);
      seen.add(normalized);
      return normalized;
    }).sort());
  }
  return Object.freeze({ type: "STRING" as const, minLength, maxLength, ...(values ? { enum: values } : {}) });
}

export function normalizeRecipeScalarSchema(schema: RecipeScalarSchema, label = "schema"): RecipeScalarSchema {
  if (typeof schema !== "object" || schema === null) throw new TypeError(`${label} must be an object`);
  if (schema.type === "STRING") return normalizeStringSchema(schema, label);
  if (schema.type === "BOOLEAN") return Object.freeze({ type: "BOOLEAN" as const });
  if (schema.type === "INTEGER") {
    const minimum = exactInteger(schema.minimum, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, `${label}.minimum`);
    const maximum = exactInteger(schema.maximum, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, `${label}.maximum`);
    if (minimum > maximum) throw new RangeError(`${label}.minimum exceeds maximum`);
    return Object.freeze({ type: "INTEGER" as const, minimum, maximum });
  }
  throw new TypeError(`${label}.type is unsupported`);
}

export function validateRecipeScalar(value: unknown, schemaInput: RecipeScalarSchema, label = "value"): RecipeScalar {
  const schema = normalizeRecipeScalarSchema(schemaInput, `${label}.schema`);
  if (schema.type === "STRING") {
    if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
    if (value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? MAX_STRING_CHARS)) throw new RangeError(`${label} string length is outside schema bounds`);
    if (schema.enum && !schema.enum.includes(value)) throw new TypeError(`${label} is not an allowed enum value`);
    return value;
  }
  if (schema.type === "BOOLEAN") {
    if (typeof value !== "boolean") throw new TypeError(`${label} must be a boolean`);
    return value;
  }
  if (!Number.isSafeInteger(value) || (value as number) < (schema.minimum ?? Number.MIN_SAFE_INTEGER) || (value as number) > (schema.maximum ?? Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${label} must be an integer inside schema bounds`);
  }
  return value as number;
}

function normalizeObjectSchema(schema: RecipeObjectSchema, label: string): RecipeObjectSchema {
  const entries = Object.entries(schema.properties ?? {});
  if (entries.length > MAX_PROPERTIES) throw new RangeError(`${label}.properties exceeds ${MAX_PROPERTIES}`);
  const properties: Record<string, RecipeScalarSchema> = {};
  for (const [name, child] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    if (!PARAMETER_NAME_PATTERN.test(name)) throw new TypeError(`${label}.property name is invalid: ${name}`);
    properties[name] = normalizeRecipeScalarSchema(child, `${label}.properties.${name}`);
  }
  const required = [...new Set(schema.required ?? [])].sort();
  for (const name of required) if (!(name in properties)) throw new TypeError(`${label}.required references unknown property: ${name}`);
  return Object.freeze({ type: "OBJECT" as const, properties: Object.freeze(properties), required: Object.freeze(required) });
}

export function normalizeRecipeResponseSchema(schema: RecipeResponseSchema, label = "responseSchema"): RecipeResponseSchema {
  if (schema.type === "OBJECT") return normalizeObjectSchema(schema, label);
  return normalizeRecipeScalarSchema(schema, label);
}

export function validateRecipeResponse(value: unknown, schemaInput: RecipeResponseSchema): RecipeScalar | Readonly<Record<string, RecipeScalar>> {
  const schema = normalizeRecipeResponseSchema(schemaInput);
  if (schema.type !== "OBJECT") return validateRecipeScalar(value, schema, "response");
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("response must be an object");
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!(key in schema.properties)) throw new TypeError(`response contains undeclared field: ${key}`);
  for (const key of schema.required ?? []) if (!(key in record)) throw new TypeError(`response is missing required field: ${key}`);
  const normalized: Record<string, RecipeScalar> = {};
  for (const [key, child] of Object.entries(schema.properties)) if (key in record) normalized[key] = validateRecipeScalar(record[key], child, `response.${key}`);
  return Object.freeze(normalized);
}

function normalizeCapabilityList(values: readonly string[] | undefined, label: string): readonly string[] {
  const list = values ?? [];
  if (list.length > MAX_CAPABILITIES_PER_ROLE) throw new RangeError(`${label} exceeds ${MAX_CAPABILITIES_PER_ROLE}`);
  const seen = new Set<string>();
  const normalized = list.map((id, index) => {
    if (!CAPABILITY_ID_PATTERN.test(id)) throw new TypeError(`${label}[${index}] is not a valid capability id`);
    if (seen.has(id)) throw new TypeError(`${label} contains duplicate capability: ${id}`);
    seen.add(id);
    return id;
  });
  return Object.freeze(normalized.sort());
}

export function normalizeRecipeCapabilitySet(input: RecipeCapabilitySet): Required<RecipeCapabilitySet> {
  const required = normalizeCapabilityList(input.required, "capabilities.required");
  const optional = normalizeCapabilityList(input.optional, "capabilities.optional");
  const forbidden = normalizeCapabilityList(input.forbidden, "capabilities.forbidden");
  const roles = new Map<string, string>();
  for (const [role, list] of [["required", required], ["optional", optional], ["forbidden", forbidden]] as const) {
    for (const id of list) {
      const prior = roles.get(id);
      if (prior) throw new TypeError(`capability ${id} appears in both ${prior} and ${role}`);
      roles.set(id, role);
    }
  }
  return Object.freeze({ required, optional, forbidden });
}

function normalizeParameter(definition: RecipeParameterDefinition, label: string): RecipeParameterDefinition {
  const schema = normalizeRecipeScalarSchema(definition.schema, `${label}.schema`);
  const required = definition.required ?? false;
  if (typeof required !== "boolean") throw new TypeError(`${label}.required must be boolean`);
  if (required && definition.default !== undefined) throw new TypeError(`${label} cannot be required and have a default`);
  const defaultValue = definition.default === undefined ? undefined : validateRecipeScalar(definition.default, schema, `${label}.default`);
  return Object.freeze({ schema, required, ...(defaultValue === undefined ? {} : { default: defaultValue }) });
}

export function normalizeGovernedRecipeDefinition(input: GovernedRecipeDefinition): GovernedRecipeDefinition {
  if (input.schemaVersion !== "toadaid.governed-recipe.v1") throw new TypeError("unsupported governed recipe schemaVersion");
  if (!RECIPE_ID_PATTERN.test(input.recipeId)) throw new TypeError("recipeId is invalid");
  if (!VERSION_PATTERN.test(input.version)) throw new TypeError("recipe version is invalid");
  const description = boundedString(input.description, "description", MAX_DESCRIPTION_CHARS);
  const maxTurns = exactInteger(input.maxTurns, 16, 1, 256, "maxTurns");
  const maxRetries = exactInteger(input.maxRetries, 0, 0, 16, "maxRetries");
  const capabilities = normalizeRecipeCapabilitySet(input.capabilities);
  const parameterEntries = Object.entries(input.parameters ?? {});
  if (parameterEntries.length > MAX_PARAMETERS) throw new RangeError(`parameters exceeds ${MAX_PARAMETERS}`);
  const parameters: Record<string, RecipeParameterDefinition> = {};
  for (const [name, definition] of parameterEntries.sort(([a], [b]) => a.localeCompare(b))) {
    if (!PARAMETER_NAME_PATTERN.test(name)) throw new TypeError(`parameter name is invalid: ${name}`);
    parameters[name] = normalizeParameter(definition, `parameters.${name}`);
  }
  if (!Array.isArray(input.steps) || input.steps.length === 0 || input.steps.length > MAX_STEPS) throw new RangeError(`steps must contain 1..${MAX_STEPS} items`);
  const requiredSet = new Set(capabilities.required);
  const optionalSet = new Set(capabilities.optional);
  const stepIds = new Set<string>();
  const steps = input.steps.map((step, index) => {
    if (!STEP_ID_PATTERN.test(step.id)) throw new TypeError(`steps[${index}].id is invalid`);
    if (stepIds.has(step.id)) throw new TypeError(`duplicate recipe step id: ${step.id}`);
    stepIds.add(step.id);
    if (!CAPABILITY_ID_PATTERN.test(step.capabilityId)) throw new TypeError(`steps[${index}].capabilityId is invalid`);
    if (!requiredSet.has(step.capabilityId) && !optionalSet.has(step.capabilityId)) throw new TypeError(`step ${step.id} uses capability not declared required/optional: ${step.capabilityId}`);
    if (requiredSet.has(step.capabilityId) && step.onUnavailable !== "FAIL") throw new TypeError(`required capability step ${step.id} must use onUnavailable=FAIL`);
    if (optionalSet.has(step.capabilityId) && step.onUnavailable !== "SKIP") throw new TypeError(`optional capability step ${step.id} must use onUnavailable=SKIP`);
    return Object.freeze({ id: step.id, summary: boundedString(step.summary, `steps[${index}].summary`, MAX_STEP_SUMMARY_CHARS), capabilityId: step.capabilityId, onUnavailable: step.onUnavailable });
  });
  return Object.freeze({
    schemaVersion: "toadaid.governed-recipe.v1" as const,
    recipeId: input.recipeId,
    version: input.version,
    description,
    parameters: Object.freeze(parameters),
    responseSchema: normalizeRecipeResponseSchema(input.responseSchema),
    maxTurns,
    maxRetries,
    capabilities,
    steps: Object.freeze(steps),
  });
}

export function normalizeRecipeInputs(recipeInput: GovernedRecipeDefinition, raw: Readonly<Record<string, unknown>>): Readonly<Record<string, RecipeScalar>> {
  const recipe = normalizeGovernedRecipeDefinition(recipeInput);
  for (const key of Object.keys(raw)) if (!(key in (recipe.parameters ?? {}))) throw new TypeError(`recipe input contains undeclared parameter: ${key}`);
  const output: Record<string, RecipeScalar> = {};
  for (const [name, definition] of Object.entries(recipe.parameters ?? {})) {
    if (name in raw) output[name] = validateRecipeScalar(raw[name], definition.schema, `inputs.${name}`);
    else if (definition.default !== undefined) output[name] = definition.default;
    else if (definition.required) throw new TypeError(`recipe input is missing required parameter: ${name}`);
  }
  return Object.freeze(output);
}
