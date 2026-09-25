import { createHash } from "node:crypto";

import type {
  HumanInterruptReason,
  HumanInterruptResponse,
  HumanInterruptResponseScalar,
  HumanInterruptResponseSchema,
  HumanInterruptScalarSchema,
} from "./humanInterruptTypes.js";

export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PROPERTY_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
export const MAX_PROMPT_CHARS = 8_000;
export const MAX_RESPONDER_CHARS = 256;
const MAX_SCHEMA_PROPERTIES = 32;
const MAX_STRING_RESPONSE_CHARS = 8_000;
const MAX_ENUM_VALUES = 64;
export const MAX_SERIALIZED_BYTES = 128 * 1024;

export function boundedString(value: string, label: string, maximum: number): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${label} must not be empty`);
  if (normalized.length > maximum) throw new RangeError(`${label} exceeds ${maximum} characters`);
  return normalized;
}

export function assertId(value: string, label: string): string {
  if (!ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function canonicalIso(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must not be empty`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("non-finite number is not serializable");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("human interrupt contains a non-serializable value");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

export function exactInteger(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function normalizeScalarSchema(schema: HumanInterruptScalarSchema, label: string): HumanInterruptScalarSchema {
  if (schema.type === "boolean") return Object.freeze({ type: "boolean" });
  if (schema.type === "integer") {
    const minimum = schema.minimum;
    const maximum = schema.maximum;
    if (minimum !== undefined && !Number.isSafeInteger(minimum)) throw new TypeError(`${label}.minimum must be a safe integer`);
    if (maximum !== undefined && !Number.isSafeInteger(maximum)) throw new TypeError(`${label}.maximum must be a safe integer`);
    if (minimum !== undefined && maximum !== undefined && minimum > maximum) throw new RangeError(`${label}.minimum must not exceed maximum`);
    return Object.freeze({
      type: "integer",
      ...(minimum === undefined ? {} : { minimum }),
      ...(maximum === undefined ? {} : { maximum }),
    });
  }
  if (schema.type !== "string") throw new TypeError(`${label}.type is invalid`);
  const minLength = exactInteger(schema.minLength, 0, 0, MAX_STRING_RESPONSE_CHARS, `${label}.minLength`);
  const maxLength = exactInteger(schema.maxLength, MAX_STRING_RESPONSE_CHARS, 1, MAX_STRING_RESPONSE_CHARS, `${label}.maxLength`);
  if (minLength > maxLength) throw new RangeError(`${label}.minLength must not exceed maxLength`);
  let enumValues: readonly string[] | undefined;
  if (schema.enum !== undefined) {
    if (!Array.isArray(schema.enum) || schema.enum.length === 0 || schema.enum.length > MAX_ENUM_VALUES) {
      throw new RangeError(`${label}.enum must contain between 1 and ${MAX_ENUM_VALUES} values`);
    }
    const seen = new Set<string>();
    enumValues = Object.freeze(schema.enum.map((value, index) => {
      if (typeof value !== "string") throw new TypeError(`${label}.enum[${index}] must be a string`);
      if (value.length < minLength || value.length > maxLength) throw new RangeError(`${label}.enum[${index}] violates length bounds`);
      if (seen.has(value)) throw new TypeError(`${label}.enum contains a duplicate value`);
      seen.add(value);
      return value;
    }));
  }
  return Object.freeze({ type: "string", minLength, maxLength, ...(enumValues === undefined ? {} : { enum: enumValues }) });
}

export function normalizeHumanInterruptResponseSchema(schema: HumanInterruptResponseSchema): HumanInterruptResponseSchema {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema)) throw new TypeError("responseSchema must be an object");
  if (schema.type !== "object") return normalizeScalarSchema(schema, "responseSchema");
  const entries = Object.entries(schema.properties ?? {});
  if (entries.length === 0 || entries.length > MAX_SCHEMA_PROPERTIES) {
    throw new RangeError(`responseSchema.properties must contain between 1 and ${MAX_SCHEMA_PROPERTIES} entries`);
  }
  const properties: Record<string, HumanInterruptScalarSchema> = {};
  for (const [key, value] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    if (!PROPERTY_PATTERN.test(key)) throw new TypeError(`responseSchema property name is invalid: ${key}`);
    properties[key] = normalizeScalarSchema(value, `responseSchema.properties.${key}`);
  }
  const requiredInput = schema.required ?? [];
  if (!Array.isArray(requiredInput)) throw new TypeError("responseSchema.required must be an array");
  const required = [...new Set(requiredInput)].sort();
  for (const key of required) {
    if (!PROPERTY_PATTERN.test(key) || properties[key] === undefined) {
      throw new TypeError(`responseSchema.required references unknown property: ${key}`);
    }
  }
  if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) {
    throw new TypeError("responseSchema.additionalProperties must be false when provided");
  }
  return Object.freeze({ type: "object", properties: Object.freeze(properties), required: Object.freeze(required), additionalProperties: false });
}

function validateScalarResponse(value: unknown, schema: HumanInterruptScalarSchema, label: string): HumanInterruptResponseScalar {
  if (schema.type === "boolean") {
    if (typeof value !== "boolean") throw new TypeError(`${label} must be a boolean`);
    return value;
  }
  if (schema.type === "integer") {
    if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new TypeError(`${label} must be a safe integer`);
    if (schema.minimum !== undefined && value < schema.minimum) throw new RangeError(`${label} is below minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) throw new RangeError(`${label} exceeds maximum`);
    return value;
  }
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const minLength = schema.minLength ?? 0;
  const maxLength = schema.maxLength ?? MAX_STRING_RESPONSE_CHARS;
  if (value.length < minLength || value.length > maxLength) throw new RangeError(`${label} violates string length bounds`);
  if (schema.enum && !schema.enum.includes(value)) throw new TypeError(`${label} is not an allowed enum value`);
  return value;
}

export function validateHumanInterruptResponse(value: unknown, schemaInput: HumanInterruptResponseSchema): HumanInterruptResponse {
  const schema = normalizeHumanInterruptResponseSchema(schemaInput);
  if (schema.type !== "object") return validateScalarResponse(value, schema, "response");
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("response must be an object");
  const raw = value as Record<string, unknown>;
  const allowed = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(raw)) if (!allowed.has(key)) throw new TypeError(`response contains undeclared property: ${key}`);
  for (const key of schema.required ?? []) {
    if (!Object.prototype.hasOwnProperty.call(raw, key)) throw new TypeError(`response is missing required property: ${key}`);
  }
  const normalized: Record<string, HumanInterruptResponseScalar> = {};
  for (const key of Object.keys(raw).sort()) {
    const propertySchema = schema.properties[key];
    if (!propertySchema) throw new TypeError(`response contains undeclared property: ${key}`);
    normalized[key] = validateScalarResponse(raw[key], propertySchema, `response.${key}`);
  }
  return Object.freeze(normalized);
}

export function normalizeReason(reason: HumanInterruptReason): HumanInterruptReason {
  const allowed: readonly HumanInterruptReason[] = ["DECISION_REQUIRED", "AMBIGUOUS", "POLICY_REQUIRED", "EXTERNAL_CONFIRMATION", "MANUAL"];
  if (!allowed.includes(reason)) throw new TypeError(`invalid interrupt reason: ${String(reason)}`);
  return reason;
}
