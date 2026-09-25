import { createHash } from "node:crypto";
import path from "node:path";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import type { SecretProjectionTarget } from "./secretLeaseTypes.js";

export const SECRET_HANDLE_PATTERN = /^secret-ref:[a-f0-9]{64}$/;
export const SHA256_PATTERN = /^[a-f0-9]{64}$/;
export const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PROVIDER_PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const FILE_SEGMENT_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

export const DEFAULT_LEASE_TTL_MS = 15 * 60 * 1000;
export const MAX_LEASE_TTL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_MATERIALIZATION_TTL_MS = 60 * 1000;
export const MAX_MATERIALIZATION_TTL_MS = 5 * 60 * 1000;
export const MAX_ALLOWED_CAPABILITIES = 64;
export const MAX_ALLOWED_TARGETS = 32;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("secret lease value is not canonically serializable");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

export function assertId(value: string, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function assertProviderProfileId(value: string, label: string): string {
  if (typeof value !== "string" || !PROVIDER_PROFILE_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function assertSecretHandle(value: string): string {
  if (typeof value !== "string" || !SECRET_HANDLE_PATTERN.test(value)) {
    throw new TypeError("secretHandle must be an opaque secret-ref 64-hex handle");
  }
  return value;
}

export function canonicalIso(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  return value;
}

export function boundedTtl(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const ttl = value ?? fallback;
  if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > maximum) throw new RangeError(`${label} must be an integer between 1000 and ${maximum}`);
  return ttl;
}

export function assertCapabilityId(value: string, label: string): string {
  if (typeof value !== "string" || !CAPABILITY_ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function assertAuthority(authority: CapabilityAuthorityDecision, capabilityId: string, label = "secret capability"): void {
  if (
    authority.schemaVersion !== "toadaid.capability-authority-decision.v1" ||
    authority.capabilityId !== capabilityId ||
    !authority.installed ||
    authority.decision !== "ALLOW"
  ) throw new Error(`${label} is not authorized: ${capabilityId}`);
}

export function normalizeAllowedCapabilities(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values) || values.length === 0) throw new TypeError("allowedCapabilities must contain at least one capability");
  if (values.length > MAX_ALLOWED_CAPABILITIES) throw new RangeError(`allowedCapabilities exceeds ${MAX_ALLOWED_CAPABILITIES}`);
  const normalized = [...new Set(values.map((value, index) => assertCapabilityId(value, `allowedCapabilities[${index}]`)))].sort();
  return Object.freeze(normalized);
}

function normalizeFileRelativePath(value: string): string {
  if (typeof value !== "string" || !value || value.length > 512) throw new TypeError("FILE relativePath is invalid");
  if (value.startsWith("/") || value.startsWith("~") || value.includes("\\") || value.includes(":") || value.includes("\0")) {
    throw new TypeError("FILE relativePath must be a portable relative path");
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === ".." || !FILE_SEGMENT_PATTERN.test(segment))) {
    throw new TypeError("FILE relativePath contains an unsafe path segment");
  }
  return segments.join("/");
}

export function normalizeSecretProjectionTarget(target: SecretProjectionTarget): SecretProjectionTarget {
  if (!target || typeof target !== "object") throw new TypeError("secret projection target must be an object");
  if (target.kind === "ENV") {
    if (!ENV_NAME_PATTERN.test(target.name)) throw new TypeError("ENV projection name is invalid");
    return Object.freeze({ kind: "ENV" as const, name: target.name });
  }
  if (target.kind === "FILE") {
    if (target.mode !== 384) throw new TypeError("FILE projection mode must be 0600");
    return Object.freeze({ kind: "FILE" as const, relativePath: normalizeFileRelativePath(target.relativePath), mode: 384 as const });
  }
  throw new TypeError("secret projection target kind is invalid");
}

export function normalizeAllowedTargets(values: readonly SecretProjectionTarget[]): readonly SecretProjectionTarget[] {
  if (!Array.isArray(values) || values.length === 0) throw new TypeError("allowedTargets must contain at least one target");
  if (values.length > MAX_ALLOWED_TARGETS) throw new RangeError(`allowedTargets exceeds ${MAX_ALLOWED_TARGETS}`);
  const map = new Map<string, SecretProjectionTarget>();
  for (const value of values) {
    const target = normalizeSecretProjectionTarget(value);
    const key = canonicalJson(target);
    map.set(key, target);
  }
  return Object.freeze([...map.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, target]) => target));
}

export function secretProjectionTargetEquals(a: SecretProjectionTarget, b: SecretProjectionTarget): boolean {
  return canonicalJson(normalizeSecretProjectionTarget(a)) === canonicalJson(normalizeSecretProjectionTarget(b));
}

export function resolveSecretFileProjectionPath(root: string, target: SecretProjectionTarget): string {
  const normalized = normalizeSecretProjectionTarget(target);
  if (normalized.kind !== "FILE") throw new TypeError("target is not a FILE projection");
  if (typeof root !== "string" || !root.trim()) throw new TypeError("projection root must not be empty");
  const absoluteRoot = path.resolve(root);
  const resolved = path.resolve(absoluteRoot, normalized.relativePath);
  const relative = path.relative(absoluteRoot, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new TypeError("resolved secret projection escapes its root");
  return resolved;
}

export function currentDate(runtime: { now?: () => Date }): Date {
  const date = (runtime.now ?? (() => new Date()))();
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) throw new TypeError("runtime.now must return a valid Date");
  return date;
}
