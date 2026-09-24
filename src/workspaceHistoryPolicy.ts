import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import type {
  NormalizedWorkspaceSnapshotPolicy,
  WorkspaceCapabilityId,
  WorkspaceHistoryRuntime,
  WorkspaceSnapshotPolicy,
} from "./workspaceHistoryTypes.js";

export const DEFAULT_STALE_LOCK_MS = 10 * 60 * 1000;
export const MAX_STALE_LOCK_MS = 24 * 60 * 60 * 1000;
export const SNAPSHOT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const WORKSPACE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const SHA256_PATTERN = /^[a-f0-9]{64}$/;

const DEFAULT_MAX_FILES = 5_000;
const MAX_MAX_FILES = 50_000;
const DEFAULT_MAX_FILE_BYTES = 20 * 1024 * 1024;
const MAX_MAX_FILE_BYTES = 250 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 250 * 1024 * 1024;
const MAX_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;

export function exactInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

export function canonicalIso(value: string, label: string): string {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

export function currentIso(runtime: WorkspaceHistoryRuntime): string {
  return (runtime.now ?? (() => new Date()))().toISOString();
}

export function assertId(value: string, pattern: RegExp, label: string): string {
  if (!pattern.test(value)) throw new TypeError(`${label} has invalid format`);
  return value;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("workspace history contains a non-serializable value");
}

export function sha256(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function toPosixPath(path: string): string {
  return path.split(sep).join("/");
}

export function normalizeRelativePath(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must not be empty`);
  if (isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value) || /^\\\\/.test(value)) {
    throw new TypeError(`${label} must be relative`);
  }
  const normalized = value.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/g, "");
  if (!normalized || normalized === "." || normalized.split("/").some((part) => part === ".." || part === "")) {
    throw new TypeError(`${label} must be a normalized relative path`);
  }
  return normalized;
}

export function isWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

export function normalizedRoots(runtime: WorkspaceHistoryRuntime): { workspaceRoot: string; historyRoot: string } {
  if (!runtime.ownerId.trim()) throw new TypeError("runtime.ownerId must not be empty");
  const workspaceRoot = resolve(runtime.workspaceRoot);
  const historyRoot = resolve(runtime.historyRoot);
  if (workspaceRoot === historyRoot || isWithin(workspaceRoot, historyRoot) || isWithin(historyRoot, workspaceRoot)) {
    throw new Error("workspaceRoot and historyRoot must be disjoint; history never lives inside project Git/workspace state");
  }
  return { workspaceRoot, historyRoot };
}

export function normalizeWorkspaceSnapshotPolicy(
  policy: WorkspaceSnapshotPolicy = {},
): NormalizedWorkspaceSnapshotPolicy {
  const excluded = new Set<string>([".git"]);
  for (const [index, value] of (policy.excludedPaths ?? []).entries()) {
    excluded.add(normalizeRelativePath(value, `excludedPaths[${index}]`));
  }
  return Object.freeze({
    maxFiles: exactInteger(policy.maxFiles, DEFAULT_MAX_FILES, 1, MAX_MAX_FILES, "maxFiles"),
    maxFileBytes: exactInteger(policy.maxFileBytes, DEFAULT_MAX_FILE_BYTES, 1, MAX_MAX_FILE_BYTES, "maxFileBytes"),
    maxTotalBytes: exactInteger(policy.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, 1, MAX_MAX_TOTAL_BYTES, "maxTotalBytes"),
    excludedPaths: Object.freeze([...excluded].sort()),
  });
}

export function assertWorkspaceAuthority(
  authority: CapabilityAuthorityDecision,
  capabilityId: WorkspaceCapabilityId,
): void {
  if (
    authority.schemaVersion !== "toadaid.capability-authority-decision.v1" ||
    authority.capabilityId !== capabilityId ||
    authority.installed !== true ||
    authority.decision !== "ALLOW"
  ) {
    throw new Error(`workspace capability is not authorized: ${capabilityId}`);
  }
}

export function excluded(path: string, excludedPaths: readonly string[]): boolean {
  return excludedPaths.some((entry) => path === entry || path.startsWith(`${entry}/`));
}
