import { createHash, randomUUID } from "node:crypto";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";

export type BrowserSessionPersistence = "EPHEMERAL" | "PERSISTENT";
export type BrowserSessionLeaseStatus = "ACTIVE" | "REVOKED";

export interface BrowserSessionLease {
  schemaVersion: "toadaid.browser-session-lease.v1";
  sessionId: string;
  ownerId: string;
  createdAt: string;
  expiresAt: string;
  allowedOrigins: readonly string[];
  persistence: BrowserSessionPersistence;
  stateRef: string | null;
  status: BrowserSessionLeaseStatus;
  revokedAt: string | null;
}

export interface BrowserSessionLeaseEnvelope {
  schemaVersion: "toadaid.browser-session-lease-envelope.v1";
  lease: BrowserSessionLease;
  leaseSha256: string;
}

export interface BrowserSessionRuntime {
  now?: () => Date;
}

export interface CreateBrowserSessionLeaseInput {
  sessionId?: string;
  ownerId: string;
  allowedOrigins: readonly string[];
  ttlMs?: number;
  persistence?: BrowserSessionPersistence;
}

export interface BrowserSessionAuthorityBundle {
  session: CapabilityAuthorityDecision;
  persistence?: CapabilityAuthorityDecision;
}

export interface BrowserSessionUseRequest {
  ownerId: string;
  url: string;
}

export interface BrowserSessionBinding {
  schemaVersion: "toadaid.browser-session-binding.v1";
  sessionId: string;
  ownerId: string;
  origin: string;
  persistence: BrowserSessionPersistence;
  stateRef: string | null;
  expiresAt: string;
}

const DEFAULT_TTL_MS = 30 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ORIGINS = 32;
const MAX_OWNER_CHARS = 256;
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean" || typeof value === "string") {
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
  throw new TypeError("value is not canonically serializable");
}

function sha256(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

function currentDate(runtime: BrowserSessionRuntime): Date {
  const value = (runtime.now ?? (() => new Date()))();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError("runtime.now must return a valid Date");
  return value;
}

function assertAuthority(authority: CapabilityAuthorityDecision | undefined, capabilityId: string): void {
  if (!authority || authority.capabilityId !== capabilityId || !authority.installed || authority.decision !== "ALLOW") {
    throw new Error(`browser session capability is not authorized: ${capabilityId}`);
  }
}

function cleanOwnerId(ownerId: string): string {
  if (typeof ownerId !== "string" || !ownerId.trim()) throw new TypeError("ownerId must not be empty");
  if (ownerId.length > MAX_OWNER_CHARS) throw new RangeError(`ownerId exceeds ${MAX_OWNER_CHARS} characters`);
  return ownerId;
}

function cleanSessionId(sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new TypeError("sessionId is invalid");
  return sessionId;
}

function exactOrigin(value: string, label: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new TypeError(`${label} must use http: or https:`);
  return url.origin;
}

export function normalizeBrowserSessionOrigins(origins: readonly string[]): readonly string[] {
  if (!Array.isArray(origins) || origins.length === 0) throw new TypeError("allowedOrigins must contain at least one origin");
  if (origins.length > MAX_ORIGINS) throw new RangeError(`allowedOrigins exceeds ${MAX_ORIGINS} entries`);
  const normalized = [...new Set(origins.map((origin) => exactOrigin(origin, "allowedOrigins entry")))].sort();
  if (normalized.length === 0) throw new TypeError("allowedOrigins must contain at least one origin");
  return Object.freeze(normalized);
}

function ttlMs(value: number | undefined): number {
  const resolved = value ?? DEFAULT_TTL_MS;
  if (!Number.isSafeInteger(resolved) || resolved < 1_000 || resolved > MAX_TTL_MS) {
    throw new RangeError(`ttlMs must be an integer between 1000 and ${MAX_TTL_MS}`);
  }
  return resolved;
}

function stateRefFor(ownerId: string, sessionId: string): string {
  return `browser-session-state:${sha256(`${ownerId}\0${sessionId}`)}`;
}

function freezeLease(lease: BrowserSessionLease): BrowserSessionLease {
  return Object.freeze({ ...lease, allowedOrigins: Object.freeze([...lease.allowedOrigins]) });
}

export function browserSessionLeaseSha256(lease: BrowserSessionLease): string {
  return sha256(lease);
}

export function sealBrowserSessionLease(lease: BrowserSessionLease): BrowserSessionLeaseEnvelope {
  const normalized = freezeLease(lease);
  return Object.freeze({
    schemaVersion: "toadaid.browser-session-lease-envelope.v1",
    lease: normalized,
    leaseSha256: browserSessionLeaseSha256(normalized),
  });
}

export function createBrowserSessionLease(
  input: CreateBrowserSessionLeaseInput,
  authority: BrowserSessionAuthorityBundle,
  runtime: BrowserSessionRuntime = {},
): BrowserSessionLeaseEnvelope {
  assertAuthority(authority.session, "browser:session");
  const ownerId = cleanOwnerId(input.ownerId);
  const sessionId = cleanSessionId(input.sessionId ?? randomUUID());
  const persistence = input.persistence ?? "EPHEMERAL";
  if (persistence !== "EPHEMERAL" && persistence !== "PERSISTENT") throw new TypeError("persistence is invalid");
  if (persistence === "PERSISTENT") assertAuthority(authority.persistence, "browser:session-persist");
  const now = currentDate(runtime);
  const lease: BrowserSessionLease = {
    schemaVersion: "toadaid.browser-session-lease.v1",
    sessionId,
    ownerId,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs(input.ttlMs)).toISOString(),
    allowedOrigins: normalizeBrowserSessionOrigins(input.allowedOrigins),
    persistence,
    stateRef: persistence === "PERSISTENT" ? stateRefFor(ownerId, sessionId) : null,
    status: "ACTIVE",
    revokedAt: null,
  };
  return sealBrowserSessionLease(lease);
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function parseIso(value: unknown, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) throw new TypeError(`${label} must be an ISO date string`);
  return new Date(value).toISOString();
}

export function validateBrowserSessionLeaseEnvelope(value: unknown): BrowserSessionLeaseEnvelope {
  const envelope = objectValue(value, "browser session envelope");
  if (envelope.schemaVersion !== "toadaid.browser-session-lease-envelope.v1") throw new TypeError("unsupported browser session envelope schemaVersion");
  const raw = objectValue(envelope.lease, "browser session lease");
  if (raw.schemaVersion !== "toadaid.browser-session-lease.v1") throw new TypeError("unsupported browser session lease schemaVersion");
  if (!Array.isArray(raw.allowedOrigins)) throw new TypeError("browser session allowedOrigins must be an array");
  const ownerId = cleanOwnerId(raw.ownerId as string);
  const sessionId = cleanSessionId(raw.sessionId as string);
  const persistence = raw.persistence;
  if (persistence !== "EPHEMERAL" && persistence !== "PERSISTENT") throw new TypeError("browser session persistence is invalid");
  const status = raw.status;
  if (status !== "ACTIVE" && status !== "REVOKED") throw new TypeError("browser session status is invalid");
  const stateRef = raw.stateRef;
  const expectedStateRef = persistence === "PERSISTENT" ? stateRefFor(ownerId, sessionId) : null;
  if (stateRef !== expectedStateRef) throw new TypeError("browser session stateRef does not match owner/session binding");
  const revokedAt = raw.revokedAt === null ? null : parseIso(raw.revokedAt, "revokedAt");
  if ((status === "ACTIVE" && revokedAt !== null) || (status === "REVOKED" && revokedAt === null)) {
    throw new TypeError("browser session revoke state is inconsistent");
  }
  const createdAt = parseIso(raw.createdAt, "createdAt");
  const expiresAt = parseIso(raw.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) throw new TypeError("browser session expiresAt must be after createdAt");
  if (Date.parse(expiresAt) - Date.parse(createdAt) > MAX_TTL_MS) throw new TypeError("browser session lease exceeds maximum TTL");
  const lease = freezeLease({
    schemaVersion: "toadaid.browser-session-lease.v1",
    sessionId,
    ownerId,
    createdAt,
    expiresAt,
    allowedOrigins: normalizeBrowserSessionOrigins(raw.allowedOrigins as string[]),
    persistence,
    stateRef: expectedStateRef,
    status,
    revokedAt,
  });
  const leaseSha256 = envelope.leaseSha256;
  if (typeof leaseSha256 !== "string" || !SHA256_PATTERN.test(leaseSha256)) throw new TypeError("browser session leaseSha256 is invalid");
  if (browserSessionLeaseSha256(lease) !== leaseSha256) throw new Error("browser session lease integrity check failed");
  return Object.freeze({ schemaVersion: "toadaid.browser-session-lease-envelope.v1", lease, leaseSha256 });
}

export function serializeBrowserSessionLease(envelope: BrowserSessionLeaseEnvelope): string {
  return canonicalJson(validateBrowserSessionLeaseEnvelope(envelope));
}

export function parseBrowserSessionLease(serialized: string): BrowserSessionLeaseEnvelope {
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > 64 * 1024) {
    throw new RangeError("browser session lease payload exceeds bound");
  }
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new TypeError("browser session lease payload must be valid JSON");
  }
  return validateBrowserSessionLeaseEnvelope(value);
}

export function assertBrowserSessionLeaseUsable(
  envelopeInput: BrowserSessionLeaseEnvelope,
  request: BrowserSessionUseRequest,
  authority: BrowserSessionAuthorityBundle,
  runtime: BrowserSessionRuntime = {},
): BrowserSessionBinding {
  assertAuthority(authority.session, "browser:session");
  const envelope = validateBrowserSessionLeaseEnvelope(envelopeInput);
  const lease = envelope.lease;
  if (lease.persistence === "PERSISTENT") assertAuthority(authority.persistence, "browser:session-persist");
  if (cleanOwnerId(request.ownerId) !== lease.ownerId) throw new Error("browser session owner mismatch");
  if (lease.status !== "ACTIVE") throw new Error("browser session lease is revoked");
  const now = currentDate(runtime);
  if (now.getTime() >= Date.parse(lease.expiresAt)) throw new Error("browser session lease is expired");
  const origin = exactOrigin(request.url, "browser session use url");
  if (!lease.allowedOrigins.includes(origin)) throw new Error(`browser session origin is not authorized: ${origin}`);
  return Object.freeze({
    schemaVersion: "toadaid.browser-session-binding.v1",
    sessionId: lease.sessionId,
    ownerId: lease.ownerId,
    origin,
    persistence: lease.persistence,
    stateRef: lease.stateRef,
    expiresAt: lease.expiresAt,
  });
}

export function revokeBrowserSessionLease(
  envelopeInput: BrowserSessionLeaseEnvelope,
  ownerIdInput: string,
  authority: BrowserSessionAuthorityBundle,
  runtime: BrowserSessionRuntime = {},
): BrowserSessionLeaseEnvelope {
  assertAuthority(authority.session, "browser:session");
  const envelope = validateBrowserSessionLeaseEnvelope(envelopeInput);
  if (cleanOwnerId(ownerIdInput) !== envelope.lease.ownerId) throw new Error("browser session owner mismatch");
  if (envelope.lease.status === "REVOKED") return envelope;
  const now = currentDate(runtime).toISOString();
  return sealBrowserSessionLease({ ...envelope.lease, status: "REVOKED", revokedAt: now });
}
