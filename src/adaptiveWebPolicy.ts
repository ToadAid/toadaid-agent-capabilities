import { createHash } from "node:crypto";
import { isIP } from "node:net";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import type {
  AdaptiveElementFingerprint, AdaptiveWebAuthorityBundle, AdaptiveWebCapabilityId, AdaptiveWebFetchMode,
  AdaptiveWebIntent, AdaptiveWebPolicy, CrawlPolicy, ExtractionFieldSpec, NormalizedAdaptiveWebPolicy
} from "./adaptiveWebTypes.js";

export const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FIELD_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_ORIGINS = 64;
const MAX_FIELDS = 128;
const MAX_SELECTOR_CHARS = 4_000;
const MAX_XHR_PATTERN_CHARS = 2_000;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const HARD_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_EXTRACTED_ITEMS = 2_000;
const HARD_MAX_EXTRACTED_ITEMS = 20_000;
const DEFAULT_MAX_VALUE_CHARS = 20_000;
const HARD_MAX_VALUE_CHARS = 100_000;
const DEFAULT_MIN_CONFIDENCE = 0.65;
const DEFAULT_AMBIGUITY_MARGIN = 0.05;
const MAX_CANDIDATES = 2_000;
const DEFAULT_CRAWL_POLICY: CrawlPolicy = Object.freeze({
  maxUrls: 200,
  maxDepth: 3,
  maxConcurrency: 4,
  perOriginMaxRequests: 100,
  minDelayMs: 250,
  maxDelayMs: 15_000,
  targetLatencyMs: 1_000,
  backoffFactor: 2,
});

export function canonicalJson(value: unknown): string {
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

export function sha256(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

export function exactInt(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function boundedNumber(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (typeof resolved !== "number" || !Number.isFinite(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be between ${minimum} and ${maximum}`);
  }
  return resolved;
}

export function boundedString(value: string, label: string, maximum: number): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${label} must not be empty`);
  if (normalized.length > maximum) throw new RangeError(`${label} exceeds ${maximum} characters`);
  return normalized;
}

export function exactOrigin(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError(`${label} must use http: or https:`);
  if (parsed.username || parsed.password) throw new TypeError(`${label} must not contain URL credentials`);
  return parsed.origin;
}

function normalizeOrigins(values: readonly string[], label: string, allowEmpty: boolean): readonly string[] {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  if (values.length > MAX_ORIGINS) throw new RangeError(`${label} exceeds ${MAX_ORIGINS} entries`);
  const normalized = [...new Set(values.map((value) => exactOrigin(value, `${label} entry`)))].sort();
  if (!allowEmpty && normalized.length === 0) throw new TypeError(`${label} must contain at least one origin`);
  return Object.freeze(normalized);
}

function normalizeCrawlPolicy(input: Partial<CrawlPolicy> | undefined): CrawlPolicy {
  const policy = input ?? {};
  const minDelayMs = exactInt(policy.minDelayMs, DEFAULT_CRAWL_POLICY.minDelayMs, 0, 60_000, "crawl.minDelayMs");
  const maxDelayMs = exactInt(policy.maxDelayMs, DEFAULT_CRAWL_POLICY.maxDelayMs, minDelayMs, 300_000, "crawl.maxDelayMs");
  return Object.freeze({
    maxUrls: exactInt(policy.maxUrls, DEFAULT_CRAWL_POLICY.maxUrls, 1, 5_000, "crawl.maxUrls"),
    maxDepth: exactInt(policy.maxDepth, DEFAULT_CRAWL_POLICY.maxDepth, 0, 16, "crawl.maxDepth"),
    maxConcurrency: exactInt(policy.maxConcurrency, DEFAULT_CRAWL_POLICY.maxConcurrency, 1, 32, "crawl.maxConcurrency"),
    perOriginMaxRequests: exactInt(
      policy.perOriginMaxRequests,
      DEFAULT_CRAWL_POLICY.perOriginMaxRequests,
      1,
      2_000,
      "crawl.perOriginMaxRequests",
    ),
    minDelayMs,
    maxDelayMs,
    targetLatencyMs: exactInt(policy.targetLatencyMs, DEFAULT_CRAWL_POLICY.targetLatencyMs, 1, 120_000, "crawl.targetLatencyMs"),
    backoffFactor: boundedNumber(policy.backoffFactor, DEFAULT_CRAWL_POLICY.backoffFactor, 1.1, 10, "crawl.backoffFactor"),
  });
}

export function normalizeAdaptiveWebPolicy(policy: AdaptiveWebPolicy): NormalizedAdaptiveWebPolicy {
  const adaptiveMinimumConfidence = boundedNumber(
    policy.adaptiveMinimumConfidence,
    DEFAULT_MIN_CONFIDENCE,
    0.4,
    1,
    "adaptiveMinimumConfidence",
  );
  const adaptiveAmbiguityMargin = boundedNumber(
    policy.adaptiveAmbiguityMargin,
    DEFAULT_AMBIGUITY_MARGIN,
    0,
    0.25,
    "adaptiveAmbiguityMargin",
  );
  return Object.freeze({
    allowedTopLevelOrigins: normalizeOrigins(policy.allowedTopLevelOrigins, "allowedTopLevelOrigins", false),
    allowedResourceOrigins: normalizeOrigins(policy.allowedResourceOrigins ?? [], "allowedResourceOrigins", true),
    allowPrivateNetwork: policy.allowPrivateNetwork ?? false,
    maxResponseBytes: exactInt(
      policy.maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      1_024,
      HARD_MAX_RESPONSE_BYTES,
      "maxResponseBytes",
    ),
    maxExtractedItems: exactInt(
      policy.maxExtractedItems,
      DEFAULT_MAX_EXTRACTED_ITEMS,
      1,
      HARD_MAX_EXTRACTED_ITEMS,
      "maxExtractedItems",
    ),
    maxValueChars: exactInt(policy.maxValueChars, DEFAULT_MAX_VALUE_CHARS, 100, HARD_MAX_VALUE_CHARS, "maxValueChars"),
    adaptiveMinimumConfidence,
    adaptiveAmbiguityMargin,
    crawl: normalizeCrawlPolicy(policy.crawl),
  });
}

export function assertAuthority(authority: CapabilityAuthorityDecision | undefined, capabilityId: AdaptiveWebCapabilityId): void {
  if (!authority || authority.capabilityId !== capabilityId || !authority.installed || authority.decision !== "ALLOW") {
    throw new Error(`adaptive web capability is not authorized: ${capabilityId}`);
  }
}

export function authorityForIntent(
  intent: AdaptiveWebIntent,
  authority: AdaptiveWebAuthorityBundle,
): Exclude<AdaptiveWebCapabilityId, "web:crawl" | "web:stealth-fetch"> {
  if (intent.kind === "extract") {
    assertAuthority(authority.extract, "web:extract");
    return "web:extract";
  }
  if (intent.kind === "adaptive-locate") {
    assertAuthority(authority.adaptiveLocate, "web:adaptive-locate");
    return "web:adaptive-locate";
  }
  assertAuthority(authority.xhrCapture, "web:xhr-capture");
  return "web:xhr-capture";
}

export function normalizedFetchMode(intent: AdaptiveWebIntent, authority: AdaptiveWebAuthorityBundle): AdaptiveWebFetchMode {
  const requested = intent.fetchMode ?? (intent.kind === "xhr-capture" ? "BROWSER" : "HTTP");
  if (intent.kind === "xhr-capture" && requested === "HTTP") throw new TypeError("xhr-capture requires BROWSER or STEALTH fetch mode");
  if (requested === "STEALTH") assertAuthority(authority.stealthFetch, "web:stealth-fetch");
  return requested;
}

function normalizeIpv4(address: string): readonly number[] | null {
  if (isIP(address) !== 4) return null;
  const parts = address.split(".").map((part) => Number(part));
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : null;
}

function isPublicIpv4(address: string): boolean {
  const parts = normalizeIpv4(address);
  if (!parts) return false;
  const [a, b, c] = parts as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function expandedIpv6(address: string): readonly number[] | null {
  if (isIP(address) !== 6) return null;
  let raw = address.toLowerCase();
  const zoneIndex = raw.indexOf("%");
  if (zoneIndex >= 0) raw = raw.slice(0, zoneIndex);
  const ipv4Tail = raw.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Tail?.[1]) {
    const ipv4 = normalizeIpv4(ipv4Tail[1]);
    if (!ipv4) return null;
    return [0, 0, 0, 0, 0, 0xffff, (ipv4[0]! << 8) | ipv4[1]!, (ipv4[2]! << 8) | ipv4[3]!];
  }
  const split = raw.split("::");
  if (split.length > 2) return null;
  const left = split[0] ? split[0].split(":").filter(Boolean) : [];
  const right = split.length === 2 && split[1] ? split[1].split(":").filter(Boolean) : [];
  if (left.length + right.length > 8) return null;
  const zeros = 8 - left.length - right.length;
  if (split.length === 1 && zeros !== 0) return null;
  const pieces = [...left, ...Array.from({ length: zeros }, () => "0"), ...right];
  if (pieces.length !== 8 || pieces.some((piece) => !/^[0-9a-f]{1,4}$/.test(piece))) return null;
  return pieces.map((piece) => Number.parseInt(piece, 16));
}

export function isPublicIpAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family !== 6) return false;
  const h = expandedIpv6(address);
  if (!h) return false;
  if (h.every((part) => part === 0)) return false;
  if (h.slice(0, 7).every((part) => part === 0) && h[7] === 1) return false;
  if ((h[0]! & 0xfe00) === 0xfc00) return false; // fc00::/7
  if ((h[0]! & 0xffc0) === 0xfe80) return false; // fe80::/10
  if ((h[0]! & 0xff00) === 0xff00) return false; // multicast
  if (h[0] === 0x2001 && h[1] === 0x0db8) return false; // documentation
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    const ipv4 = `${h[6]! >> 8}.${h[6]! & 255}.${h[7]! >> 8}.${h[7]! & 255}`;
    return isPublicIpv4(ipv4);
  }
  return true;
}

function hostnameLooksPrivateLiteral(hostname: string): boolean {
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return isIP(unbracketed) !== 0 && !isPublicIpAddress(unbracketed);
}

export function authorizedUrl(value: string, policy: NormalizedAdaptiveWebPolicy, label: string, allowQuery = true): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError(`${label} must use http: or https:`);
  if (parsed.username || parsed.password) throw new TypeError(`${label} must not contain URL credentials`);
  if (!policy.allowedTopLevelOrigins.includes(parsed.origin)) throw new Error(`${label} origin is not authorized: ${parsed.origin}`);
  if (!policy.allowPrivateNetwork && hostnameLooksPrivateLiteral(parsed.hostname)) throw new Error(`${label} targets a private/local address literal`);
  if (!allowQuery && (parsed.search || parsed.hash)) throw new Error(`${label} for resumable crawl must not contain query or fragment`);
  return parsed;
}

export function authorizedResourceUrl(value: string, policy: NormalizedAdaptiveWebPolicy, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError(`${label} must use http: or https:`);
  if (parsed.username || parsed.password) throw new TypeError(`${label} must not contain URL credentials`);
  const allowed = new Set([...policy.allowedTopLevelOrigins, ...policy.allowedResourceOrigins]);
  if (!allowed.has(parsed.origin)) throw new Error(`${label} origin is not authorized: ${parsed.origin}`);
  if (!policy.allowPrivateNetwork && hostnameLooksPrivateLiteral(parsed.hostname)) throw new Error(`${label} targets a private/local address literal`);
  return parsed;
}

export function persistedUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

export function normalizeField(field: ExtractionFieldSpec, index: number, policy: NormalizedAdaptiveWebPolicy): ExtractionFieldSpec {
  if (!FIELD_NAME_PATTERN.test(field.name)) throw new TypeError(`fields[${index}].name is invalid`);
  if (field.selectorKind !== "CSS" && field.selectorKind !== "XPATH") throw new TypeError(`fields[${index}].selectorKind is invalid`);
  const selector = boundedString(field.selector, `fields[${index}].selector`, MAX_SELECTOR_CHARS);
  if (!(["TEXT", "HTML", "ATTRIBUTE"] as const).includes(field.valueKind)) throw new TypeError(`fields[${index}].valueKind is invalid`);
  const attribute = field.valueKind === "ATTRIBUTE" ? boundedString(field.attribute ?? "", `fields[${index}].attribute`, 128) : undefined;
  const maxItems = exactInt(field.maxItems, field.multiple ? 100 : 1, 1, Math.min(policy.maxExtractedItems, 1_000), `fields[${index}].maxItems`);
  return Object.freeze({
    name: field.name,
    selectorKind: field.selectorKind,
    selector,
    valueKind: field.valueKind,
    ...(attribute === undefined ? {} : { attribute }),
    multiple: field.multiple ?? false,
    maxItems,
  });
}

export function normalizeFingerprint(value: AdaptiveElementFingerprint, label: string): AdaptiveElementFingerprint {
  const attrs = Object.fromEntries(
    Object.entries(value.attributes ?? {}).map(([key, val]) => [boundedString(key, `${label}.attribute key`, 128), String(val).slice(0, 1_000)]),
  );
  const parentAttrs = Object.fromEntries(
    Object.entries(value.parent?.attributes ?? {}).map(([key, val]) => [boundedString(key, `${label}.parent attribute key`, 128), String(val).slice(0, 1_000)]),
  );
  return Object.freeze({
    id: boundedString(value.id, `${label}.id`, 256),
    tag: boundedString(value.tag, `${label}.tag`, 128).toLowerCase(),
    text: String(value.text ?? "").slice(0, 4_000),
    attributes: Object.freeze(attrs),
    parent: Object.freeze({
      tag: value.parent?.tag ? boundedString(value.parent.tag, `${label}.parent.tag`, 128).toLowerCase() : null,
      text: String(value.parent?.text ?? "").slice(0, 2_000),
      attributes: Object.freeze(parentAttrs),
    }),
    siblingTags: Object.freeze((value.siblingTags ?? []).slice(0, 32).map((tag) => String(tag).toLowerCase().slice(0, 128))),
    pathTags: Object.freeze((value.pathTags ?? []).slice(-32).map((tag) => String(tag).toLowerCase().slice(0, 128))),
  });
}


export function normalizeCrawlUrl(value: string, policy: NormalizedAdaptiveWebPolicy, label: string): string {
  return authorizedUrl(value, policy, label, false).toString();
}
