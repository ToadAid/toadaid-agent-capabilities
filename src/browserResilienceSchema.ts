import { createHash } from "node:crypto";
import type {
  BrowserFreshDomToken,
  BrowserResilienceInteractiveElement,
  BrowserResiliencePolicy,
  BrowserResilienceDomInput,
  BrowserResilienceDomEvidence,
  NormalizedBrowserResiliencePolicy,
} from "./browserResilienceTypes.js";

const SHA256 = /^[0-9a-f]{64}$/;
const DEFAULT_TEXT = 20_000;
const DEFAULT_HEADINGS = 50;
const DEFAULT_INTERACTIVE = 100;
const DEFAULT_READY_TIMEOUT = 10_000;

export function resilienceCanonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(resilienceCanonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${resilienceCanonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("browser resilience value is not canonically serializable");
}

export function resilienceSha256(value: unknown): string {
  return createHash("sha256").update(resilienceCanonicalJson(value)).digest("hex");
}

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) throw new RangeError(`${label} must be in [${min}, ${max}]`);
  return resolved;
}

export function normalizeBrowserResiliencePolicy(policy: BrowserResiliencePolicy = {}): NormalizedBrowserResiliencePolicy {
  return Object.freeze({
    maxTextChars: boundedInteger(policy.maxTextChars, DEFAULT_TEXT, 100, 100_000, "maxTextChars"),
    maxHeadings: boundedInteger(policy.maxHeadings, DEFAULT_HEADINGS, 0, 200, "maxHeadings"),
    maxInteractiveElements: boundedInteger(policy.maxInteractiveElements, DEFAULT_INTERACTIVE, 0, 500, "maxInteractiveElements"),
    navigationReadyTimeoutMs: boundedInteger(policy.navigationReadyTimeoutMs, DEFAULT_READY_TIMEOUT, 250, 60_000, "navigationReadyTimeoutMs"),
  });
}

export function persistedBrowserUrl(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new TypeError("browser URL must be absolute"); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError("browser URL must use http: or https:");
  return `${parsed.origin}${parsed.pathname}`;
}

function normalizedElement(element: BrowserResilienceDomInput["interactiveElements"][number]) {
  return {
    tag: String(element.tag ?? "").toLowerCase().slice(0, 64),
    role: element.role === null ? null : String(element.role).slice(0, 128),
    ariaLabel: element.ariaLabel === null ? null : String(element.ariaLabel).slice(0, 300),
    text: String(element.text ?? "").replace(/\s+/g, " ").trim().slice(0, 300),
    href: element.href === null ? null : persistedBrowserUrl(element.href),
    type: element.type === null ? null : String(element.type).slice(0, 64),
    name: element.name === null ? null : String(element.name).slice(0, 128),
  };
}

export function stableInteractiveElementIds(input: readonly BrowserResilienceDomInput["interactiveElements"][number][]): readonly BrowserResilienceInteractiveElement[] {
  const occurrence = new Map<string, number>();
  return Object.freeze(input.map((element, sourceIndex) => {
    const normalized = normalizedElement(element);
    const semanticSha = resilienceSha256(normalized);
    const ordinal = occurrence.get(semanticSha) ?? 0;
    occurrence.set(semanticSha, ordinal + 1);
    return Object.freeze({
      stableId: resilienceSha256({ semanticSha, ordinal }),
      sourceIndex,
      ...normalized,
    });
  }));
}

export function boundBrowserDomEvidence(input: BrowserResilienceDomInput, policyInput: BrowserResiliencePolicy = {}): BrowserResilienceDomEvidence {
  const policy = normalizeBrowserResiliencePolicy(policyInput);
  const rawText = String(input.textExcerpt ?? "");
  const textExcerpt = rawText.slice(0, policy.maxTextChars);
  const headings = Object.freeze(input.headings.slice(0, policy.maxHeadings).map((heading) => Object.freeze({
    level: Math.min(6, Math.max(1, Number.isSafeInteger(heading.level) ? heading.level : 1)),
    text: String(heading.text ?? "").replace(/\s+/g, " ").trim().slice(0, 500),
  })));
  const boundedInteractive = input.interactiveElements.slice(0, policy.maxInteractiveElements);
  const interactiveElements = stableInteractiveElementIds(boundedInteractive);
  const core = {
    title: String(input.title ?? "").slice(0, 1_000),
    textExcerpt,
    textTruncated: Boolean(input.textTruncated) || rawText.length > policy.maxTextChars,
    headingsTruncated: input.headings.length > policy.maxHeadings,
    interactiveElementsTruncated: input.interactiveElements.length > policy.maxInteractiveElements,
    headings,
    interactiveElements,
  };
  return Object.freeze({ ...core, domSha256: resilienceSha256(core) });
}

function tokenCore(token: Omit<BrowserFreshDomToken, "tokenSha256"> | BrowserFreshDomToken): Omit<BrowserFreshDomToken, "tokenSha256"> {
  const { tokenSha256: _ignored, ...core } = token as BrowserFreshDomToken;
  return core;
}

export function browserFreshDomTokenSha256(token: Omit<BrowserFreshDomToken, "tokenSha256"> | BrowserFreshDomToken): string {
  return resilienceSha256(tokenCore(token));
}

export function validateBrowserFreshDomToken(token: BrowserFreshDomToken): BrowserFreshDomToken {
  if (token.schemaVersion !== "toadaid.browser-fresh-dom-token.v1") throw new TypeError("unsupported fresh DOM token schemaVersion");
  if (!Number.isSafeInteger(token.navigationEpoch) || token.navigationEpoch < 0) throw new RangeError("fresh DOM navigationEpoch is invalid");
  if (!SHA256.test(token.pageIdentitySha256) || !SHA256.test(token.domSha256) || !SHA256.test(token.tokenSha256)) throw new TypeError("fresh DOM token contains invalid SHA-256");
  if (browserFreshDomTokenSha256(token) !== token.tokenSha256) throw new Error("fresh DOM token integrity mismatch");
  return Object.freeze({ ...token });
}
