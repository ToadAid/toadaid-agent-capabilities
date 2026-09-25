import { randomUUID } from "node:crypto";
import type {
  AdaptiveWebAuthorityBundle, AdaptiveWebIntent, AdaptiveWebPolicy, CrawlWorkerRequestInput, ScraplingWorkerRequest
} from "./adaptiveWebTypes.js";
import { assertAuthority, boundedString, exactInt, normalizeAdaptiveWebPolicy, normalizeCrawlUrl, normalizeField, normalizedFetchMode, authorityForIntent, authorizedUrl } from "./adaptiveWebPolicy.js";

const MAX_FIELDS = 128;
const MAX_SELECTOR_CHARS = 4_000;
const MAX_XHR_PATTERN_CHARS = 2_000;
const MAX_CANDIDATES = 2_000;

export function buildScraplingWorkerRequest(
  intent: AdaptiveWebIntent,
  policyInput: AdaptiveWebPolicy,
  authority: AdaptiveWebAuthorityBundle,
  requestId = randomUUID(),
): ScraplingWorkerRequest {
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const url = authorizedUrl(intent.url, policy, "intent.url");
  const capability = authorityForIntent(intent, authority);
  const fetchMode = normalizedFetchMode(intent, authority);
  const base = {
    schemaVersion: "toadaid.scrapling-worker.request.v1" as const,
    requestId: boundedString(requestId, "requestId", 128),
    capability,
    url: url.toString(),
    fetchMode,
    policy: Object.freeze({
      allowedTopLevelOrigins: policy.allowedTopLevelOrigins,
      allowedResourceOrigins: policy.allowedResourceOrigins,
      allowPrivateNetwork: policy.allowPrivateNetwork,
      maxResponseBytes: policy.maxResponseBytes,
      maxExtractedItems: policy.maxExtractedItems,
      maxValueChars: policy.maxValueChars,
    }),
  };

  if (intent.kind === "extract") {
    if (!Array.isArray(intent.fields) || intent.fields.length === 0 || intent.fields.length > MAX_FIELDS) {
      throw new RangeError(`extract fields must contain between 1 and ${MAX_FIELDS} entries`);
    }
    const seen = new Set<string>();
    const fields = intent.fields.map((field, index) => {
      const normalized = normalizeField(field, index, policy);
      if (seen.has(normalized.name)) throw new TypeError(`duplicate extraction field name: ${normalized.name}`);
      seen.add(normalized.name);
      return normalized;
    });
    return Object.freeze({ ...base, operation: "EXTRACT" as const, fields: Object.freeze(fields) });
  }

  if (intent.kind === "adaptive-locate") {
    const maxCandidates = exactInt(intent.maxCandidates, 100, 1, MAX_CANDIDATES, "maxCandidates");
    return Object.freeze({
      ...base,
      operation: "CANDIDATES" as const,
      candidateSelector: Object.freeze({
        selectorKind: intent.selectorKind,
        selector: boundedString(intent.candidateSelector, "candidateSelector", MAX_SELECTOR_CHARS),
        maxCandidates,
      }),
    });
  }

  const pattern = boundedString(intent.pattern, "xhr pattern", MAX_XHR_PATTERN_CHARS);
  return Object.freeze({
    ...base,
    operation: "XHR_CAPTURE" as const,
    xhr: Object.freeze({ pattern, bodyMode: intent.bodyMode ?? "HASH_ONLY" }),
  });
}

export function buildCrawlWorkerRequest(
  input: CrawlWorkerRequestInput,
  policyInput: AdaptiveWebPolicy,
  authority: AdaptiveWebAuthorityBundle,
  requestId = randomUUID(),
): ScraplingWorkerRequest {
  assertAuthority(authority.crawl, "web:crawl");
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const url = normalizeCrawlUrl(input.entry.url, policy, "crawl entry.url");
  if (!Number.isSafeInteger(input.entry.depth) || input.entry.depth < 0 || input.entry.depth > policy.crawl.maxDepth) {
    throw new RangeError(`crawl entry.depth must be between 0 and ${policy.crawl.maxDepth}`);
  }
  if (!Array.isArray(input.fields) || input.fields.length === 0 || input.fields.length > MAX_FIELDS) {
    throw new RangeError(`crawl extraction fields must contain between 1 and ${MAX_FIELDS} entries`);
  }
  const seen = new Set<string>();
  const fields = input.fields.map((field, index) => {
    const normalized = normalizeField(field, index, policy);
    if (seen.has(normalized.name)) throw new TypeError(`duplicate extraction field name: ${normalized.name}`);
    seen.add(normalized.name);
    return normalized;
  });
  const fetchMode = input.fetchMode ?? "HTTP";
  if (fetchMode === "STEALTH") assertAuthority(authority.stealthFetch, "web:stealth-fetch");
  return Object.freeze({
    schemaVersion: "toadaid.scrapling-worker.request.v1",
    requestId: boundedString(requestId, "requestId", 128),
    operation: "EXTRACT",
    capability: "web:crawl",
    url,
    fetchMode,
    policy: Object.freeze({
      allowedTopLevelOrigins: policy.allowedTopLevelOrigins,
      allowedResourceOrigins: policy.allowedResourceOrigins,
      allowPrivateNetwork: policy.allowPrivateNetwork,
      maxResponseBytes: policy.maxResponseBytes,
      maxExtractedItems: policy.maxExtractedItems,
      maxValueChars: policy.maxValueChars,
    }),
    fields: Object.freeze(fields),
  });
}

export function resolveCrawlDiscoveredUrls(
  baseUrl: string,
  hrefs: readonly string[],
  policyInput: AdaptiveWebPolicy,
): readonly string[] {
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const base = authorizedUrl(baseUrl, policy, "baseUrl", false);
  const output = new Set<string>();
  for (const [index, href] of hrefs.entries()) {
    if (typeof href !== "string" || !href.trim()) continue;
    let resolved: URL;
    try {
      resolved = new URL(href, base);
    } catch {
      continue;
    }
    try {
      output.add(normalizeCrawlUrl(resolved.toString(), policy, `hrefs[${index}]`));
    } catch {
      continue;
    }
  }
  return Object.freeze([...output].sort());
}
