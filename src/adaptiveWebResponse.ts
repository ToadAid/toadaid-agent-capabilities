import { isIP } from "node:net";
import type { AdaptiveElementFingerprint, AdaptiveWebPolicy, NormalizedAdaptiveWebPolicy, ScraplingWorkerRequest, ScraplingWorkerResponse, WorkerResolvedAddress, XhrEvidence } from "./adaptiveWebTypes.js";
import { SHA256_PATTERN, authorizedResourceUrl, authorizedUrl, boundedString, isPublicIpAddress, normalizeAdaptiveWebPolicy, normalizeFingerprint, persistedUrl } from "./adaptiveWebPolicy.js";

export function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function safeWorkerUrl(value: unknown, label: string, policy: NormalizedAdaptiveWebPolicy): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  return persistedUrl(authorizedUrl(value, policy, label));
}

export function nonNegativeInt(value: unknown, label: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new TypeError(`${label} must be a non-negative safe integer <= ${max}`);
  }
  return value;
}

function parseResolvedAddresses(value: unknown, policy: NormalizedAdaptiveWebPolicy): readonly WorkerResolvedAddress[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) throw new TypeError("resolvedAddresses must be a non-empty bounded array");
  return Object.freeze(
    value.map((entry, index) => {
      const row = objectValue(entry, `resolvedAddresses[${index}]`);
      const host = boundedString(String(row.host ?? ""), `resolvedAddresses[${index}].host`, 512);
      const address = boundedString(String(row.address ?? ""), `resolvedAddresses[${index}].address`, 128);
      if (isIP(address) === 0) throw new TypeError(`resolvedAddresses[${index}].address is not an IP address`);
      if (!policy.allowPrivateNetwork && !isPublicIpAddress(address)) {
        throw new Error(`worker resolved private/local address for ${host}: ${address}`);
      }
      return Object.freeze({ host, address });
    }),
  );
}

function parseExtracted(value: unknown, request: ScraplingWorkerRequest, policy: NormalizedAdaptiveWebPolicy): Readonly<Record<string, readonly string[]>> | undefined {
  if (request.operation !== "EXTRACT") return undefined;
  const raw = objectValue(value, "extracted");
  const specs = new Map((request.fields ?? []).map((field) => [field.name, field]));
  const output: Record<string, readonly string[]> = {};
  let total = 0;
  for (const [name, spec] of specs) {
    const items = raw[name];
    if (!Array.isArray(items)) throw new TypeError(`extracted.${name} must be an array`);
    if (items.length > (spec.maxItems ?? 1)) throw new RangeError(`extracted.${name} exceeds field maxItems`);
    total += items.length;
    if (total > policy.maxExtractedItems) throw new RangeError("extracted values exceed policy maxExtractedItems");
    output[name] = Object.freeze(
      items.map((item, index) => {
        if (typeof item !== "string") throw new TypeError(`extracted.${name}[${index}] must be a string`);
        if (item.length > policy.maxValueChars) throw new RangeError(`extracted.${name}[${index}] exceeds maxValueChars`);
        return item;
      }),
    );
  }
  for (const name of Object.keys(raw)) if (!specs.has(name)) throw new TypeError(`worker returned undeclared extraction field: ${name}`);
  return Object.freeze(output);
}

function parseCandidates(value: unknown, request: ScraplingWorkerRequest): readonly AdaptiveElementFingerprint[] | undefined {
  if (request.operation !== "CANDIDATES") return undefined;
  if (!Array.isArray(value)) throw new TypeError("candidates must be an array");
  const maximum = request.candidateSelector?.maxCandidates ?? 0;
  if (value.length > maximum) throw new RangeError("worker returned too many candidates");
  const ids = new Set<string>();
  return Object.freeze(
    value.map((entry, index) => {
      const normalized = normalizeFingerprint(entry as AdaptiveElementFingerprint, `candidates[${index}]`);
      if (ids.has(normalized.id)) throw new TypeError(`duplicate candidate id: ${normalized.id}`);
      ids.add(normalized.id);
      return normalized;
    }),
  );
}

function parseXhr(value: unknown, request: ScraplingWorkerRequest, policy: NormalizedAdaptiveWebPolicy): readonly XhrEvidence[] | undefined {
  if (request.operation !== "XHR_CAPTURE") return undefined;
  if (!Array.isArray(value) || value.length > 2_000) throw new TypeError("xhr must be a bounded array");
  return Object.freeze(
    value.map((entry, index) => {
      const raw = objectValue(entry, `xhr[${index}]`);
      const url = typeof raw.url === "string" ? persistedUrl(authorizedResourceUrl(raw.url, policy, `xhr[${index}].url`)) : (() => { throw new TypeError(`xhr[${index}].url must be a string`); })();
      const status = nonNegativeInt(raw.status, `xhr[${index}].status`, 999);
      const bytes = nonNegativeInt(raw.bytes, `xhr[${index}].bytes`, policy.maxResponseBytes);
      if (typeof raw.sha256 !== "string" || !SHA256_PATTERN.test(raw.sha256)) throw new TypeError(`xhr[${index}].sha256 is invalid`);
      const contentType = raw.contentType === null || raw.contentType === undefined ? null : boundedString(String(raw.contentType), `xhr[${index}].contentType`, 512);
      const textExcerpt = raw.textExcerpt;
      const textTruncated = raw.textTruncated;
      if (request.xhr?.bodyMode === "HASH_ONLY" && (textExcerpt !== undefined || textTruncated !== undefined)) {
        throw new TypeError("HASH_ONLY XHR response must not include text excerpt");
      }
      if (textExcerpt !== undefined && (typeof textExcerpt !== "string" || textExcerpt.length > policy.maxValueChars)) {
        throw new RangeError(`xhr[${index}].textExcerpt exceeds maxValueChars`);
      }
      if (textTruncated !== undefined && typeof textTruncated !== "boolean") throw new TypeError(`xhr[${index}].textTruncated must be boolean`);
      return Object.freeze({
        url,
        status,
        bytes,
        sha256: raw.sha256,
        contentType,
        ...(textExcerpt === undefined ? {} : { textExcerpt }),
        ...(textTruncated === undefined ? {} : { textTruncated }),
      });
    }),
  );
}

export function parseScraplingWorkerResponse(
  rawJson: string,
  request: ScraplingWorkerRequest,
  policyInput: AdaptiveWebPolicy,
): ScraplingWorkerResponse {
  if (Buffer.byteLength(rawJson, "utf8") > 8 * 1024 * 1024) throw new RangeError("worker response exceeds 8 MiB envelope limit");
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson) as unknown;
  } catch {
    throw new TypeError("worker response must be valid JSON");
  }
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const value = objectValue(parsed, "worker response");
  if (value.schemaVersion !== "toadaid.scrapling-worker.response.v1") throw new TypeError("unsupported worker response schemaVersion");
  if (value.requestId !== request.requestId) throw new TypeError("worker response requestId mismatch");
  if (value.operation !== request.operation) throw new TypeError("worker response operation mismatch");
  if (value.status !== "OK") throw new TypeError("worker response status must be OK");
  const requestedUrl = safeWorkerUrl(value.requestedUrl, "worker requestedUrl", policy);
  if (requestedUrl !== persistedUrl(authorizedUrl(request.url, policy, "request.url"))) throw new TypeError("worker requestedUrl does not match request");
  const finalUrl = safeWorkerUrl(value.finalUrl, "worker finalUrl", policy);
  const responseBytes = nonNegativeInt(value.responseBytes, "responseBytes", policy.maxResponseBytes);
  if (typeof value.responseSha256 !== "string" || !SHA256_PATTERN.test(value.responseSha256)) throw new TypeError("responseSha256 is invalid");
  const resolvedAddresses = parseResolvedAddresses(value.resolvedAddresses, policy);
  const extracted = parseExtracted(value.extracted, request, policy);
  const candidates = parseCandidates(value.candidates, request);
  const xhr = parseXhr(value.xhr, request, policy);
  return Object.freeze({
    schemaVersion: "toadaid.scrapling-worker.response.v1",
    requestId: request.requestId,
    operation: request.operation,
    status: "OK",
    requestedUrl,
    finalUrl,
    httpStatus: nonNegativeInt(value.httpStatus, "httpStatus", 999),
    responseBytes,
    responseSha256: value.responseSha256,
    resolvedAddresses,
    ...(extracted === undefined ? {} : { extracted }),
    ...(candidates === undefined ? {} : { candidates }),
    ...(xhr === undefined ? {} : { xhr }),
  });
}
