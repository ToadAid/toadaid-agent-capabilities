import { randomUUID } from "node:crypto";
import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import type {
  AdaptiveWebPolicy, CrawlCheckpoint, CrawlCheckpointEnvelope, CrawlContinuityBinding, CrawlPolicy, CrawlResumeBinding, CrawlStepResult, CreateCrawlCheckpointInput, NormalizedAdaptiveWebPolicy
} from "./adaptiveWebTypes.js";
import { SHA256_PATTERN, assertAuthority, authorizedUrl, boundedString, canonicalJson, exactInt, exactOrigin, normalizeAdaptiveWebPolicy, normalizeCrawlUrl, sha256 } from "./adaptiveWebPolicy.js";
import { nonNegativeInt, objectValue } from "./adaptiveWebResponse.js";

function assertIso(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must be canonical ISO-8601`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) throw new TypeError(`${label} must be canonical ISO-8601`);
  return value;
}

function assertSha(value: string, label: string): string {
  if (!SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256 hex digest`);
  return value;
}

function normalizeContinuity(binding: CrawlContinuityBinding): CrawlContinuityBinding {
  const runId = boundedString(binding.runId, "continuity.runId", 128);
  const runCapsuleSha256 = assertSha(binding.runCapsuleSha256, "continuity.runCapsuleSha256");
  const childTaskId = binding.childTaskId === null ? null : boundedString(binding.childTaskId, "continuity.childTaskId", 128);
  const childTaskSha256 = binding.childTaskSha256 === null ? null : assertSha(binding.childTaskSha256, "continuity.childTaskSha256");
  if ((childTaskId === null) !== (childTaskSha256 === null)) throw new TypeError("child task continuity requires both id and sha or neither");
  return Object.freeze({ runId, runCapsuleSha256, childTaskId, childTaskSha256 });
}

function freezeCheckpoint(checkpoint: CrawlCheckpoint): CrawlCheckpoint {
  return Object.freeze({
    ...checkpoint,
    continuity: Object.freeze({ ...checkpoint.continuity }),
    pending: Object.freeze(checkpoint.pending.map((entry) => Object.freeze({ ...entry }))),
    seenUrls: Object.freeze([...checkpoint.seenUrls]),
    origins: Object.freeze(checkpoint.origins.map((entry) => Object.freeze({ ...entry }))),
  });
}

export function crawlCheckpointSha256(checkpoint: CrawlCheckpoint): string {
  return sha256(checkpoint);
}

export function sealCrawlCheckpoint(checkpoint: CrawlCheckpoint): CrawlCheckpointEnvelope {
  const normalized = freezeCheckpoint(checkpoint);
  return Object.freeze({
    schemaVersion: "toadaid.web-crawl-checkpoint-envelope.v1",
    checkpoint: normalized,
    checkpointSha256: crawlCheckpointSha256(normalized),
  });
}

export function createCrawlCheckpoint(
  input: CreateCrawlCheckpointInput,
  policyInput: AdaptiveWebPolicy,
  authority: CapabilityAuthorityDecision,
): CrawlCheckpointEnvelope {
  assertAuthority(authority, "web:crawl");
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  if (!Array.isArray(input.seedUrls) || input.seedUrls.length === 0 || input.seedUrls.length > policy.crawl.maxUrls) {
    throw new RangeError(`seedUrls must contain between 1 and ${policy.crawl.maxUrls} entries`);
  }
  const seedUrls = [...new Set(input.seedUrls.map((url, index) => normalizeCrawlUrl(url, policy, `seedUrls[${index}]`)))].sort();
  const createdAt = assertIso(input.createdAt, "createdAt");
  const checkpoint: CrawlCheckpoint = {
    schemaVersion: "toadaid.web-crawl-checkpoint.v1",
    crawlId: boundedString(input.crawlId ?? randomUUID(), "crawlId", 128),
    ownerId: boundedString(input.ownerId, "ownerId", 256),
    revision: 0,
    createdAt,
    updatedAt: createdAt,
    continuity: normalizeContinuity(input.continuity),
    pending: seedUrls.map((url) => Object.freeze({ url, depth: 0 })),
    seenUrls: Object.freeze([]),
    origins: Object.freeze([]),
    previousCheckpointSha256: null,
  };
  return sealCrawlCheckpoint(checkpoint);
}

export function validateCrawlCheckpointEnvelope(value: unknown, policyInput: AdaptiveWebPolicy): CrawlCheckpointEnvelope {
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const envelope = objectValue(value, "crawl checkpoint envelope");
  if (envelope.schemaVersion !== "toadaid.web-crawl-checkpoint-envelope.v1") throw new TypeError("unsupported crawl checkpoint envelope schemaVersion");
  const raw = objectValue(envelope.checkpoint, "crawl checkpoint");
  if (raw.schemaVersion !== "toadaid.web-crawl-checkpoint.v1") throw new TypeError("unsupported crawl checkpoint schemaVersion");
  if (!Array.isArray(raw.pending) || !Array.isArray(raw.seenUrls) || !Array.isArray(raw.origins)) throw new TypeError("crawl checkpoint arrays are invalid");
  const pending = raw.pending.map((entry, index) => {
    const row = objectValue(entry, `pending[${index}]`);
    return Object.freeze({
      url: normalizeCrawlUrl(String(row.url), policy, `pending[${index}].url`),
      depth: nonNegativeInt(row.depth, `pending[${index}].depth`, policy.crawl.maxDepth),
    });
  });
  const seenUrls = raw.seenUrls.map((url, index) => normalizeCrawlUrl(String(url), policy, `seenUrls[${index}]`));
  if (pending.length + seenUrls.length > policy.crawl.maxUrls) throw new RangeError("crawl checkpoint exceeds maxUrls");
  const identities = new Set<string>();
  for (const entry of pending) {
    if (identities.has(entry.url)) throw new TypeError(`duplicate crawl URL: ${entry.url}`);
    identities.add(entry.url);
  }
  for (const url of seenUrls) {
    if (identities.has(url)) throw new TypeError(`crawl URL exists in both pending and seen: ${url}`);
    identities.add(url);
  }
  const origins = raw.origins.map((entry, index) => {
    const row = objectValue(entry, `origins[${index}]`);
    const origin = exactOrigin(String(row.origin), `origins[${index}].origin`);
    if (!policy.allowedTopLevelOrigins.includes(origin)) throw new Error(`checkpoint origin is not authorized: ${origin}`);
    return Object.freeze({
      origin,
      requests: nonNegativeInt(row.requests, `origins[${index}].requests`, policy.crawl.perOriginMaxRequests),
      nextDelayMs: nonNegativeInt(row.nextDelayMs, `origins[${index}].nextDelayMs`, policy.crawl.maxDelayMs),
    });
  });
  const checkpoint = freezeCheckpoint({
    schemaVersion: "toadaid.web-crawl-checkpoint.v1",
    crawlId: boundedString(String(raw.crawlId), "crawlId", 128),
    ownerId: boundedString(String(raw.ownerId), "ownerId", 256),
    revision: nonNegativeInt(raw.revision, "revision"),
    createdAt: assertIso(String(raw.createdAt), "createdAt"),
    updatedAt: assertIso(String(raw.updatedAt), "updatedAt"),
    continuity: normalizeContinuity(raw.continuity as CrawlContinuityBinding),
    pending,
    seenUrls: Object.freeze([...seenUrls].sort()),
    origins: Object.freeze([...origins].sort((a, b) => a.origin.localeCompare(b.origin))),
    previousCheckpointSha256:
      raw.previousCheckpointSha256 === null ? null : assertSha(String(raw.previousCheckpointSha256), "previousCheckpointSha256"),
  });
  if (typeof envelope.checkpointSha256 !== "string" || !SHA256_PATTERN.test(envelope.checkpointSha256)) throw new TypeError("checkpointSha256 is invalid");
  if (crawlCheckpointSha256(checkpoint) !== envelope.checkpointSha256) throw new Error("crawl checkpoint SHA-256 mismatch");
  return Object.freeze({
    schemaVersion: "toadaid.web-crawl-checkpoint-envelope.v1",
    checkpoint,
    checkpointSha256: envelope.checkpointSha256,
  });
}

export function assertCrawlCheckpointBinding(envelope: CrawlCheckpointEnvelope, binding: CrawlResumeBinding): void {
  const expected = normalizeContinuity({
    runId: binding.runId,
    runCapsuleSha256: binding.runCapsuleSha256,
    childTaskId: binding.childTaskId ?? null,
    childTaskSha256: binding.childTaskSha256 ?? null,
  });
  const actual = envelope.checkpoint.continuity;
  if (
    actual.runId !== expected.runId ||
    actual.runCapsuleSha256 !== expected.runCapsuleSha256 ||
    actual.childTaskId !== expected.childTaskId ||
    actual.childTaskSha256 !== expected.childTaskSha256
  ) {
    throw new Error("crawl checkpoint continuity binding does not match current P4/P5 state");
  }
}

function updatedDelay(current: number, result: CrawlStepResult, policy: CrawlPolicy): number {
  if (result.blocked || result.httpStatus === 429 || result.httpStatus === 503) {
    return Math.min(policy.maxDelayMs, Math.max(policy.minDelayMs, Math.ceil(Math.max(current, policy.minDelayMs) * policy.backoffFactor)));
  }
  if (result.latencyMs > policy.targetLatencyMs) {
    return Math.min(policy.maxDelayMs, Math.max(policy.minDelayMs, Math.ceil((current + result.latencyMs) / 2)));
  }
  return Math.max(policy.minDelayMs, Math.floor(current * 0.8));
}

export function advanceCrawlCheckpoint(
  envelopeInput: CrawlCheckpointEnvelope,
  step: CrawlStepResult,
  continuity: CrawlContinuityBinding,
  policyInput: AdaptiveWebPolicy,
  authority: CapabilityAuthorityDecision,
): CrawlCheckpointEnvelope {
  assertAuthority(authority, "web:crawl");
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  const envelope = validateCrawlCheckpointEnvelope(envelopeInput, policyInput);
  const current = envelope.checkpoint;
  const stepUrl = normalizeCrawlUrl(step.url, policy, "step.url");
  const pendingIndex = current.pending.findIndex((entry) => entry.url === stepUrl && entry.depth === step.depth);
  if (pendingIndex < 0) throw new Error("crawl step does not match a pending queue entry");
  const completedAt = assertIso(step.completedAt, "step.completedAt");
  if (Date.parse(completedAt) < Date.parse(current.updatedAt)) throw new Error("crawl step completedAt precedes checkpoint updatedAt");
  const latencyMs = exactInt(step.latencyMs, step.latencyMs, 0, 10 * 60 * 1_000, "step.latencyMs");
  const origin = new URL(stepUrl).origin;
  const originMap = new Map(current.origins.map((entry) => [entry.origin, { ...entry }]));
  const state = originMap.get(origin) ?? { origin, requests: 0, nextDelayMs: policy.crawl.minDelayMs };
  if (state.requests >= policy.crawl.perOriginMaxRequests) throw new Error(`crawl per-origin request budget exhausted: ${origin}`);
  state.requests += 1;
  state.nextDelayMs = updatedDelay(state.nextDelayMs, { ...step, url: stepUrl, latencyMs }, policy.crawl);
  originMap.set(origin, state);

  const pending = current.pending.filter((_, index) => index !== pendingIndex).map((entry) => ({ ...entry }));
  const seenSet = new Set(current.seenUrls);
  seenSet.add(stepUrl);
  const queued = new Set(pending.map((entry) => entry.url));
  if (step.depth < policy.crawl.maxDepth && !step.blocked) {
    const discovered = [...new Set(step.discoveredUrls.map((url, index) => normalizeCrawlUrl(url, policy, `step.discoveredUrls[${index}]`)))].sort();
    for (const url of discovered) {
      if (seenSet.has(url) || queued.has(url)) continue;
      if (seenSet.size + pending.length >= policy.crawl.maxUrls) break;
      const discoveredOrigin = new URL(url).origin;
      const discoveredState = originMap.get(discoveredOrigin);
      if ((discoveredState?.requests ?? 0) >= policy.crawl.perOriginMaxRequests) continue;
      pending.push({ url, depth: step.depth + 1 });
      queued.add(url);
    }
  }
  pending.sort((a, b) => a.depth - b.depth || a.url.localeCompare(b.url));
  const checkpoint = freezeCheckpoint({
    schemaVersion: "toadaid.web-crawl-checkpoint.v1",
    crawlId: current.crawlId,
    ownerId: current.ownerId,
    revision: current.revision + 1,
    createdAt: current.createdAt,
    updatedAt: completedAt,
    continuity: normalizeContinuity(continuity),
    pending,
    seenUrls: Object.freeze([...seenSet].sort()),
    origins: Object.freeze([...originMap.values()].sort((a, b) => a.origin.localeCompare(b.origin))),
    previousCheckpointSha256: envelope.checkpointSha256,
  });
  return sealCrawlCheckpoint(checkpoint);
}

export function assertCrawlCheckpointPredecessor(previous: CrawlCheckpointEnvelope, next: CrawlCheckpointEnvelope): void {
  if (previous.checkpoint.crawlId !== next.checkpoint.crawlId) throw new Error("crawl checkpoint predecessor crawlId mismatch");
  if (previous.checkpoint.ownerId !== next.checkpoint.ownerId) throw new Error("crawl checkpoint predecessor ownerId mismatch");
  if (next.checkpoint.revision !== previous.checkpoint.revision + 1) throw new Error("crawl checkpoint revision is not contiguous");
  if (next.checkpoint.previousCheckpointSha256 !== previous.checkpointSha256) throw new Error("crawl checkpoint predecessor SHA mismatch");
}
