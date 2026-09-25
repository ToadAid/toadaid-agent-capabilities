import test from "node:test";
import assert from "node:assert/strict";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  advanceCrawlCheckpoint,
  assertCrawlCheckpointBinding,
  assertCrawlCheckpointPredecessor,
  buildCrawlWorkerRequest,
  buildScraplingWorkerRequest,
  createCrawlCheckpoint,
  crawlCheckpointSha256,
  isPublicIpAddress,
  normalizeAdaptiveWebPolicy,
  parseScraplingWorkerResponse,
  resolveCrawlDiscoveredUrls,
  scoreAdaptiveElementCandidate,
  selectAdaptiveElementCandidate,
  validateCrawlCheckpointEnvelope,
  type AdaptiveElementFingerprint,
  type AdaptiveWebCapabilityId,
  type AdaptiveWebPolicy,
} from "../src/adaptiveWebIntelligence.js";

function allow(capabilityId: AdaptiveWebCapabilityId): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: "ALLOW",
    reason: "AUTHORIZED_BY_POLICY",
    trace: [],
  };
}

const policy: AdaptiveWebPolicy = {
  allowedTopLevelOrigins: ["https://example.com", "https://api.example.com"],
  allowedResourceOrigins: ["https://cdn.example.com"],
};

const runA = "a".repeat(64);
const runB = "b".repeat(64);
const childA = "c".repeat(64);
const childB = "d".repeat(64);

function fp(id: string, patch: Partial<AdaptiveElementFingerprint> = {}): AdaptiveElementFingerprint {
  return {
    id,
    tag: "button",
    text: "Portfolio",
    attributes: { class: "primary action", role: "button" },
    parent: { tag: "nav", text: "Main", attributes: { class: "header" } },
    siblingTags: ["a", "button", "a"],
    pathTags: ["html", "body", "nav", "button"],
    ...patch,
  };
}

test("policy normalization is exact-origin, bounded, and fail-closed", () => {
  const normalized = normalizeAdaptiveWebPolicy({
    allowedTopLevelOrigins: ["https://example.com/a", "https://example.com/b"],
  });
  assert.deepEqual(normalized.allowedTopLevelOrigins, ["https://example.com"]);
  assert.equal(normalized.allowPrivateNetwork, false);
  assert.equal(normalized.crawl.maxUrls, 200);
  assert.throws(() => normalizeAdaptiveWebPolicy({ allowedTopLevelOrigins: ["file:///tmp/x"] }), /http: or https:/);
});

test("IP classifier refuses local/private/reserved ranges", () => {
  assert.equal(isPublicIpAddress("8.8.8.8"), true);
  assert.equal(isPublicIpAddress("10.0.0.1"), false);
  assert.equal(isPublicIpAddress("127.0.0.1"), false);
  assert.equal(isPublicIpAddress("169.254.169.254"), false);
  assert.equal(isPublicIpAddress("192.0.2.1"), false);
  assert.equal(isPublicIpAddress("::1"), false);
  assert.equal(isPublicIpAddress("fd00::1"), false);
  assert.equal(isPublicIpAddress("2001:4860:4860::8888"), true);
  assert.equal(isPublicIpAddress("::ffff:127.0.0.1"), false);
});

test("extract worker request requires exact authority and carries no authority token", () => {
  const request = buildScraplingWorkerRequest(
    {
      kind: "extract",
      url: "https://example.com/products?source=agent",
      fields: [{ name: "title", selectorKind: "CSS", selector: "h1", valueKind: "TEXT" }],
    },
    policy,
    { extract: allow("web:extract") },
    "request-1",
  );
  assert.equal(request.operation, "EXTRACT");
  assert.equal(request.fetchMode, "HTTP");
  assert.equal(request.capability, "web:extract");
  assert.equal("authority" in (request as unknown as Record<string, unknown>), false);
  assert.throws(
    () =>
      buildScraplingWorkerRequest(
        {
          kind: "extract",
          url: "https://example.com/",
          fields: [{ name: "title", selectorKind: "CSS", selector: "h1", valueKind: "TEXT" }],
        },
        policy,
        {},
      ),
    /not authorized/,
  );
});

test("stealth mode requires separate web:stealth-fetch authority", () => {
  const intent = {
    kind: "extract" as const,
    url: "https://example.com/",
    fetchMode: "STEALTH" as const,
    fields: [{ name: "title", selectorKind: "CSS" as const, selector: "h1", valueKind: "TEXT" as const }],
  };
  assert.throws(() => buildScraplingWorkerRequest(intent, policy, { extract: allow("web:extract") }), /web:stealth-fetch/);
  const request = buildScraplingWorkerRequest(intent, policy, {
    extract: allow("web:extract"),
    stealthFetch: allow("web:stealth-fetch"),
  });
  assert.equal(request.fetchMode, "STEALTH");
});

test("XHR capture requires explicit authority and browser/stealth mode", () => {
  const request = buildScraplingWorkerRequest(
    {
      kind: "xhr-capture",
      url: "https://example.com/dashboard",
      pattern: "https://api\\.example\\.com/.*",
    },
    policy,
    { xhrCapture: allow("web:xhr-capture") },
  );
  assert.equal(request.operation, "XHR_CAPTURE");
  assert.equal(request.fetchMode, "BROWSER");
  assert.equal(request.xhr?.bodyMode, "HASH_ONLY");
});

test("worker response is origin/address/size constrained and hashes XHR-only by default", () => {
  const request = buildScraplingWorkerRequest(
    {
      kind: "xhr-capture",
      url: "https://example.com/dashboard",
      pattern: "https://api\\.example\\.com/.*",
    },
    policy,
    { xhrCapture: allow("web:xhr-capture") },
    "xhr-1",
  );
  const response = parseScraplingWorkerResponse(
    JSON.stringify({
      schemaVersion: "toadaid.scrapling-worker.response.v1",
      requestId: "xhr-1",
      operation: "XHR_CAPTURE",
      status: "OK",
      requestedUrl: "https://example.com/dashboard?secret=gone",
      finalUrl: "https://example.com/dashboard#state",
      httpStatus: 200,
      responseBytes: 100,
      responseSha256: "1".repeat(64),
      resolvedAddresses: [{ host: "example.com", address: "93.184.216.34" }],
      xhr: [
        {
          url: "https://api.example.com/data?token=gone",
          status: 200,
          bytes: 12,
          sha256: "2".repeat(64),
          contentType: "application/json",
        },
      ],
    }),
    request,
    policy,
  );
  assert.equal(response.requestedUrl, "https://example.com/dashboard");
  assert.equal(response.finalUrl, "https://example.com/dashboard");
  assert.equal(response.xhr?.[0]?.url, "https://api.example.com/data");
  assert.equal("textExcerpt" in (response.xhr?.[0] ?? {}), false);

  const privateAddress = JSON.stringify({
    ...response,
    requestedUrl: "https://example.com/dashboard",
    finalUrl: "https://example.com/dashboard",
    resolvedAddresses: [{ host: "example.com", address: "127.0.0.1" }],
  });
  assert.throws(() => parseScraplingWorkerResponse(privateAddress, request, policy), /private\/local/);
});

test("adaptive scorer selects a strong unique structural match", () => {
  const reference = fp("reference");
  const strong = fp("strong", { text: "Portfolio Overview" });
  const weak = fp("weak", {
    tag: "div",
    text: "Logout",
    attributes: { class: "footer" },
    parent: { tag: "footer", text: "Footer", attributes: {} },
    siblingTags: ["span"],
    pathTags: ["html", "body", "footer", "div"],
  });
  assert.ok(scoreAdaptiveElementCandidate(reference, strong) > scoreAdaptiveElementCandidate(reference, weak));
  const result = selectAdaptiveElementCandidate(reference, [weak, strong], policy);
  assert.equal(result.decision, "MATCH");
  assert.equal(result.selectedCandidateId, "strong");
  assert.ok(result.confidence >= 0.65);
});

test("adaptive scorer fails closed on ambiguous candidates", () => {
  const reference = fp("reference");
  const first = fp("a", { text: "Portfolio one" });
  const second = fp("b", { text: "Portfolio two" });
  const result = selectAdaptiveElementCandidate(reference, [first, second], {
    ...policy,
    adaptiveMinimumConfidence: 0.5,
    adaptiveAmbiguityMargin: 0.1,
  });
  assert.equal(result.decision, "AMBIGUOUS");
  assert.equal(result.selectedCandidateId, null);
});


test("crawl worker request uses web:crawl authority without silently borrowing web:extract", () => {
  const request = buildCrawlWorkerRequest(
    {
      entry: { url: "https://example.com/list", depth: 1 },
      fields: [{ name: "links", selectorKind: "CSS", selector: "a", valueKind: "ATTRIBUTE", attribute: "href", multiple: true }],
    },
    policy,
    { crawl: allow("web:crawl") },
    "crawl-fetch-1",
  );
  assert.equal(request.operation, "EXTRACT");
  assert.equal(request.capability, "web:crawl");
  assert.equal(request.fetchMode, "HTTP");
});

test("crawl link resolver keeps only authorized query-free resumable URLs", () => {
  const urls = resolveCrawlDiscoveredUrls(
    "https://example.com/base/",
    ["../a", "/b", "https://evil.example.net/no", "/secret?token=x", "#fragment", "/b"],
    policy,
  );
  assert.deepEqual(urls, ["https://example.com/a", "https://example.com/b"]);
});

test("crawl checkpoint is sealed and bound to exact P4/P5 continuity", () => {
  const envelope = createCrawlCheckpoint(
    {
      crawlId: "crawl-1",
      ownerId: "agent0",
      createdAt: "2026-09-25T00:00:00.000Z",
      seedUrls: ["https://example.com/", "https://example.com/start"],
      continuity: {
        runId: "run-1",
        runCapsuleSha256: runA,
        childTaskId: "child-1",
        childTaskSha256: childA,
      },
    },
    policy,
    allow("web:crawl"),
  );
  assert.equal(envelope.checkpointSha256, crawlCheckpointSha256(envelope.checkpoint));
  assert.doesNotThrow(() =>
    assertCrawlCheckpointBinding(envelope, {
      runId: "run-1",
      runCapsuleSha256: runA,
      childTaskId: "child-1",
      childTaskSha256: childA,
    }),
  );
  assert.throws(
    () =>
      assertCrawlCheckpointBinding(envelope, {
        runId: "run-1",
        runCapsuleSha256: runB,
        childTaskId: "child-1",
        childTaskSha256: childA,
      }),
    /does not match current P4\/P5 state/,
  );
});

test("tampered crawl checkpoint fails seal validation", () => {
  const envelope = createCrawlCheckpoint(
    {
      ownerId: "agent0",
      createdAt: "2026-09-25T00:00:00.000Z",
      seedUrls: ["https://example.com/"],
      continuity: { runId: "run-1", runCapsuleSha256: runA, childTaskId: null, childTaskSha256: null },
    },
    policy,
    allow("web:crawl"),
  );
  const tampered = {
    ...envelope,
    checkpoint: { ...envelope.checkpoint, ownerId: "evil" },
  };
  assert.throws(() => validateCrawlCheckpointEnvelope(tampered, policy), /SHA-256 mismatch/);
});

test("resumable crawl refuses query-bearing checkpoint URLs", () => {
  assert.throws(
    () =>
      createCrawlCheckpoint(
        {
          ownerId: "agent0",
          createdAt: "2026-09-25T00:00:00.000Z",
          seedUrls: ["https://example.com/?token=secret"],
          continuity: { runId: "run-1", runCapsuleSha256: runA, childTaskId: null, childTaskSha256: null },
        },
        policy,
        allow("web:crawl"),
      ),
    /must not contain query or fragment/,
  );
});

test("crawl advance is contiguous, deduplicated, bounded, and updates throttle", () => {
  const first = createCrawlCheckpoint(
    {
      crawlId: "crawl-1",
      ownerId: "agent0",
      createdAt: "2026-09-25T00:00:00.000Z",
      seedUrls: ["https://example.com/"],
      continuity: { runId: "run-1", runCapsuleSha256: runA, childTaskId: "child-1", childTaskSha256: childA },
    },
    policy,
    allow("web:crawl"),
  );
  const next = advanceCrawlCheckpoint(
    first,
    {
      url: "https://example.com/",
      depth: 0,
      completedAt: "2026-09-25T00:00:05.000Z",
      httpStatus: 200,
      latencyMs: 1_500,
      blocked: false,
      discoveredUrls: ["https://example.com/a", "https://example.com/a", "https://example.com/b"],
    },
    { runId: "run-1", runCapsuleSha256: runB, childTaskId: "child-1", childTaskSha256: childB },
    policy,
    allow("web:crawl"),
  );
  assert.equal(next.checkpoint.revision, 1);
  assert.equal(next.checkpoint.previousCheckpointSha256, first.checkpointSha256);
  assert.deepEqual(next.checkpoint.pending.map((entry) => entry.url), ["https://example.com/a", "https://example.com/b"]);
  assert.equal(next.checkpoint.seenUrls[0], "https://example.com/");
  assert.ok((next.checkpoint.origins[0]?.nextDelayMs ?? 0) >= 250);
  assert.doesNotThrow(() => assertCrawlCheckpointPredecessor(first, next));
});

test("429/blocked crawl response backs off and does not enqueue discovered work", () => {
  const first = createCrawlCheckpoint(
    {
      ownerId: "agent0",
      createdAt: "2026-09-25T00:00:00.000Z",
      seedUrls: ["https://example.com/"],
      continuity: { runId: "run-1", runCapsuleSha256: runA, childTaskId: null, childTaskSha256: null },
    },
    policy,
    allow("web:crawl"),
  );
  const next = advanceCrawlCheckpoint(
    first,
    {
      url: "https://example.com/",
      depth: 0,
      completedAt: "2026-09-25T00:00:01.000Z",
      httpStatus: 429,
      latencyMs: 100,
      blocked: true,
      discoveredUrls: ["https://example.com/should-not-queue"],
    },
    { runId: "run-1", runCapsuleSha256: runB, childTaskId: null, childTaskSha256: null },
    policy,
    allow("web:crawl"),
  );
  assert.equal(next.checkpoint.pending.length, 0);
  assert.equal(next.checkpoint.origins[0]?.nextDelayMs, 500);
});

test("crawl discovered origin outside policy fails before checkpoint mutation", () => {
  const first = createCrawlCheckpoint(
    {
      ownerId: "agent0",
      createdAt: "2026-09-25T00:00:00.000Z",
      seedUrls: ["https://example.com/"],
      continuity: { runId: "run-1", runCapsuleSha256: runA, childTaskId: null, childTaskSha256: null },
    },
    policy,
    allow("web:crawl"),
  );
  assert.throws(
    () =>
      advanceCrawlCheckpoint(
        first,
        {
          url: "https://example.com/",
          depth: 0,
          completedAt: "2026-09-25T00:00:01.000Z",
          httpStatus: 200,
          latencyMs: 100,
          blocked: false,
          discoveredUrls: ["https://evil.example.net/"],
        },
        { runId: "run-1", runCapsuleSha256: runB, childTaskId: null, childTaskSha256: null },
        policy,
        allow("web:crawl"),
      ),
    /origin is not authorized/,
  );
});
