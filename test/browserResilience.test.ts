import assert from "node:assert/strict";
import test from "node:test";
import {
  assessBrowserNavigationReadiness,
  assertFreshBrowserDom,
  beginBrowserNavigation,
  boundBrowserDomEvidence,
  createBrowserResilienceState,
  recordBrowserCaptureFailure,
  recordFreshBrowserDom,
  stableInteractiveElementIds,
} from "../src/browserResilience.js";

const H = "a".repeat(64);
const dom = {
  title: "Frog",
  textExcerpt: "hello browser",
  headings: [{ level: 1, text: "Hello" }],
  interactiveElements: [
    { tag: "button", role: "button", ariaLabel: "Save", text: "Save", href: null, type: null, name: "save" },
    { tag: "a", role: null, ariaLabel: null, text: "Next", href: "https://example.com/next?secret=x#f", type: null, name: null },
  ],
};

test("fresh DOM becomes invalid immediately when navigation starts", () => {
  let state = createBrowserResilienceState("https://example.com/start?x=1");
  const captured = recordFreshBrowserDom(state, dom, "https://example.com/start?x=2");
  assertFreshBrowserDom(captured.state, captured.token, "https://example.com/start");
  state = beginBrowserNavigation(captured.state, "https://example.com/next?token=nope");
  assert.throws(() => assertFreshBrowserDom(state, captured.token, "https://example.com/next"), /stale DOM refused/);
  assert.equal(state.lastKnownUrl, "https://example.com/next");
});

test("capture failure refuses stale DOM and emits degraded evidence", () => {
  const initial = createBrowserResilienceState("https://example.com/");
  const captured = recordFreshBrowserDom(initial, dom, "https://example.com/");
  const failed = recordBrowserCaptureFailure(captured.state, {
    phase: "dom-capture",
    reason: "DOM_CAPTURE_TIMEOUT",
    errorFingerprintSha256: H,
  }, { now: () => new Date("2026-09-25T10:00:00.000Z") });
  assert.equal(failed.receipt.status, "DEGRADED");
  assert.equal(failed.receipt.recoverable, true);
  assert.equal(failed.receipt.previousFreshDomSha256, captured.dom.domSha256);
  assert.equal(failed.receipt.observedAt, "2026-09-25T10:00:00.000Z");
  assert.throws(() => assertFreshBrowserDom(failed.state, captured.token, "https://example.com/"), /DOM_CAPTURE_TIMEOUT/);
});

test("same-document navigation is ready without requiring DOMContentLoaded", () => {
  const state = beginBrowserNavigation(createBrowserResilienceState(), "https://example.com/page#two");
  const receipt = assessBrowserNavigationReadiness(state, {
    beforeUrl: "https://example.com/page#one",
    afterUrl: "https://example.com/page#two",
    navigationKind: "SAME_DOCUMENT",
    domContentLoaded: false,
    timedOut: true,
  });
  assert.equal(receipt.decision, "READY");
  assert.equal(receipt.reason, "SAME_DOCUMENT_TIMEOUT_IGNORED");
  assert.equal(receipt.beforeUrl, "https://example.com/page");
});

test("full-document readiness timeout degrades instead of fabricating readiness", () => {
  const state = beginBrowserNavigation(createBrowserResilienceState(), "https://example.com/b");
  const receipt = assessBrowserNavigationReadiness(state, {
    beforeUrl: "https://example.com/a",
    afterUrl: "https://example.com/b",
    navigationKind: "FULL_DOCUMENT",
    domContentLoaded: false,
    timedOut: true,
  });
  assert.equal(receipt.decision, "DEGRADED");
});

test("closed page blocks readiness", () => {
  const receipt = assessBrowserNavigationReadiness(createBrowserResilienceState("https://example.com"), {
    beforeUrl: "https://example.com",
    afterUrl: "https://example.com",
    navigationKind: "NONE",
    domContentLoaded: true,
    pageClosed: true,
  });
  assert.equal(receipt.decision, "BLOCKED");
});

test("DOM evidence is bounded and truncation is explicit", () => {
  const evidence = boundBrowserDomEvidence({
    ...dom,
    textExcerpt: "a".repeat(150),
    headings: Array.from({ length: 5 }, (_, i) => ({ level: 1, text: `h${i}` })),
    interactiveElements: Array.from({ length: 5 }, (_, i) => ({ ...dom.interactiveElements[0]!, text: `b${i}` })),
  }, { maxTextChars: 100, maxHeadings: 2, maxInteractiveElements: 2 });
  assert.equal(evidence.textExcerpt.length, 100);
  assert.equal(evidence.textTruncated, true);
  assert.equal(evidence.headingsTruncated, true);
  assert.equal(evidence.interactiveElementsTruncated, true);
  assert.equal(evidence.interactiveElements.length, 2);
});

test("stable IDs ignore query and fragment changes in href", () => {
  const a = stableInteractiveElementIds([{ ...dom.interactiveElements[1]!, href: "https://example.com/next?a=1#x" }]);
  const b = stableInteractiveElementIds([{ ...dom.interactiveElements[1]!, href: "https://example.com/next?a=2#y" }]);
  assert.equal(a[0]!.stableId, b[0]!.stableId);
});

test("stable IDs are deterministic across sessions for same semantic element", () => {
  const a = stableInteractiveElementIds(dom.interactiveElements);
  const b = stableInteractiveElementIds(dom.interactiveElements.map((item) => ({ ...item })));
  assert.deepEqual(a.map((x) => x.stableId), b.map((x) => x.stableId));
});

test("duplicate semantic elements receive distinct but deterministic stable IDs", () => {
  const button = dom.interactiveElements[0]!;
  const result = stableInteractiveElementIds([button, button]);
  assert.notEqual(result[0]!.stableId, result[1]!.stableId);
  assert.deepEqual(result.map((x) => x.stableId), stableInteractiveElementIds([button, button]).map((x) => x.stableId));
});

test("persisted URLs strip secrets", () => {
  const state = createBrowserResilienceState("https://example.com/path?token=secret#frag");
  assert.equal(state.lastKnownUrl, "https://example.com/path");
});

test("non-http URLs refuse", () => {
  assert.throws(() => createBrowserResilienceState("file:///etc/passwd"), /http: or https:/);
});

test("fresh token refuses a different current URL", () => {
  const state = createBrowserResilienceState("https://example.com/a");
  const captured = recordFreshBrowserDom(state, dom, "https://example.com/a");
  assert.throws(() => assertFreshBrowserDom(captured.state, captured.token, "https://example.com/b"), /page identity changed/);
});

test("fresh token integrity is tamper evident", () => {
  const captured = recordFreshBrowserDom(createBrowserResilienceState(), dom, "https://example.com/a");
  assert.throws(() => assertFreshBrowserDom(captured.state, { ...captured.token, domSha256: H }, "https://example.com/a"), /integrity mismatch/);
});

test("non-recoverable page closed receipt is explicit", () => {
  const failed = recordBrowserCaptureFailure(createBrowserResilienceState("https://example.com"), {
    phase: "capture",
    reason: "PAGE_CLOSED",
    errorFingerprintSha256: H,
  });
  assert.equal(failed.receipt.recoverable, false);
});
