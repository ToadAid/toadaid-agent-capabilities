import {
  boundBrowserDomEvidence,
  browserFreshDomTokenSha256,
  normalizeBrowserResiliencePolicy,
  persistedBrowserUrl,
  resilienceSha256,
  validateBrowserFreshDomToken,
} from "./browserResilienceSchema.js";
import type {
  BrowserCaptureFailureReason,
  BrowserDegradedEvidenceReceipt,
  BrowserFreshDomToken,
  BrowserNavigationObservation,
  BrowserReadinessReceipt,
  BrowserResilienceDomEvidence,
  BrowserResilienceDomInput,
  BrowserResiliencePolicy,
  BrowserResilienceRuntime,
  BrowserResilienceState,
} from "./browserResilienceTypes.js";

export {
  boundBrowserDomEvidence,
  browserFreshDomTokenSha256,
  normalizeBrowserResiliencePolicy,
  persistedBrowserUrl,
  stableInteractiveElementIds,
  validateBrowserFreshDomToken,
} from "./browserResilienceSchema.js";
export type * from "./browserResilienceTypes.js";

function nowIso(runtime?: BrowserResilienceRuntime): string {
  return (runtime?.now ?? (() => new Date()))().toISOString();
}

export function createBrowserResilienceState(initialUrl?: string): BrowserResilienceState {
  const persisted = initialUrl === undefined ? null : persistedBrowserUrl(initialUrl);
  return Object.freeze({
    schemaVersion: "toadaid.browser-resilience-state.v1",
    navigationEpoch: 0,
    pageIdentitySha256: persisted === null ? null : resilienceSha256({ epoch: 0, url: persisted }),
    lastKnownUrl: persisted,
    freshDomToken: null,
    invalidationReason: "NO_FRESH_CAPTURE",
  });
}

export function beginBrowserNavigation(state: BrowserResilienceState, targetUrl: string): BrowserResilienceState {
  const url = persistedBrowserUrl(targetUrl);
  const epoch = state.navigationEpoch + 1;
  return Object.freeze({
    schemaVersion: "toadaid.browser-resilience-state.v1",
    navigationEpoch: epoch,
    pageIdentitySha256: resilienceSha256({ epoch, url }),
    lastKnownUrl: url,
    freshDomToken: null,
    invalidationReason: "NAVIGATION_STARTED",
  });
}

export function assessBrowserNavigationReadiness(
  state: BrowserResilienceState,
  observation: BrowserNavigationObservation,
): BrowserReadinessReceipt {
  const beforeUrl = persistedBrowserUrl(observation.beforeUrl);
  const afterUrl = persistedBrowserUrl(observation.afterUrl);
  let decision: BrowserReadinessReceipt["decision"] = "READY";
  let reason = "READY";
  if (observation.pageClosed) {
    decision = "BLOCKED";
    reason = "PAGE_CLOSED";
  } else if (observation.navigationKind === "SAME_DOCUMENT") {
    // Same-document changes do not require a new DOMContentLoaded event.
    decision = "READY";
    reason = observation.timedOut ? "SAME_DOCUMENT_TIMEOUT_IGNORED" : "SAME_DOCUMENT_READY";
  } else if (observation.navigationKind === "FULL_DOCUMENT" && observation.timedOut) {
    decision = "DEGRADED";
    reason = "FULL_DOCUMENT_READINESS_TIMEOUT";
  } else if (observation.navigationKind === "FULL_DOCUMENT" && !observation.domContentLoaded) {
    decision = "DEGRADED";
    reason = "FULL_DOCUMENT_NOT_READY";
  }
  return Object.freeze({
    schemaVersion: "toadaid.browser-readiness.v1",
    navigationEpoch: state.navigationEpoch,
    navigationKind: observation.navigationKind,
    decision,
    reason,
    beforeUrl,
    afterUrl,
  });
}

export function recordFreshBrowserDom(
  state: BrowserResilienceState,
  domInput: BrowserResilienceDomInput,
  currentUrl: string,
  policy: BrowserResiliencePolicy = {},
): { readonly state: BrowserResilienceState; readonly dom: BrowserResilienceDomEvidence; readonly token: BrowserFreshDomToken } {
  const url = persistedBrowserUrl(currentUrl);
  const dom = boundBrowserDomEvidence(domInput, policy);
  const pageIdentitySha256 = resilienceSha256({ epoch: state.navigationEpoch, url });
  const core = Object.freeze({
    schemaVersion: "toadaid.browser-fresh-dom-token.v1" as const,
    navigationEpoch: state.navigationEpoch,
    pageIdentitySha256,
    domSha256: dom.domSha256,
  });
  const token = Object.freeze({ ...core, tokenSha256: browserFreshDomTokenSha256(core) });
  const next = Object.freeze({
    schemaVersion: "toadaid.browser-resilience-state.v1" as const,
    navigationEpoch: state.navigationEpoch,
    pageIdentitySha256,
    lastKnownUrl: url,
    freshDomToken: token,
    invalidationReason: null,
  });
  return Object.freeze({ state: next, dom, token });
}

export function assertFreshBrowserDom(
  state: BrowserResilienceState,
  tokenInput: BrowserFreshDomToken,
  currentUrl: string,
): BrowserFreshDomToken {
  const token = validateBrowserFreshDomToken(tokenInput);
  const url = persistedBrowserUrl(currentUrl);
  const currentPageIdentity = resilienceSha256({ epoch: state.navigationEpoch, url });
  if (state.freshDomToken === null) throw new Error(`stale DOM refused: ${state.invalidationReason ?? "NO_FRESH_CAPTURE"}`);
  if (token.navigationEpoch !== state.navigationEpoch) throw new Error("stale DOM refused: navigation epoch changed");
  if (token.pageIdentitySha256 !== currentPageIdentity || state.pageIdentitySha256 !== currentPageIdentity) throw new Error("stale DOM refused: page identity changed");
  if (token.tokenSha256 !== state.freshDomToken.tokenSha256) throw new Error("stale DOM refused: token is not current");
  return token;
}

const RECOVERABLE = new Set<BrowserCaptureFailureReason>([
  "NAVIGATION_TIMEOUT",
  "DOM_CAPTURE_TIMEOUT",
  "DOM_CAPTURE_FAILED",
  "SCREENSHOT_FAILED",
  "OUTPUT_TRUNCATED",
]);

export function recordBrowserCaptureFailure(
  state: BrowserResilienceState,
  input: {
    readonly phase: string;
    readonly reason: BrowserCaptureFailureReason;
    readonly errorFingerprintSha256: string;
    readonly lastKnownUrl?: string | null;
  },
  runtime?: BrowserResilienceRuntime,
): { readonly state: BrowserResilienceState; readonly receipt: BrowserDegradedEvidenceReceipt } {
  if (!/^[0-9a-f]{64}$/.test(input.errorFingerprintSha256)) throw new TypeError("errorFingerprintSha256 must be lowercase SHA-256");
  const priorDom = state.freshDomToken?.domSha256 ?? null;
  const lastKnownUrl = input.lastKnownUrl == null ? state.lastKnownUrl : persistedBrowserUrl(input.lastKnownUrl);
  const next = Object.freeze({
    schemaVersion: "toadaid.browser-resilience-state.v1" as const,
    navigationEpoch: state.navigationEpoch,
    pageIdentitySha256: state.pageIdentitySha256,
    lastKnownUrl,
    freshDomToken: null,
    invalidationReason: input.reason,
  });
  const receipt = Object.freeze({
    schemaVersion: "toadaid.browser-degraded-evidence.v1" as const,
    status: "DEGRADED" as const,
    navigationEpoch: state.navigationEpoch,
    phase: String(input.phase).slice(0, 128),
    reason: input.reason,
    recoverable: RECOVERABLE.has(input.reason),
    staleDomRefused: true as const,
    lastKnownUrl,
    errorFingerprintSha256: input.errorFingerprintSha256,
    previousFreshDomSha256: priorDom,
    observedAt: nowIso(runtime),
  });
  return Object.freeze({ state: next, receipt });
}
