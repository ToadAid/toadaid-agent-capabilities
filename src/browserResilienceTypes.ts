export type BrowserNavigationKind = "NONE" | "SAME_DOCUMENT" | "FULL_DOCUMENT";
export type BrowserReadinessDecision = "READY" | "DEGRADED" | "BLOCKED";
export type BrowserCaptureFailureReason =
  | "NAVIGATION_TIMEOUT"
  | "NAVIGATION_ABORTED"
  | "DOM_CAPTURE_TIMEOUT"
  | "DOM_CAPTURE_FAILED"
  | "SCREENSHOT_FAILED"
  | "OUTPUT_TRUNCATED"
  | "PAGE_CLOSED"
  | "UNKNOWN_BROWSER_FAILURE";

export interface BrowserResiliencePolicy {
  maxTextChars?: number;
  maxHeadings?: number;
  maxInteractiveElements?: number;
  navigationReadyTimeoutMs?: number;
}

export interface NormalizedBrowserResiliencePolicy {
  readonly maxTextChars: number;
  readonly maxHeadings: number;
  readonly maxInteractiveElements: number;
  readonly navigationReadyTimeoutMs: number;
}

export interface BrowserResilienceHeading {
  readonly level: number;
  readonly text: string;
}

export interface BrowserResilienceInteractiveElement {
  readonly stableId: string;
  readonly sourceIndex: number;
  readonly tag: string;
  readonly role: string | null;
  readonly ariaLabel: string | null;
  readonly text: string;
  readonly href: string | null;
  readonly type: string | null;
  readonly name: string | null;
}

export interface BrowserResilienceDomInput {
  readonly title: string;
  readonly textExcerpt: string;
  readonly textTruncated?: boolean;
  readonly headings: readonly {
    readonly level: number;
    readonly text: string;
  }[];
  readonly interactiveElements: readonly {
    readonly tag: string;
    readonly role: string | null;
    readonly ariaLabel: string | null;
    readonly text: string;
    readonly href: string | null;
    readonly type: string | null;
    readonly name: string | null;
  }[];
}

export interface BrowserResilienceDomEvidence {
  readonly title: string;
  readonly textExcerpt: string;
  readonly textTruncated: boolean;
  readonly headingsTruncated: boolean;
  readonly interactiveElementsTruncated: boolean;
  readonly headings: readonly BrowserResilienceHeading[];
  readonly interactiveElements: readonly BrowserResilienceInteractiveElement[];
  readonly domSha256: string;
}

export interface BrowserNavigationObservation {
  readonly beforeUrl: string;
  readonly afterUrl: string;
  readonly navigationKind: BrowserNavigationKind;
  readonly domContentLoaded: boolean;
  readonly timedOut?: boolean;
  readonly pageClosed?: boolean;
}

export interface BrowserReadinessReceipt {
  readonly schemaVersion: "toadaid.browser-readiness.v1";
  readonly navigationEpoch: number;
  readonly navigationKind: BrowserNavigationKind;
  readonly decision: BrowserReadinessDecision;
  readonly reason: string;
  readonly beforeUrl: string;
  readonly afterUrl: string;
}

export interface BrowserFreshDomToken {
  readonly schemaVersion: "toadaid.browser-fresh-dom-token.v1";
  readonly navigationEpoch: number;
  readonly pageIdentitySha256: string;
  readonly domSha256: string;
  readonly tokenSha256: string;
}

export interface BrowserDegradedEvidenceReceipt {
  readonly schemaVersion: "toadaid.browser-degraded-evidence.v1";
  readonly status: "DEGRADED";
  readonly navigationEpoch: number;
  readonly phase: string;
  readonly reason: BrowserCaptureFailureReason;
  readonly recoverable: boolean;
  readonly staleDomRefused: true;
  readonly lastKnownUrl: string | null;
  readonly errorFingerprintSha256: string;
  readonly previousFreshDomSha256: string | null;
  readonly observedAt: string;
}

export interface BrowserResilienceState {
  readonly schemaVersion: "toadaid.browser-resilience-state.v1";
  readonly navigationEpoch: number;
  readonly pageIdentitySha256: string | null;
  readonly lastKnownUrl: string | null;
  readonly freshDomToken: BrowserFreshDomToken | null;
  readonly invalidationReason: string | null;
}

export interface BrowserResilienceRuntime {
  readonly now?: () => Date;
}
