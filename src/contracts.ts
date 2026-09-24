export interface BrowserEvidenceRequest {
  /** Agent intent. This does not grant authority. */
  url: string;
}

export interface BrowserEvidencePolicy {
  /** Exact HTTP(S) origins the top-level page may use. */
  allowedTopLevelOrigins: readonly string[];
  /** Additional exact HTTP(S) origins that page resources may use. */
  allowedResourceOrigins?: readonly string[];
  timeoutMs?: number;
  maxDomChars?: number;
  maxInteractiveElements?: number;
  fullPageScreenshot?: boolean;
}

export interface BrowserEvidenceRuntime {
  /** Caller-owned artifact root. The agent cannot choose the screenshot path. */
  artifactRoot: string;
  headless?: boolean;
  now?: () => Date;
}

export interface NormalizedBrowserEvidencePolicy {
  allowedTopLevelOrigins: readonly string[];
  allowedResourceOrigins: readonly string[];
  timeoutMs: number;
  maxDomChars: number;
  maxInteractiveElements: number;
  fullPageScreenshot: boolean;
}

export interface DomHeadingEvidence {
  level: number;
  text: string;
}

export interface DomInteractiveElement {
  tag: string;
  role: string | null;
  ariaLabel: string | null;
  text: string;
  href: string | null;
  type: string | null;
  name: string | null;
}

export interface DomEvidence {
  title: string;
  textExcerpt: string;
  textTruncated: boolean;
  headings: readonly DomHeadingEvidence[];
  interactiveElements: readonly DomInteractiveElement[];
}

export interface BrowserEvidenceReceipt {
  schemaVersion: "toadaid.browser-evidence.receipt.v1";
  receiptId: string;
  capability: "browser.evidence.capture";
  status: "CAPTURED";
  capturedAt: string;
  request: {
    url: string;
  };
  policy: NormalizedBrowserEvidencePolicy;
  page: {
    requestedUrl: string;
    finalUrl: string;
    httpStatus: number | null;
    title: string;
  };
  screenshot: {
    relativePath: string;
    sha256: string;
    bytes: number;
  };
  dom: DomEvidence;
  network: {
    blockedOrigins: readonly string[];
    blockedWebSocketOrigins: readonly string[];
  };
}
