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

export interface BrowserNetworkEvidence {
  blockedOrigins: readonly string[];
  blockedWebSocketOrigins: readonly string[];
  blockedHttpMethods: readonly string[];
}

export interface BrowserScreenshotEvidence {
  relativePath: string;
  sha256: string;
  bytes: number;
}

export interface BrowserEvidenceReceipt {
  schemaVersion: "toadaid.browser-evidence.receipt.v1";
  receiptId: string;
  capability: "browser.evidence.capture";
  status: "CAPTURED";
  capturedAt: string;
  request: {
    /** Persisted URL omits query and fragment. */
    url: string;
  };
  policy: NormalizedBrowserEvidencePolicy;
  page: {
    requestedUrl: string;
    finalUrl: string;
    httpStatus: number | null;
    title: string;
  };
  screenshot: BrowserScreenshotEvidence;
  dom: DomEvidence;
  network: BrowserNetworkEvidence;
}

export type BrowserInteractionActionKind = "navigate" | "click" | "type";

export type BrowserInteractionTarget =
  | { by: "css"; value: string }
  | { by: "text"; value: string; exact?: boolean }
  | { by: "label"; value: string; exact?: boolean };

export type BrowserInteractionAction =
  | { kind: "navigate"; url: string }
  | { kind: "click"; target: BrowserInteractionTarget }
  | { kind: "type"; target: BrowserInteractionTarget; text: string };

export interface BrowserInteractionRequest {
  /** Initial agent-requested page. Authority still comes from policy. */
  url: string;
  /** Ordered bounded interaction intent. */
  actions: readonly BrowserInteractionAction[];
}

export interface BrowserInteractionPolicy extends BrowserEvidencePolicy {
  /** Action kinds the runtime/operator authorizes for this invocation. */
  allowedActionKinds: readonly BrowserInteractionActionKind[];
  maxActions?: number;
  maxTargetChars?: number;
  maxTypeChars?: number;
  actionTimeoutMs?: number;
}

export type BrowserInteractionRuntime = BrowserEvidenceRuntime;

export interface NormalizedBrowserInteractionPolicy extends NormalizedBrowserEvidencePolicy {
  allowedActionKinds: readonly BrowserInteractionActionKind[];
  maxActions: number;
  maxTargetChars: number;
  maxTypeChars: number;
  actionTimeoutMs: number;
}

export interface BrowserInteractionActionReceipt {
  index: number;
  kind: BrowserInteractionActionKind;
  status: "APPLIED";
  /** Target description is not persisted; this proves which target intent was used without storing it. */
  target?: {
    by: BrowserInteractionTarget["by"];
    sha256: string;
  };
  /** Typed text is not copied into structured action metadata. */
  typedCharacters?: number;
  /** Persisted URL omits query and fragment. */
  navigatedTo?: string;
}

export interface BrowserInteractionReceipt {
  schemaVersion: "toadaid.browser-interaction.receipt.v1";
  receiptId: string;
  capability: "browser.interaction.execute";
  status: "COMPLETED";
  startedAt: string;
  completedAt: string;
  request: {
    url: string;
    actionCount: number;
  };
  policy: NormalizedBrowserInteractionPolicy;
  actions: readonly BrowserInteractionActionReceipt[];
  page: {
    finalUrl: string;
    title: string;
  };
  screenshot: BrowserScreenshotEvidence;
  dom: DomEvidence;
  network: BrowserNetworkEvidence;
}
