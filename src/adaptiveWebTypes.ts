import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";

export type AdaptiveWebCapabilityId =
  | "web:extract"
  | "web:adaptive-locate"
  | "web:crawl"
  | "web:xhr-capture"
  | "web:stealth-fetch";

export type AdaptiveWebFetchMode = "HTTP" | "BROWSER" | "STEALTH";
export type ExtractionSelectorKind = "CSS" | "XPATH";
export type ExtractionValueKind = "TEXT" | "HTML" | "ATTRIBUTE";
export type XhrBodyMode = "HASH_ONLY" | "BOUNDED_TEXT";
export type AdaptiveMatchDecision = "MATCH" | "AMBIGUOUS" | "NO_MATCH";
export type WorkerOperation = "EXTRACT" | "CANDIDATES" | "XHR_CAPTURE";

export interface ExtractionFieldSpec {
  name: string;
  selectorKind: ExtractionSelectorKind;
  selector: string;
  valueKind: ExtractionValueKind;
  attribute?: string;
  multiple?: boolean;
  maxItems?: number;
}

export interface AdaptiveElementFingerprint {
  id: string;
  tag: string;
  text: string;
  attributes: Readonly<Record<string, string>>;
  parent: {
    tag: string | null;
    text: string;
    attributes: Readonly<Record<string, string>>;
  };
  siblingTags: readonly string[];
  pathTags: readonly string[];
}

export interface AdaptiveCandidateScore {
  candidateId: string;
  score: number;
}

export interface AdaptiveLocateResult {
  schemaVersion: "toadaid.adaptive-locate-result.v1";
  decision: AdaptiveMatchDecision;
  selectedCandidateId: string | null;
  confidence: number;
  threshold: number;
  ambiguityMargin: number;
  candidates: readonly AdaptiveCandidateScore[];
}

export interface AdaptiveWebPolicy {
  allowedTopLevelOrigins: readonly string[];
  allowedResourceOrigins?: readonly string[];
  allowPrivateNetwork?: boolean;
  maxResponseBytes?: number;
  maxExtractedItems?: number;
  maxValueChars?: number;
  adaptiveMinimumConfidence?: number;
  adaptiveAmbiguityMargin?: number;
  crawl?: Partial<CrawlPolicy>;
}

export interface NormalizedAdaptiveWebPolicy {
  allowedTopLevelOrigins: readonly string[];
  allowedResourceOrigins: readonly string[];
  allowPrivateNetwork: boolean;
  maxResponseBytes: number;
  maxExtractedItems: number;
  maxValueChars: number;
  adaptiveMinimumConfidence: number;
  adaptiveAmbiguityMargin: number;
  crawl: CrawlPolicy;
}

export interface CrawlPolicy {
  maxUrls: number;
  maxDepth: number;
  maxConcurrency: number;
  perOriginMaxRequests: number;
  minDelayMs: number;
  maxDelayMs: number;
  targetLatencyMs: number;
  backoffFactor: number;
}

export type AdaptiveWebIntent =
  | {
      kind: "extract";
      url: string;
      fields: readonly ExtractionFieldSpec[];
      fetchMode?: AdaptiveWebFetchMode;
    }
  | {
      kind: "adaptive-locate";
      url: string;
      selectorKind: ExtractionSelectorKind;
      candidateSelector: string;
      maxCandidates?: number;
      fetchMode?: AdaptiveWebFetchMode;
    }
  | {
      kind: "xhr-capture";
      url: string;
      pattern: string;
      bodyMode?: XhrBodyMode;
      fetchMode?: "BROWSER" | "STEALTH";
    };

export interface AdaptiveWebAuthorityBundle {
  extract?: CapabilityAuthorityDecision;
  adaptiveLocate?: CapabilityAuthorityDecision;
  crawl?: CapabilityAuthorityDecision;
  xhrCapture?: CapabilityAuthorityDecision;
  stealthFetch?: CapabilityAuthorityDecision;
}

export interface ScraplingWorkerRequest {
  schemaVersion: "toadaid.scrapling-worker.request.v1";
  requestId: string;
  operation: WorkerOperation;
  capability: Exclude<AdaptiveWebCapabilityId, "web:stealth-fetch">;
  url: string;
  fetchMode: AdaptiveWebFetchMode;
  policy: {
    allowedTopLevelOrigins: readonly string[];
    allowedResourceOrigins: readonly string[];
    allowPrivateNetwork: boolean;
    maxResponseBytes: number;
    maxExtractedItems: number;
    maxValueChars: number;
  };
  fields?: readonly ExtractionFieldSpec[];
  candidateSelector?: {
    selectorKind: ExtractionSelectorKind;
    selector: string;
    maxCandidates: number;
  };
  xhr?: {
    pattern: string;
    bodyMode: XhrBodyMode;
  };
}

export interface WorkerResolvedAddress {
  host: string;
  address: string;
}

export interface XhrEvidence {
  url: string;
  status: number;
  bytes: number;
  sha256: string;
  contentType: string | null;
  textExcerpt?: string;
  textTruncated?: boolean;
}

export interface ScraplingWorkerResponse {
  schemaVersion: "toadaid.scrapling-worker.response.v1";
  requestId: string;
  operation: WorkerOperation;
  status: "OK";
  requestedUrl: string;
  finalUrl: string;
  httpStatus: number;
  responseBytes: number;
  responseSha256: string;
  resolvedAddresses: readonly WorkerResolvedAddress[];
  extracted?: Readonly<Record<string, readonly string[]>>;
  candidates?: readonly AdaptiveElementFingerprint[];
  xhr?: readonly XhrEvidence[];
}

export interface CrawlQueueEntry {
  url: string;
  depth: number;
}

export interface CrawlOriginState {
  origin: string;
  requests: number;
  nextDelayMs: number;
}

export interface CrawlContinuityBinding {
  runId: string;
  runCapsuleSha256: string;
  childTaskId: string | null;
  childTaskSha256: string | null;
}

export interface CrawlCheckpoint {
  schemaVersion: "toadaid.web-crawl-checkpoint.v1";
  crawlId: string;
  ownerId: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  continuity: CrawlContinuityBinding;
  pending: readonly CrawlQueueEntry[];
  seenUrls: readonly string[];
  origins: readonly CrawlOriginState[];
  previousCheckpointSha256: string | null;
}

export interface CrawlCheckpointEnvelope {
  schemaVersion: "toadaid.web-crawl-checkpoint-envelope.v1";
  checkpoint: CrawlCheckpoint;
  checkpointSha256: string;
}

export interface CreateCrawlCheckpointInput {
  crawlId?: string;
  ownerId: string;
  createdAt: string;
  seedUrls: readonly string[];
  continuity: CrawlContinuityBinding;
}

export interface CrawlWorkerRequestInput {
  entry: CrawlQueueEntry;
  fields: readonly ExtractionFieldSpec[];
  fetchMode?: AdaptiveWebFetchMode;
}

export interface CrawlStepResult {
  url: string;
  depth: number;
  completedAt: string;
  httpStatus: number;
  latencyMs: number;
  blocked: boolean;
  discoveredUrls: readonly string[];
}

export interface CrawlResumeBinding {
  runId: string;
  runCapsuleSha256: string;
  childTaskId?: string | null;
  childTaskSha256?: string | null;
}
