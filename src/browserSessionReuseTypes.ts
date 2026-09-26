import type {
  BrowserSessionAuthorityBundle,
  BrowserSessionLeaseEnvelope,
  BrowserSessionRuntime,
  BrowserSessionUseRequest,
} from "./browserSessionLease.js";

export type ReusableBrowserSessionMode =
  | "ONE_SHOT_ANONYMOUS"
  | "PERSISTENT_AUTHENTICATED";

export type ReusableBrowserResourceType =
  | "document"
  | "stylesheet"
  | "image"
  | "font"
  | "script"
  | "xhr"
  | "fetch"
  | "media";

export interface ReusableBrowserHeader {
  readonly name: string;
  readonly value: string;
}

export interface ReusableBrowserRequestPolicy {
  readonly timeoutMs?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly allowedResourceOrigins?: readonly string[];
  readonly allowedResourceTypes?: readonly ReusableBrowserResourceType[];
  readonly allowPrivateNetwork?: boolean;
}

export interface NormalizedReusableBrowserRequestPolicy {
  readonly timeoutMs: number;
  readonly headers: readonly ReusableBrowserHeader[];
  readonly allowedTopLevelOrigins: readonly string[];
  readonly allowedResourceOrigins: readonly string[];
  readonly allowedResourceTypes: readonly ReusableBrowserResourceType[];
  readonly allowPrivateNetwork: boolean;
  readonly allowedHttpMethods: readonly ["GET", "HEAD"];
  readonly allowWebSockets: false;
}

export interface ReusableBrowserPoolCandidate {
  readonly schemaVersion: "toadaid.reusable-browser-pool-candidate.v1";
  readonly sessionId: string;
  readonly origin: string;
  readonly leaseSha256: string;
  readonly reuseKey: string;
  readonly lastSettingsSha256: string;
  readonly sourcePreparationReceiptSha256: string;
  readonly status: "READY";
  readonly candidateSha256: string;
}

export interface PrepareReusableBrowserRequestInput {
  readonly lease: BrowserSessionLeaseEnvelope;
  readonly use: BrowserSessionUseRequest;
  readonly authority: BrowserSessionAuthorityBundle;
  readonly mode: ReusableBrowserSessionMode;
  readonly policy?: ReusableBrowserRequestPolicy;
  readonly candidate?: ReusableBrowserPoolCandidate;
}

export interface ReusableBrowserRuntimeIdentity {
  readonly sessionId: string;
  readonly origin: string;
  readonly leaseSha256: string;
  readonly mode: ReusableBrowserSessionMode;
  readonly reuseKey: string | null;
  readonly sourceCandidateSha256: string | null;
}

export interface ReusableBrowserCandidateClaimReceipt {
  readonly schemaVersion: "toadaid.reusable-browser-candidate-claim-receipt.v1";
  readonly candidateSha256: string;
  readonly disposition: "CLAIMED" | "ALREADY_CLAIMED";
}

export interface ReusableBrowserResetReceipt {
  readonly schemaVersion: "toadaid.reusable-browser-reset-receipt.v1";
  readonly resetComplete: true;
}

export interface ReusableBrowserPolicyApplyReceipt {
  readonly schemaVersion: "toadaid.reusable-browser-policy-apply-receipt.v1";
  readonly appliedSettingsSha256: string;
}

export interface ReusableBrowserRuntimeAdapter {
  claimPoolCandidate(
    input: Readonly<{
      identity: ReusableBrowserRuntimeIdentity;
      candidateSha256: string;
    }>,
  ): Promise<ReusableBrowserCandidateClaimReceipt>;
  resetRequestState(
    identity: ReusableBrowserRuntimeIdentity,
  ): Promise<ReusableBrowserResetReceipt>;
  applyRequestState(
    input: Readonly<{
      identity: ReusableBrowserRuntimeIdentity;
      settings: NormalizedReusableBrowserRequestPolicy;
      settingsSha256: string;
    }>,
  ): Promise<ReusableBrowserPolicyApplyReceipt>;
  quarantineAndEvict(
    input: Readonly<{
      identity: ReusableBrowserRuntimeIdentity;
      reason: string;
    }>,
  ): Promise<void>;
  disposeOneShot(
    input: Readonly<{
      identity: ReusableBrowserRuntimeIdentity;
      reason: string;
    }>,
  ): Promise<void>;
}

export interface ReusableBrowserPreparationReceipt {
  readonly schemaVersion: "toadaid.reusable-browser-preparation-receipt.v1";
  readonly sessionId: string;
  readonly origin: string;
  readonly mode: ReusableBrowserSessionMode;
  readonly leaseSha256: string;
  readonly reuseKey: string | null;
  readonly sourceCandidateSha256: string | null;
  readonly settingsSha256: string;
  readonly checkout: "FRESH" | "REUSED";
  readonly preparedAt: string;
  readonly receiptSha256: string;
}

export type ReusableBrowserExecutionStatus = "SUCCESS" | "ERROR";
export type ReusableBrowserPageHealth = "HEALTHY" | "POISONED";

export interface ReusableBrowserExecutionOutcome {
  readonly status: ReusableBrowserExecutionStatus;
  readonly pageHealth: ReusableBrowserPageHealth;
}

export type ReusableBrowserDisposition =
  | "RETURN_TO_POOL"
  | "QUARANTINE_EVICT"
  | "DISPOSE";

export type ReusableBrowserDispositionReason =
  | "SUCCESS_HEALTHY"
  | "ONE_SHOT_COMPLETE"
  | "EXECUTION_ERROR"
  | "POISONED_PAGE"
  | "AUTHORITY_OR_LEASE_CHANGED";

export interface ReusableBrowserDispositionReceipt {
  readonly schemaVersion: "toadaid.reusable-browser-disposition-receipt.v1";
  readonly preparationReceiptSha256: string;
  readonly disposition: ReusableBrowserDisposition;
  readonly reason: ReusableBrowserDispositionReason;
  readonly candidate: ReusableBrowserPoolCandidate | null;
  readonly finalizedAt: string;
}

export interface FinalizeReusableBrowserRequestInput {
  readonly preparation: ReusableBrowserPreparationReceipt;
  readonly lease: BrowserSessionLeaseEnvelope;
  readonly use: BrowserSessionUseRequest;
  readonly authority: BrowserSessionAuthorityBundle;
  readonly outcome: ReusableBrowserExecutionOutcome;
}

export type ReusableBrowserRuntime = BrowserSessionRuntime;
