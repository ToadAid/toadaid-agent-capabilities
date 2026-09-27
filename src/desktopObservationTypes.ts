import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import type {
  CapabilityContractRegistry,
  CapabilityContractRequirement,
  CapabilityInvocationContractBinding,
  CapabilityInvocationContractReadyReceipt,
} from "./capabilityContractTypes.js";
import type {
  HostConnectorSessionLeaseEnvelope,
  HostConnectorSessionUseRuntime,
} from "./hostConnectorSessionLeaseTypes.js";
import type {
  CapabilityInvocationEnvelope,
} from "./invocationTypes.js";
import type {
  RunBudgetLedgerEnvelope,
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type DesktopObservationCapabilityId =
  | "host:display-inventory"
  | "host:screenshot"
  | "host:ui-snapshot"
  | "host:wait-for";

export type DesktopObservationKind =
  | "DISPLAY_INVENTORY"
  | "SCREENSHOT"
  | "UI_SNAPSHOT"
  | "WAIT_FOR";

export type DesktopWaitForCondition =
  | "text_exists"
  | "active_window"
  | "element_exists"
  | "element_enabled"
  | "focused_element";

export interface DesktopObservationRegion {
  readonly left: number;
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
}

export interface DesktopObservationScope {
  readonly displayIds?: readonly number[];
  readonly region?: DesktopObservationRegion;
}

export interface DesktopDisplayInventoryRequest {
  readonly kind: "DISPLAY_INVENTORY";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly maxWallClockMs?: number;
}

export interface DesktopScreenshotRequest {
  readonly kind: "SCREENSHOT";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly scope: DesktopObservationScope;
  readonly annotate?: boolean;
  readonly maxWallClockMs?: number;
}

export interface DesktopUiSnapshotRequest {
  readonly kind: "UI_SNAPSHOT";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly scope?: DesktopObservationScope;
  readonly windowId?: string;
  readonly includeScreenshot?: boolean;
  readonly useDom?: boolean;
  readonly maxElements?: number;
  readonly maxWallClockMs?: number;
}

export interface DesktopWaitForRequest {
  readonly kind: "WAIT_FOR";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly windowId: string;
  readonly condition: DesktopWaitForCondition;
  readonly text?: string;
  readonly timeoutMs?: number;
  readonly intervalMs?: number;
  readonly useDom?: boolean;
}

export type DesktopObservationRequest =
  | DesktopDisplayInventoryRequest
  | DesktopScreenshotRequest
  | DesktopUiSnapshotRequest
  | DesktopWaitForRequest;

export interface NormalizedDesktopObservationRequest {
  readonly kind: DesktopObservationKind;
  readonly capabilityId: DesktopObservationCapabilityId;
  readonly toolName: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly displayIds: readonly number[];
  readonly region: DesktopObservationRegion | null;
  readonly windowId: string | null;
  readonly annotate: boolean;
  readonly includeScreenshot: boolean;
  readonly useDom: boolean;
  readonly maxElements: number;
  readonly condition: DesktopWaitForCondition | null;
  readonly text: string | null;
  readonly timeoutMs: number;
  readonly intervalMs: number;
  readonly maxWallClockMs: number;
}

export type DesktopObservationArtifactKind =
  | "DISPLAY_INVENTORY"
  | "SCREENSHOT"
  | "UI_TREE"
  | "DOM"
  | "WAIT_RESULT";

export interface DesktopObservationArtifactReference {
  readonly id: string;
  readonly kind: DesktopObservationArtifactKind;
  readonly sha256: string;
}

export interface DesktopObservationElementEvidence {
  readonly elementId: string;
  readonly evidenceSha256: string;
}

export interface DesktopObservedElementReference {
  readonly schemaVersion:
    "toadaid.desktop-observed-element-ref.v1";
  readonly elementId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly windowId: string;
  readonly observationEpoch: string;
  readonly observationEvidenceSha256: string;
  readonly elementEvidenceSha256: string;
}

export interface DesktopObservationAdapterRegistration {
  readonly schemaVersion:
    "toadaid.desktop-observation-adapter-registration.v1";
  readonly adapterId: string;
  readonly capabilityId: DesktopObservationCapabilityId;
  readonly toolName: string;
  readonly contractId: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface DesktopObservationAdapterRequest {
  readonly schemaVersion:
    "toadaid.desktop-observation-adapter-request.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly capabilityId: DesktopObservationCapabilityId;
  readonly toolName: string;
  readonly observationEpoch: string;
  readonly parametersSha256: string;
  readonly maxWallClockMs: number;
  readonly parameters: NormalizedDesktopObservationRequest;
}

export interface DesktopObservationAdapterResult {
  readonly schemaVersion:
    "toadaid.desktop-observation-adapter-result.v1";
  readonly observationEpoch: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly displayIds: readonly number[];
  readonly windowId: string | null;
  readonly evidenceSha256: string;
  readonly artifacts: readonly DesktopObservationArtifactReference[];
  readonly elements?: readonly DesktopObservationElementEvidence[];
  readonly matched?: boolean;
}

export interface GovernedDesktopObservationAdapter {
  readonly registration: DesktopObservationAdapterRegistration;
  observe(
    request: DesktopObservationAdapterRequest,
  ): Promise<DesktopObservationAdapterResult>;
}

export type DesktopObservationHeadStatus =
  | "PENDING"
  | "OK"
  | "DEGRADED";

export interface DesktopObservationHead {
  readonly schemaVersion:
    "toadaid.desktop-observation-head.v1";
  readonly hostId: string;
  readonly sessionId: string;
  readonly windowId: string;
  readonly observationEpoch: string;
  readonly status: DesktopObservationHeadStatus;
  readonly evidenceSha256: string | null;
  readonly receiptSha256: string | null;
}

export interface DesktopObservationHeadRuntime {
  publishCurrentObservationHead(
    head: DesktopObservationHead,
  ): void;
  resolveCurrentObservationHead(
    identity: Readonly<{
      hostId: string;
      sessionId: string;
      windowId: string;
    }>,
  ): DesktopObservationHead | null;
}

export interface DesktopObservationRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export interface GovernedDesktopObservationInput {
  readonly lease: HostConnectorSessionLeaseEnvelope;
  readonly leaseRuntime: HostConnectorSessionUseRuntime;
  readonly observationHeadRuntime: DesktopObservationHeadRuntime;
  readonly sessionAuthority: CapabilityAuthorityDecision;
  readonly actionAuthority: CapabilityAuthorityDecision;
  readonly invocation: CapabilityInvocationEnvelope;
  readonly contractBinding: CapabilityInvocationContractBinding;
  readonly contractReady: CapabilityInvocationContractReadyReceipt;
  readonly contractRequirement: CapabilityContractRequirement;
  readonly contractRegistry: CapabilityContractRegistry;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly request: DesktopObservationRequest;
}

export type DesktopObservationStatus =
  | "OK"
  | "DEGRADED";

export type DesktopObservationDegradedReason =
  | "ADAPTER_ERROR"
  | "ADAPTER_RESULT_INVALID";

export interface DesktopObservationBudgetEvidence {
  readonly ledgerSha256Before: string;
  readonly ledgerSha256After: string;
  readonly reservedCost: RunBudgetVector;
}

export interface DesktopObservationReceipt {
  readonly schemaVersion:
    "toadaid.desktop-observation-receipt.v1";
  readonly status: DesktopObservationStatus;
  readonly capabilityId: DesktopObservationCapabilityId;
  readonly invocationId: string;
  readonly runId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly leaseSha256: string;
  readonly contractBindingSha256: string;
  readonly descriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly observationEpoch: string;
  readonly parametersSha256: string;
  readonly observedAt: string;
  readonly displayIds: readonly number[];
  readonly windowId: string | null;
  readonly evidenceSha256: string | null;
  readonly artifacts:
    readonly DesktopObservationArtifactReference[];
  readonly elements:
    readonly DesktopObservedElementReference[];
  readonly budget: DesktopObservationBudgetEvidence;
  readonly degradedReason: DesktopObservationDegradedReason | null;
  readonly errorClass: string | null;
  readonly errorFingerprint: string | null;
  readonly receiptSha256: string;
}

export interface GovernedDesktopObservationOutcome {
  readonly receipt: DesktopObservationReceipt;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly result: DesktopObservationAdapterResult | null;
}
