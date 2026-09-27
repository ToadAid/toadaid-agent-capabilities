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
  DesktopObservationHeadRuntime,
  DesktopObservationReceipt,
  DesktopObservationRequest,
  DesktopObservedElementReference,
} from "./desktopObservationTypes.js";
import type {
  HostConnectorSessionLeaseEnvelope,
  HostConnectorSessionUseRuntime,
} from "./hostConnectorSessionLeaseTypes.js";
import type {
  CapabilityInvocationEnvelope,
} from "./invocationTypes.js";
import type {
  ReplayFenceEnvelope,
  ReplayReconciliationEnvelope,
} from "./replayFenceTypes.js";
import type {
  RunBudgetLedgerEnvelope,
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type DesktopInteractionCapabilityId =
  | "host:pointer-click"
  | "host:pointer-move"
  | "host:scroll"
  | "host:text-input"
  | "host:shortcut";

export type DesktopInteractionKind =
  | "POINTER_CLICK"
  | "POINTER_MOVE"
  | "SCROLL"
  | "TEXT_INPUT"
  | "SHORTCUT";

export interface DesktopInteractionObservationBinding {
  readonly receiptSha256: string;
  readonly observationEpoch: string;
  readonly evidenceSha256: string;
  readonly windowId: string;
}

export interface DesktopElementTarget {
  readonly kind: "ELEMENT";
  readonly element: DesktopObservedElementReference;
}

export interface DesktopCoordinateTarget {
  readonly kind: "COORDINATE";
  readonly displayId?: number;
  readonly x: number;
  readonly y: number;
}

export type DesktopPointerTarget =
  | DesktopElementTarget
  | DesktopCoordinateTarget;

export interface DesktopPointerClickRequest {
  readonly kind: "POINTER_CLICK";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly target: DesktopPointerTarget;
  readonly button?: "LEFT" | "RIGHT" | "MIDDLE";
  readonly clickCount?: number;
  readonly maxObservationAgeMs?: number;
  readonly maxWallClockMs?: number;
}

export interface DesktopPointerMoveRequest {
  readonly kind: "POINTER_MOVE";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly target: DesktopPointerTarget;
  readonly maxObservationAgeMs?: number;
  readonly maxWallClockMs?: number;
}

export interface DesktopScrollRequest {
  readonly kind: "SCROLL";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly deltaX: number;
  readonly deltaY: number;
  readonly maxObservationAgeMs?: number;
  readonly maxWallClockMs?: number;
}

export interface DesktopTextInputRequest {
  readonly kind: "TEXT_INPUT";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly target: DesktopElementTarget;
  readonly text: string;
  readonly contentClass: "ORDINARY_TEXT";
  readonly replace?: boolean;
  readonly maxObservationAgeMs?: number;
  readonly maxWallClockMs?: number;
}

export interface DesktopShortcutRequest {
  readonly kind: "SHORTCUT";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly keys: readonly string[];
  readonly maxObservationAgeMs?: number;
  readonly maxWallClockMs?: number;
}

export type DesktopInteractionRequest =
  | DesktopPointerClickRequest
  | DesktopPointerMoveRequest
  | DesktopScrollRequest
  | DesktopTextInputRequest
  | DesktopShortcutRequest;

export interface NormalizedDesktopElementTarget {
  readonly kind: "ELEMENT";
  readonly element: DesktopObservedElementReference;
}

export interface NormalizedDesktopCoordinateTarget {
  readonly kind: "COORDINATE";
  readonly displayId: number | null;
  readonly x: number;
  readonly y: number;
}

export type NormalizedDesktopPointerTarget =
  | NormalizedDesktopElementTarget
  | NormalizedDesktopCoordinateTarget;

export interface NormalizedDesktopInteractionRequest {
  readonly kind: DesktopInteractionKind;
  readonly capabilityId: DesktopInteractionCapabilityId;
  readonly toolName: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly observation: DesktopInteractionObservationBinding;
  readonly target: NormalizedDesktopPointerTarget | null;
  readonly button: "LEFT" | "RIGHT" | "MIDDLE" | null;
  readonly clickCount: number;
  readonly deltaX: number;
  readonly deltaY: number;
  readonly text: string | null;
  readonly contentClass: "ORDINARY_TEXT" | null;
  readonly replace: boolean;
  readonly keys: readonly string[];
  readonly maxObservationAgeMs: number;
  readonly maxWallClockMs: number;
}

export interface DesktopInteractionAdapterRegistration {
  readonly schemaVersion:
    "toadaid.desktop-interaction-adapter-registration.v1";
  readonly adapterId: string;
  readonly capabilityId: DesktopInteractionCapabilityId;
  readonly toolName: string;
  readonly contractId: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface DesktopInteractionAdapterRequest {
  readonly schemaVersion:
    "toadaid.desktop-interaction-adapter-request.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly windowId: string;
  readonly capabilityId: DesktopInteractionCapabilityId;
  readonly toolName: string;
  readonly interactionEpoch: string;
  readonly parametersSha256: string;
  readonly targetEvidenceSha256: string;
  readonly maxWallClockMs: number;
  readonly parameters: NormalizedDesktopInteractionRequest;
}

export interface DesktopInteractionObservationReference {
  readonly observationEpoch: string;
  readonly evidenceSha256: string;
  readonly receiptSha256: string;
}

export interface DesktopInteractionAdapterResult {
  readonly schemaVersion:
    "toadaid.desktop-interaction-adapter-result.v1";
  readonly interactionEpoch: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly windowId: string;
  readonly evidenceSha256: string;
  readonly resultingObservation?:
    DesktopInteractionObservationReference | null;
}

export interface GovernedDesktopInteractionAdapter {
  readonly registration: DesktopInteractionAdapterRegistration;
  interact(
    request: DesktopInteractionAdapterRequest,
  ): Promise<DesktopInteractionAdapterResult>;
}

export interface DesktopInteractionRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export interface GovernedDesktopInteractionInput {
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
  readonly replayFence: ReplayFenceEnvelope;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly observationRequest: DesktopObservationRequest;
  readonly observationReceipt: DesktopObservationReceipt;
  readonly request: DesktopInteractionRequest;
}

export type DesktopInteractionStatus =
  | "OK"
  | "RECONCILIATION_REQUIRED";

export interface DesktopInteractionBudgetEvidence {
  readonly ledgerSha256Before: string;
  readonly ledgerSha256After: string;
  readonly reservedCost: RunBudgetVector;
}

export interface DesktopInteractionReceipt {
  readonly schemaVersion:
    "toadaid.desktop-interaction-receipt.v1";
  readonly status: DesktopInteractionStatus;
  readonly capabilityId: DesktopInteractionCapabilityId;
  readonly invocationId: string;
  readonly intentSha256: string;
  readonly runId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly windowId: string;
  readonly leaseSha256: string;
  readonly contractBindingSha256: string;
  readonly descriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly replayFenceSha256: string;
  readonly interactionEpoch: string;
  readonly observationReceiptSha256: string;
  readonly targetEvidenceSha256: string;
  readonly parametersSha256: string;
  readonly actionParametersSha256: string;
  readonly dispatchedAt: string;
  readonly resultEvidenceSha256: string | null;
  readonly resultingObservation:
    DesktopInteractionObservationReference | null;
  readonly reconciliationSha256: string | null;
  readonly budget: DesktopInteractionBudgetEvidence;
  readonly errorClass: string | null;
  readonly errorFingerprint: string | null;
  readonly receiptSha256: string;
}

export interface GovernedDesktopInteractionOutcome {
  readonly receipt: DesktopInteractionReceipt;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly result: DesktopInteractionAdapterResult | null;
  readonly reconciliation: ReplayReconciliationEnvelope | null;
}
