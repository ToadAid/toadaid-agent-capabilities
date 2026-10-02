import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
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
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";
import type {
  ReplayFenceEnvelope,
  ReplayReconciliationEnvelope,
} from "./replayFenceTypes.js";
import type {
  RunBudgetLedgerEnvelope,
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type HostServiceCapabilityId =
  | "host:app-launch"
  | "host:clipboard-read"
  | "host:clipboard-write"
  | "host:process-read"
  | "host:process-stop"
  | "host:file-read"
  | "host:file-write"
  | "host:notification"
  | "host:registry-read"
  | "host:registry-write"
  | "host:command-exec";

export type HostServiceKind =
  | "APP_LAUNCH"
  | "CLIPBOARD_READ"
  | "CLIPBOARD_WRITE"
  | "PROCESS_READ"
  | "PROCESS_STOP"
  | "FILE_READ"
  | "FILE_WRITE"
  | "NOTIFICATION"
  | "REGISTRY_READ"
  | "REGISTRY_WRITE"
  | "COMMAND_EXEC";

export type HostServiceJsonValue =
  | string
  | number
  | boolean
  | null
  | readonly HostServiceJsonValue[]
  | { readonly [key: string]: HostServiceJsonValue };

export interface HostPathScope {
  readonly root: string;
  readonly path: string;
}

export interface HostEnvironmentBinding {
  readonly name: string;
  readonly valueRef: string;
  readonly valueSha256: string;
}

export type HostRegistryHive = "HKCU" | "HKLM";
export type HostRegistryView =
  | "REGISTRY_32"
  | "REGISTRY_64";

export interface HostRegistryScope {
  readonly hive: HostRegistryHive;
  readonly view: HostRegistryView;
  readonly rootKeyPath: string;
  readonly keyPath: string;
}

export interface HostServiceProviderIdentity {
  readonly providerDescriptorSha256: string;
  readonly providerGenerationSha256: string;
  readonly evidenceNamespace: string;
}

export interface HostProcessReference {
  readonly schemaVersion:
    "toadaid.host-process-reference.v1";
  readonly hostId: string;
  readonly sessionId: string;
  readonly pid: number;
  readonly processRef: string;
  readonly processReadReceiptSha256: string;
  readonly processEvidenceSha256: string;
  readonly providerDescriptorSha256: string;
  readonly providerGenerationSha256: string;
  readonly evidenceNamespace: string;
  readonly observedAt: string;
  readonly referenceSha256: string;
}

export interface HostServiceEvidenceRuntime {
  readonly resolveCurrentProviderIdentity: (
    identity: Readonly<{
      hostId: string;
      sessionId: string;
    }>,
  ) => HostServiceProviderIdentity | null;
  readonly resolveCurrentProcessReference: (
    identity: Readonly<{
      hostId: string;
      sessionId: string;
      processRef: string;
    }>,
  ) => HostProcessReference | null;
}

interface HostServiceBase {
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly maxWallClockMs?: number;
}

export interface HostAppLaunchRequest extends HostServiceBase {
  readonly kind: "APP_LAUNCH";
  readonly executable: string;
  readonly argv?: readonly string[];
  readonly cwd: HostPathScope;
  readonly env?: readonly HostEnvironmentBinding[];
}

export interface HostClipboardReadRequest extends HostServiceBase {
  readonly kind: "CLIPBOARD_READ";
  readonly format: "text/plain";
  readonly maxBytes?: number;
}

export interface HostClipboardWriteRequest extends HostServiceBase {
  readonly kind: "CLIPBOARD_WRITE";
  readonly format: "text/plain";
  readonly contentRef: string;
  readonly contentSha256: string;
  readonly byteLength: number;
  readonly contentClass: "ORDINARY_TEXT";
}

export interface HostProcessReadRequest extends HostServiceBase {
  readonly kind: "PROCESS_READ";
  readonly pid?: number;
  readonly name?: string;
  readonly maxResults?: number;
}

export interface HostProcessStopRequest extends HostServiceBase {
  readonly kind: "PROCESS_STOP";
  readonly process: HostProcessReference;
  readonly maxEvidenceAgeMs?: number;
}

export interface HostFileReadRequest extends HostServiceBase {
  readonly kind: "FILE_READ";
  readonly scope: HostPathScope;
  readonly maxBytes?: number;
}

export interface HostFileWriteRequest extends HostServiceBase {
  readonly kind: "FILE_WRITE";
  readonly scope: HostPathScope;
  readonly contentRef: string;
  readonly contentSha256: string;
  readonly byteLength: number;
  readonly mode: "CREATE_NEW" | "REPLACE_EXISTING";
}

export interface HostNotificationRequest extends HostServiceBase {
  readonly kind: "NOTIFICATION";
  readonly title: string;
  readonly body: string;
  readonly urgency?: "LOW" | "NORMAL" | "HIGH";
}

export interface HostRegistryReadRequest extends HostServiceBase {
  readonly kind: "REGISTRY_READ";
  readonly scope: HostRegistryScope;
  readonly valueName?: string;
}

export interface HostRegistryWriteRequest extends HostServiceBase {
  readonly kind: "REGISTRY_WRITE";
  readonly scope: HostRegistryScope;
  readonly valueName: string;
  readonly valueType: "STRING" | "DWORD" | "QWORD" | "BINARY";
  readonly valueRef: string;
  readonly valueSha256: string;
  readonly byteLength: number;
}

export interface HostCommandExecRequest extends HostServiceBase {
  readonly kind: "COMMAND_EXEC";
  readonly executable: string;
  readonly argv?: readonly string[];
  readonly cwd: HostPathScope;
  readonly env?: readonly HostEnvironmentBinding[];
  readonly stdinRef?: string;
  readonly stdinSha256?: string;
  readonly maxOutputBytes?: number;
}

export type HostServiceRequest =
  | HostAppLaunchRequest
  | HostClipboardReadRequest
  | HostClipboardWriteRequest
  | HostProcessReadRequest
  | HostProcessStopRequest
  | HostFileReadRequest
  | HostFileWriteRequest
  | HostNotificationRequest
  | HostRegistryReadRequest
  | HostRegistryWriteRequest
  | HostCommandExecRequest;

export interface NormalizedHostServiceRequest {
  readonly kind: HostServiceKind;
  readonly capabilityId: HostServiceCapabilityId;
  readonly toolName: string;
  readonly mutation: boolean;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly details: HostServiceJsonValue;
  readonly maxWallClockMs: number;
}

export interface HostServiceAdapterRegistration {
  readonly schemaVersion:
    "toadaid.host-service-adapter-registration.v1";
  readonly adapterId: string;
  readonly capabilityId: HostServiceCapabilityId;
  readonly toolName: string;
  readonly contractId: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface HostServiceAdapterRequest {
  readonly schemaVersion:
    "toadaid.host-service-adapter-request.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly operationId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly capabilityId: HostServiceCapabilityId;
  readonly providerIdentity: HostServiceProviderIdentity;
  readonly toolName: string;
  readonly parametersSha256: string;
  readonly actionParametersSha256: string;
  readonly maxWallClockMs: number;
  readonly parameters: NormalizedHostServiceRequest;
}

export interface HostServiceArtifactReference {
  readonly id: string;
  readonly kind: string;
  readonly sha256: string;
}

export interface HostServiceAdapterResult {
  readonly schemaVersion:
    "toadaid.host-service-adapter-result.v1";
  readonly operationId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly capabilityId: HostServiceCapabilityId;
  readonly evidenceSha256: string;
  readonly payload?: HostServiceJsonValue;
  readonly payloadRef?: string;
  readonly artifacts?: readonly HostServiceArtifactReference[];
}

export interface GovernedHostServiceAdapter {
  readonly registration: HostServiceAdapterRegistration;
  invoke(
    request: HostServiceAdapterRequest,
  ): Promise<HostServiceAdapterResult>;
}

export interface HostServiceRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export interface GovernedHostServiceInput {
  readonly lease: HostConnectorSessionLeaseEnvelope;
  readonly leaseRuntime: HostConnectorSessionUseRuntime;
  readonly evidenceRuntime: HostServiceEvidenceRuntime;
  readonly sessionAuthority: CapabilityAuthorityDecision;
  readonly actionAuthority: CapabilityAuthorityDecision;
  readonly invocation: CapabilityInvocationEnvelope;
  readonly contractBinding: CapabilityInvocationContractBinding;
  readonly contractReady: CapabilityInvocationContractReadyReceipt;
  readonly contractRequirement: CapabilityContractRequirement;
  readonly contractRegistry: CapabilityContractRegistry;
  readonly replayFence?: ReplayFenceEnvelope;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly request: HostServiceRequest;
}

export type HostServiceStatus =
  | "OK"
  | "DEGRADED"
  | "RECONCILIATION_REQUIRED";

export interface HostServiceReceipt {
  readonly schemaVersion: "toadaid.host-service-receipt.v1";
  readonly status: HostServiceStatus;
  readonly capabilityId: HostServiceCapabilityId;
  readonly invocationId: string;
  readonly intentSha256: string;
  readonly runId: string;
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly providerDescriptorSha256: string;
  readonly providerGenerationSha256: string;
  readonly evidenceNamespace: string;
  readonly leaseSha256: string;
  readonly contractBindingSha256: string;
  readonly descriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly replayFenceSha256: string | null;
  readonly operationId: string;
  readonly parametersSha256: string;
  readonly actionParametersSha256: string;
  readonly invokedAt: string;
  readonly resultEvidenceSha256: string | null;
  readonly payloadSha256: string | null;
  readonly payloadRefSha256: string | null;
  readonly artifactSetSha256: string | null;
  readonly reconciliationSha256: string | null;
  readonly budget: {
    readonly ledgerSha256Before: string;
    readonly ledgerSha256After: string;
    readonly reservedCost: RunBudgetVector;
  };
  readonly errorClass: string | null;
  readonly errorFingerprint: string | null;
  readonly receiptSha256: string;
}

export interface GovernedHostServiceOutcome {
  readonly receipt: HostServiceReceipt;
  readonly budget: RunBudgetLedgerEnvelope;
  readonly result: HostServiceAdapterResult | null;
  readonly reconciliation: ReplayReconciliationEnvelope | null;
}
