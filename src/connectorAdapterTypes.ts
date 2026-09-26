import type {
  CapabilityContractRegistry,
  CapabilityContractRequirement,
  CapabilityInvocationContractBinding,
  CapabilityInvocationContractReadyReceipt,
} from "./capabilityContractTypes.js";
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";

export type ConnectorJsonPrimitive = null | boolean | number | string;

export interface ConnectorJsonObject {
  readonly [key: string]: ConnectorJsonValue;
}

export type ConnectorJsonValue =
  | ConnectorJsonPrimitive
  | readonly ConnectorJsonValue[]
  | ConnectorJsonObject;

export interface ConnectorAdapterRegistration {
  readonly schemaVersion: "toadaid.connector-adapter-registration.v1";
  readonly adapterId: string;
  readonly capabilityId: string;
  readonly toolName: string;
  readonly contractId: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
}

export interface ConnectorAdapterInvocationRequest {
  readonly schemaVersion: "toadaid.connector-adapter-invocation.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly capabilityId: string;
  readonly toolName: string;
  readonly intentSha256: string;
  readonly argumentsSha256: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly registrationSha256: string;
  readonly arguments: ConnectorJsonValue;
}

export interface GovernedConnectorAdapter {
  readonly registration: ConnectorAdapterRegistration;
  invoke(
    request: ConnectorAdapterInvocationRequest,
  ): ConnectorJsonValue | Promise<ConnectorJsonValue>;
}

export interface ConnectorAdapterInvocationReceipt {
  readonly schemaVersion: "toadaid.connector-adapter-receipt.v1";
  readonly invocationId: string;
  readonly runId: string;
  readonly capabilityId: string;
  readonly toolName: string;
  readonly adapterId: string;
  readonly bindingSha256: string;
  readonly descriptorSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly registrationSha256: string;
  readonly requestSha256: string;
  readonly resultSha256: string;
}

export interface ConnectorAdapterInvocationResult {
  readonly result: ConnectorJsonValue;
  readonly receipt: ConnectorAdapterInvocationReceipt;
}

export interface GovernedConnectorInvocationInput {
  readonly invocation: CapabilityInvocationEnvelope;
  readonly contractBinding: CapabilityInvocationContractBinding;
  readonly contractReady: CapabilityInvocationContractReadyReceipt;
  readonly contractRequirement: CapabilityContractRequirement;
  readonly contractRegistry: CapabilityContractRegistry;
  readonly arguments: ConnectorJsonValue;
}
