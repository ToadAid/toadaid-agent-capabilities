import type {
  ConnectorAdapterInvocationResult,
  GovernedConnectorAdapter,
  GovernedConnectorInvocationInput,
} from "./connectorAdapterTypes.js";
import type {
  CapabilityInvocationEnvelope,
  CapabilityInvocationHeadRuntime,
} from "./invocationTypes.js";
import type {
  ReplayFenceEnvelope,
  ReplayFenceRuntime,
  ReplayReconciliationEnvelope,
} from "./replayFenceTypes.js";

export interface GovernedConnectorExecutionInput
  extends GovernedConnectorInvocationInput {
  readonly invocationHeadRuntime: CapabilityInvocationHeadRuntime;
  readonly replayFence: ReplayFenceEnvelope;
  readonly reconciliationId?: string;
  readonly openedAt?: string;
}

export interface ConnectorExecutionSuccess {
  readonly schemaVersion: "toadaid.connector-execution-outcome.v1";
  readonly status: "SUCCEEDED";
  readonly replayFenceSha256: string;
  readonly invocationRecordSha256: string;
  readonly invocation: CapabilityInvocationEnvelope;
  readonly adapterReceiptSha256: string;
  readonly invocationResult: ConnectorAdapterInvocationResult;
}

export interface ConnectorExecutionReconciliationRequired {
  readonly schemaVersion: "toadaid.connector-execution-outcome.v1";
  readonly status: "RECONCILIATION_REQUIRED";
  readonly replayFenceSha256: string;
  readonly invocationRecordSha256: string;
  readonly invocation: CapabilityInvocationEnvelope;
  readonly errorClass: string;
  readonly errorFingerprintSha256: string;
  readonly reconciliation: ReplayReconciliationEnvelope;
}

export type GovernedConnectorExecutionOutcome =
  | ConnectorExecutionSuccess
  | ConnectorExecutionReconciliationRequired;

export interface GovernedConnectorExecutionRuntime extends ReplayFenceRuntime {}

export type GovernedConnectorExecutionAdapter = GovernedConnectorAdapter;
