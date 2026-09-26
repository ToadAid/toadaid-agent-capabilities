export type * from "./connectorExecutionTypes.js";

import { invokeGovernedConnectorAdapter } from "./connectorAdapter.js";
import { validateCapabilityInvocationEnvelope } from "./capabilityInvocationRecord.js";
import { sha256 } from "./invocationSchema.js";
import {
  openReplayReconciliation,
  validateReplayFenceEnvelope,
} from "./replayFence.js";
import {
  boundedId,
  canonicalIso,
} from "./replayFenceSchema.js";
import type {
  ConnectorAdapterInvocationRequest,
  GovernedConnectorAdapter,
} from "./connectorAdapterTypes.js";
import type {
  GovernedConnectorExecutionInput,
  GovernedConnectorExecutionOutcome,
  GovernedConnectorExecutionRuntime,
} from "./connectorExecutionTypes.js";

const MAX_ERROR_CLASS_LENGTH = 128;
const MAX_ERROR_FINGERPRINT_TEXT = 1024;

function normalizedErrorClass(error: unknown): string {
  if (error instanceof Error) {
    const candidate = error.name.trim();
    if (candidate.length > 0 && candidate.length <= MAX_ERROR_CLASS_LENGTH) {
      return candidate;
    }
    return "Error";
  }
  if (typeof error === "string") return "THROWN_STRING";
  if (error === null) return "THROWN_NULL";
  return `THROWN_${typeof error}`.slice(0, MAX_ERROR_CLASS_LENGTH);
}

function boundedFingerprintText(value: string): string {
  return value.slice(0, MAX_ERROR_FINGERPRINT_TEXT);
}

function connectorErrorFingerprint(error: unknown): string {
  if (error instanceof Error) {
    return sha256({
      kind: "ERROR",
      name: boundedFingerprintText(error.name),
      message: boundedFingerprintText(error.message),
    });
  }
  if (
    error === null ||
    typeof error === "boolean" ||
    typeof error === "number" ||
    typeof error === "string"
  ) {
    return sha256({
      kind: "THROWN_PRIMITIVE",
      type: error === null ? "null" : typeof error,
      value: boundedFingerprintText(String(error)),
    });
  }
  return sha256({
    kind: "THROWN_NON_PRIMITIVE",
    type: typeof error,
  });
}

function validateReconciliationMetadata(
  input: GovernedConnectorExecutionInput,
): Readonly<{ reconciliationId?: string; openedAt?: string }> {
  return Object.freeze({
    ...(input.reconciliationId === undefined
      ? {}
      : { reconciliationId: boundedId(input.reconciliationId, "reconciliationId") }),
    ...(input.openedAt === undefined
      ? {}
      : { openedAt: canonicalIso(input.openedAt, "openedAt") }),
  });
}

function assertReplayFenceMatchesInvocation(
  input: GovernedConnectorExecutionInput,
): ReturnType<typeof validateReplayFenceEnvelope> {
  const invocation = validateCapabilityInvocationEnvelope(input.invocation);
  const fence = validateReplayFenceEnvelope(input.replayFence);
  const binding = fence.record.binding;

  if (
    binding.runId !== invocation.record.runId ||
    binding.invocationId !== invocation.record.invocationId ||
    binding.capabilityId !== invocation.record.capabilityId ||
    binding.intentSha256 !== invocation.record.request.intentSha256
  ) {
    throw new Error("connector execution replay fence does not match H1 invocation");
  }

  return fence;
}

export async function executeGovernedConnectorInvocation(
  adapter: GovernedConnectorAdapter,
  input: GovernedConnectorExecutionInput,
  runtime?: GovernedConnectorExecutionRuntime,
): Promise<GovernedConnectorExecutionOutcome> {
  const invocation = validateCapabilityInvocationEnvelope(input.invocation);
  const fence = assertReplayFenceMatchesInvocation(input);
  const reconciliationMetadata = validateReconciliationMetadata(input);

  let adapterEntered = false;
  const trackedAdapter: GovernedConnectorAdapter = Object.freeze({
    registration: adapter.registration,
    invoke(request: ConnectorAdapterInvocationRequest) {
      adapterEntered = true;
      return adapter.invoke(request);
    },
  });

  const {
    replayFence: _replayFence,
    reconciliationId: _reconciliationId,
    openedAt: _openedAt,
    ...connectorInput
  } = input;

  try {
    const invocationResult = await invokeGovernedConnectorAdapter(
      trackedAdapter,
      connectorInput,
    );

    return Object.freeze({
      schemaVersion: "toadaid.connector-execution-outcome.v1",
      status: "SUCCEEDED",
      replayFenceSha256: fence.recordSha256,
      adapterReceiptSha256: sha256(invocationResult.receipt),
      invocationResult,
    });
  } catch (error) {
    if (!adapterEntered) throw error;

    const errorClass = normalizedErrorClass(error);
    const errorFingerprintSha256 = connectorErrorFingerprint(error);
    const reconciliation = openReplayReconciliation(
      fence,
      invocation,
      {
        ...reconciliationMetadata,
        reasonCode: "CONNECTOR_OUTCOME_UNKNOWN",
        evidenceRefs: Object.freeze([
          Object.freeze({
            id: "connector-error",
            sha256: errorFingerprintSha256,
          }),
        ]),
      },
      runtime,
    );

    return Object.freeze({
      schemaVersion: "toadaid.connector-execution-outcome.v1",
      status: "RECONCILIATION_REQUIRED",
      replayFenceSha256: fence.recordSha256,
      errorClass,
      errorFingerprintSha256,
      reconciliation,
    });
  }
}
