import {
  transitionCapabilityInvocation,
  validateCapabilityInvocationEnvelope,
} from "./capabilityInvocationRecord.js";
import {
  canonicalIso,
  managerId,
  normalizeEvidenceRefs,
} from "./invocationSchema.js";
import {
  openReplayReconciliation,
  validateReplayReconciliationEnvelope,
} from "./replayFence.js";
import type {
  CapabilityInvocationEnvelope,
  CapabilityInvocationExecutionTruth,
  CapabilityInvocationTransitionRuntime,
} from "./invocationTypes.js";
import type {
  OpenReplayReconciliationInput,
  ReplayFenceEnvelope,
  ReplayFenceRuntime,
  ReplayReconciliationEnvelope,
} from "./replayFenceTypes.js";

export interface OpenCapabilityInvocationReconciliationResult {
  readonly schemaVersion:
    "toadaid.capability-invocation-reconciliation-open.v1";
  readonly invocation: CapabilityInvocationEnvelope;
  readonly reconciliation: ReplayReconciliationEnvelope;
}

function closeoutNow(
  runtime?: CapabilityInvocationTransitionRuntime,
): string {
  return canonicalIso(
    undefined,
    "now",
    runtime?.now ?? (() => new Date()),
  );
}

function executionTruth(
  finding:
    | "CONFIRMED_NOT_EXECUTED"
    | "CONFIRMED_EXECUTED"
    | "STILL_UNKNOWN",
): CapabilityInvocationExecutionTruth {
  if (finding === "CONFIRMED_EXECUTED") return "EXECUTED";
  if (finding === "CONFIRMED_NOT_EXECUTED") return "NOT_EXECUTED";
  return "UNKNOWN";
}

export function beginCapabilityInvocationReconciliation(
  fence: ReplayFenceEnvelope,
  invocation: CapabilityInvocationEnvelope,
  input: OpenReplayReconciliationInput,
  runtime?: ReplayFenceRuntime,
): OpenCapabilityInvocationReconciliationResult {
  const current = validateCapabilityInvocationEnvelope(invocation);
  if (
    current.record.status !== "STARTED" &&
    current.record.status !== "CANCEL_REQUESTED"
  ) {
    throw new Error(
      "only active invocation may enter reconciliation lock",
    );
  }

  const reconciliation = openReplayReconciliation(
    fence,
    current,
    input,
    runtime,
  );
  if (
    reconciliation.record.invocationRecordSha256 !==
    current.recordSha256
  ) {
    throw new Error(
      "opened reconciliation is not bound to exact H1 predecessor",
    );
  }
  if (
    Date.parse(reconciliation.record.openedAt) <
    Date.parse(current.record.updatedAt)
  ) {
    throw new RangeError(
      "X1 openedAt is earlier than active H1 predecessor",
    );
  }

  const locked = transitionCapabilityInvocation(current, {
    ...current.record,
    status: "RECONCILIATION_REQUIRED",
    updatedAt: reconciliation.record.openedAt,
    reconciliation: Object.freeze({
      reconciliationId:
        reconciliation.record.reconciliationId,
      replayFenceSha256:
        reconciliation.record.replayFenceSha256,
      openReconciliationSha256:
        reconciliation.recordSha256,
      invocationRecordSha256:
        reconciliation.record.invocationRecordSha256,
      openedAt: reconciliation.record.openedAt,
    }),
  });

  return Object.freeze({
    schemaVersion:
      "toadaid.capability-invocation-reconciliation-open.v1",
    invocation: locked,
    reconciliation,
  });
}

export function closeCapabilityInvocationReconciliation(
  invocation: CapabilityInvocationEnvelope,
  reconciliationInput: ReplayReconciliationEnvelope,
  manager: string,
  runtime?: CapabilityInvocationTransitionRuntime,
): CapabilityInvocationEnvelope {
  const current = validateCapabilityInvocationEnvelope(invocation);
  if (
    current.record.status !== "RECONCILIATION_REQUIRED"
  ) {
    throw new Error(
      "only reconciliation-locked invocation may close from X1",
    );
  }
  const lock = current.record.reconciliation;
  if (!lock) {
    throw new Error(
      "reconciliation-locked invocation is missing H1/X1 binding",
    );
  }

  const reconciliation =
    validateReplayReconciliationEnvelope(reconciliationInput);
  if (
    reconciliation.record.status !== "RESOLVED" ||
    reconciliation.record.resolvedAt === null ||
    reconciliation.record.finding === null
  ) {
    throw new Error(
      "H1 reconciliation closeout requires resolved X1 truth",
    );
  }

  if (
    reconciliation.record.reconciliationId !==
      lock.reconciliationId ||
    reconciliation.record.replayFenceSha256 !==
      lock.replayFenceSha256 ||
    reconciliation.record.invocationRecordSha256 !==
      lock.invocationRecordSha256 ||
    reconciliation.record.continuity.previousRecordSha256 !==
      lock.openReconciliationSha256
  ) {
    throw new Error(
      "resolved X1 reconciliation does not continue exact H1/X1 lock",
    );
  }

  if (
    current.record.continuity.previousRecordSha256 !==
    lock.invocationRecordSha256
  ) {
    throw new Error(
      "H1 reconciliation lock is not the direct invocation predecessor",
    );
  }

  const binding = reconciliation.record.binding;
  if (
    binding.runId !== current.record.runId ||
    binding.invocationId !== current.record.invocationId ||
    binding.capabilityId !== current.record.capabilityId ||
    binding.intentSha256 !== current.record.request.intentSha256
  ) {
    throw new Error(
      "resolved X1 binding does not match H1 invocation identity",
    );
  }

  const reconciledAt = closeoutNow(runtime);
  if (
    Date.parse(reconciledAt) <
    Date.parse(reconciliation.record.resolvedAt)
  ) {
    throw new RangeError(
      "H1 closeout time is earlier than X1 resolution",
    );
  }

  return transitionCapabilityInvocation(current, {
    ...current.record,
    status: "RECONCILED",
    updatedAt: reconciledAt,
    outcome: Object.freeze({
      kind: "RECONCILED",
      reconciledAt,
      managerId: managerId(manager),
      reconciliationId:
        reconciliation.record.reconciliationId,
      reconciliationSha256:
        reconciliation.recordSha256,
      replayFenceSha256:
        reconciliation.record.replayFenceSha256,
      finding: reconciliation.record.finding,
      disposition: reconciliation.record.disposition,
      executionTruth: executionTruth(
        reconciliation.record.finding,
      ),
      proofSha256: reconciliation.record.proofSha256,
      evidenceRefs: normalizeEvidenceRefs([
        {
          id: "reconciliation",
          sha256: reconciliation.recordSha256,
        },
      ]),
    }),
  });
}
