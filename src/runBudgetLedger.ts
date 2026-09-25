import { randomUUID } from "node:crypto";
import {
  boundedId,
  canonicalIso,
  normalizeRunBudgetVector,
  optionalSha,
  runBudgetVectorIsZero,
  sha256,
  zeroRunBudgetVector,
} from "./runBudgetSchema.js";
import {
  assertChildRunBudgetBinding,
  assertRunBudgetPredecessor,
  evaluateRunBudgetAvailability,
  exhaustedRunBudgetMetrics,
  parseRunBudgetLedger,
  remainingRunBudget,
  runBudgetChildAllocationSha256,
  runBudgetLedgerSha256,
  sealRunBudgetLedger,
  serializeRunBudgetLedger,
  validateAllocation,
  validateRunBudgetLedgerEnvelope,
  validateRunBudgetLedgerRecord,
  validateUsageReceipt,
} from "./runBudgetRecord.js";
import type {
  AllocateChildRunBudgetInput,
  AllocateChildRunBudgetResult,
  CreateRunBudgetInput,
  RecordRunBudgetUsageInput,
  RunBudgetLedgerEnvelope,
  RunBudgetLedgerRecord,
  RunBudgetRuntime,
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type * from "./runBudgetTypes.js";
export { RUN_BUDGET_METRICS, normalizeRunBudgetVector } from "./runBudgetSchema.js";
export {
  assertChildRunBudgetBinding,
  assertRunBudgetPredecessor,
  evaluateRunBudgetAvailability,
  exhaustedRunBudgetMetrics,
  parseRunBudgetLedger,
  remainingRunBudget,
  runBudgetChildAllocationSha256,
  runBudgetLedgerSha256,
  sealRunBudgetLedger,
  serializeRunBudgetLedger,
  validateRunBudgetLedgerEnvelope,
  validateRunBudgetLedgerRecord,
} from "./runBudgetRecord.js";

function runtimeNow(runtime?: RunBudgetRuntime): () => Date {
  return runtime?.now ?? (() => new Date());
}

function runtimeId(runtime?: RunBudgetRuntime): string {
  return (runtime?.randomId ?? randomUUID)();
}

function transition(currentInput: RunBudgetLedgerEnvelope, nextPartial: Omit<RunBudgetLedgerRecord, "revision" | "continuity">): RunBudgetLedgerEnvelope {
  const current = validateRunBudgetLedgerEnvelope(currentInput);
  const next = sealRunBudgetLedger({
    ...nextPartial,
    revision: current.record.revision + 1,
    continuity: Object.freeze({ previousRecordSha256: current.recordSha256 }),
  });
  assertRunBudgetPredecessor(current, next);
  return next;
}

export function createRunBudgetLedger(input: CreateRunBudgetInput, runtime?: RunBudgetRuntime): RunBudgetLedgerEnvelope {
  const now = runtimeNow(runtime);
  const createdAt = canonicalIso(input.createdAt, "createdAt", now);
  return sealRunBudgetLedger({
    schemaVersion: "toadaid.run-budget-ledger.v1",
    budgetId: boundedId(input.budgetId ?? runtimeId(runtime), "budgetId"),
    runId: boundedId(input.runId, "runId"),
    ...(input.childTaskId === undefined ? {} : { childTaskId: boundedId(input.childTaskId, "childTaskId") }),
    revision: 0,
    createdAt,
    updatedAt: createdAt,
    limits: normalizeRunBudgetVector(input.limits, "limits"),
    parentBinding: null,
    usageReceipts: Object.freeze([]),
    childAllocations: Object.freeze([]),
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

export function recordRunBudgetUsage(
  envelope: RunBudgetLedgerEnvelope,
  input: RecordRunBudgetUsageInput,
  runtime?: RunBudgetRuntime,
): RunBudgetLedgerEnvelope {
  const current = validateRunBudgetLedgerEnvelope(envelope);
  const delta = normalizeRunBudgetVector(input.delta, "usage.delta");
  if (runBudgetVectorIsZero(delta)) throw new TypeError("usage delta must consume at least one metric");
  if (delta.childTasks !== 0) throw new TypeError("childTasks may only be consumed through allocateChildRunBudget");
  const availability = evaluateRunBudgetAvailability(current, delta);
  if (!availability.allowed) throw new RangeError(`run budget exceeded: ${availability.exceededMetrics.join(",")}`);
  const occurredAt = canonicalIso(input.occurredAt, "occurredAt", runtimeNow(runtime));
  if (Date.parse(occurredAt) < Date.parse(current.record.updatedAt)) throw new RangeError("usage occurredAt precedes current budget revision");
  const receipt = validateUsageReceipt({
    schemaVersion: "toadaid.run-budget-usage.v1",
    receiptId: boundedId(input.receiptId ?? runtimeId(runtime), "receiptId"),
    kind: input.kind,
    occurredAt,
    ...(input.invocationId === undefined ? {} : { invocationId: boundedId(input.invocationId, "invocationId") }),
    ...(input.sourceSha256 === undefined ? {} : { sourceSha256: optionalSha(input.sourceSha256, "sourceSha256")! }),
    delta,
  });
  if (current.record.usageReceipts.some((item) => item.receiptId === receipt.receiptId)) throw new TypeError(`duplicate budget usage receipt: ${receipt.receiptId}`);
  return transition(current, {
    ...current.record,
    updatedAt: occurredAt,
    usageReceipts: Object.freeze([...current.record.usageReceipts, receipt]),
  });
}

export function allocateChildRunBudget(
  envelope: RunBudgetLedgerEnvelope,
  input: AllocateChildRunBudgetInput,
  runtime?: RunBudgetRuntime,
): AllocateChildRunBudgetResult {
  const current = validateRunBudgetLedgerEnvelope(envelope);
  const limits = normalizeRunBudgetVector(input.limits, "child.limits");
  const reservationCost = { ...limits, childTasks: limits.childTasks + 1 } as RunBudgetVector;
  if (!Number.isSafeInteger(reservationCost.childTasks)) throw new RangeError("child task reservation exceeds safe integer range");
  const availability = evaluateRunBudgetAvailability(current, reservationCost);
  if (!availability.allowed) throw new RangeError(`child budget allocation exceeds parent remaining budget: ${availability.exceededMetrics.join(",")}`);

  const allocatedAt = canonicalIso(input.allocatedAt, "allocatedAt", runtimeNow(runtime));
  if (Date.parse(allocatedAt) < Date.parse(current.record.updatedAt)) throw new RangeError("allocation time precedes current parent budget revision");
  const allocationId = boundedId(input.allocationId ?? runtimeId(runtime), "allocationId");
  const childBudgetId = boundedId(input.childBudgetId ?? runtimeId(runtime), "childBudgetId");
  if (current.record.childAllocations.some((item) => item.allocationId === allocationId || item.childBudgetId === childBudgetId)) {
    throw new TypeError("duplicate child allocation identity");
  }

  const allocationCoreValue = {
    schemaVersion: "toadaid.run-budget-child-allocation.v1" as const,
    allocationId,
    childBudgetId,
    childRunId: boundedId(input.childRunId, "childRunId"),
    ...(input.childTaskId === undefined ? {} : { childTaskId: boundedId(input.childTaskId, "childTaskId") }),
    allocatedAt,
    parentLedgerSha256Before: current.recordSha256,
    limits,
  };
  const allocation = validateAllocation({ ...allocationCoreValue, allocationSha256: runBudgetChildAllocationSha256(allocationCoreValue) });
  const childCountReceipt = validateUsageReceipt({
    schemaVersion: "toadaid.run-budget-usage.v1",
    receiptId: boundedId(`child-${sha256(allocationId).slice(0, 32)}`, "receiptId"),
    kind: "CHILD_ALLOCATION",
    occurredAt: allocatedAt,
    sourceSha256: allocation.allocationSha256,
    delta: Object.freeze({ ...zeroRunBudgetVector(), childTasks: 1 }),
  });

  const parent = transition(current, {
    ...current.record,
    updatedAt: allocatedAt,
    usageReceipts: Object.freeze([...current.record.usageReceipts, childCountReceipt]),
    childAllocations: Object.freeze([...current.record.childAllocations, allocation]),
  });

  const child = sealRunBudgetLedger({
    schemaVersion: "toadaid.run-budget-ledger.v1",
    budgetId: childBudgetId,
    runId: allocation.childRunId,
    ...(allocation.childTaskId === undefined ? {} : { childTaskId: allocation.childTaskId }),
    revision: 0,
    createdAt: allocatedAt,
    updatedAt: allocatedAt,
    limits,
    parentBinding: Object.freeze({
      parentBudgetId: current.record.budgetId,
      allocationId,
      allocationSha256: allocation.allocationSha256,
    }),
    usageReceipts: Object.freeze([]),
    childAllocations: Object.freeze([]),
    continuity: Object.freeze({ previousRecordSha256: null }),
  });

  return Object.freeze({ parent, allocation, child });
}

