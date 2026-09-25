import {
  RUN_BUDGET_METRICS,
  SHA256_PATTERN,
  addRunBudgetVectors,
  boundedId,
  canonicalIso,
  normalizeRunBudgetVector,
  optionalSha,
  requiredSha,
  runBudgetVectorIsZero,
  sha256,
  subtractRunBudgetVectors,
  sumUsage,
  zeroRunBudgetVector,
} from "./runBudgetSchema.js";
import type {
  RunBudgetAvailabilityReceipt,
  RunBudgetChildAllocation,
  RunBudgetLedgerEnvelope,
  RunBudgetLedgerRecord,
  RunBudgetMetric,
  RunBudgetParentBinding,
  RunBudgetUsageKind,
  RunBudgetUsageReceipt,
  RunBudgetVector,
} from "./runBudgetTypes.js";

function freezeVector(vector: RunBudgetVector): RunBudgetVector {
  return Object.freeze({ ...vector });
}

function freezeUsage(receipt: RunBudgetUsageReceipt): RunBudgetUsageReceipt {
  return Object.freeze({ ...receipt, delta: freezeVector(receipt.delta) });
}

function allocationCore(allocation: Omit<RunBudgetChildAllocation, "allocationSha256"> | RunBudgetChildAllocation) {
  const { allocationSha256: _ignored, ...core } = allocation as RunBudgetChildAllocation;
  return core;
}

export function runBudgetChildAllocationSha256(allocation: Omit<RunBudgetChildAllocation, "allocationSha256"> | RunBudgetChildAllocation): string {
  return sha256(allocationCore(allocation));
}

function freezeAllocation(allocation: RunBudgetChildAllocation): RunBudgetChildAllocation {
  return Object.freeze({ ...allocation, limits: freezeVector(allocation.limits) });
}

function freezeParentBinding(binding: RunBudgetParentBinding | null): RunBudgetParentBinding | null {
  return binding === null ? null : Object.freeze({ ...binding });
}

function freezeRecord(record: RunBudgetLedgerRecord): RunBudgetLedgerRecord {
  return Object.freeze({
    ...record,
    limits: freezeVector(record.limits),
    parentBinding: freezeParentBinding(record.parentBinding),
    usageReceipts: Object.freeze(record.usageReceipts.map(freezeUsage)),
    childAllocations: Object.freeze(record.childAllocations.map(freezeAllocation)),
    continuity: Object.freeze({ ...record.continuity }),
  });
}

export function runBudgetLedgerSha256(record: RunBudgetLedgerRecord): string {
  return sha256(record);
}

export function validateUsageReceipt(receipt: RunBudgetUsageReceipt): RunBudgetUsageReceipt {
  if (receipt.schemaVersion !== "toadaid.run-budget-usage.v1") throw new TypeError("unsupported run budget usage schemaVersion");
  const receiptId = boundedId(receipt.receiptId, "receiptId");
  const kinds: readonly RunBudgetUsageKind[] = ["MODEL", "TOOL", "NETWORK", "RETRY", "WALL_CLOCK", "OTHER", "CHILD_ALLOCATION"];
  if (!kinds.includes(receipt.kind)) throw new TypeError("run budget usage kind is invalid");
  const occurredAt = canonicalIso(receipt.occurredAt, "occurredAt", () => new Date(receipt.occurredAt));
  const invocationId = receipt.invocationId === undefined ? undefined : boundedId(receipt.invocationId, "invocationId");
  const sourceSha256 = optionalSha(receipt.sourceSha256, "sourceSha256");
  const delta = normalizeRunBudgetVector(receipt.delta, "usage.delta");
  if (runBudgetVectorIsZero(delta)) throw new TypeError("usage delta must consume at least one budget metric");
  if (receipt.kind !== "CHILD_ALLOCATION" && delta.childTasks !== 0) {
    throw new TypeError("childTasks may only be consumed by a child allocation");
  }
  return freezeUsage({ schemaVersion: receipt.schemaVersion, receiptId, kind: receipt.kind, occurredAt, ...(invocationId ? { invocationId } : {}), ...(sourceSha256 ? { sourceSha256 } : {}), delta });
}

export function validateAllocation(allocation: RunBudgetChildAllocation): RunBudgetChildAllocation {
  if (allocation.schemaVersion !== "toadaid.run-budget-child-allocation.v1") throw new TypeError("unsupported child allocation schemaVersion");
  const normalized: RunBudgetChildAllocation = {
    schemaVersion: allocation.schemaVersion,
    allocationId: boundedId(allocation.allocationId, "allocationId"),
    childBudgetId: boundedId(allocation.childBudgetId, "childBudgetId"),
    childRunId: boundedId(allocation.childRunId, "childRunId"),
    ...(allocation.childTaskId === undefined ? {} : { childTaskId: boundedId(allocation.childTaskId, "childTaskId") }),
    allocatedAt: canonicalIso(allocation.allocatedAt, "allocatedAt", () => new Date(allocation.allocatedAt)),
    parentLedgerSha256Before: requiredSha(allocation.parentLedgerSha256Before, "parentLedgerSha256Before"),
    limits: normalizeRunBudgetVector(allocation.limits, "allocation.limits"),
    allocationSha256: allocation.allocationSha256,
  };
  if (!SHA256_PATTERN.test(normalized.allocationSha256) || runBudgetChildAllocationSha256(normalized) !== normalized.allocationSha256) {
    throw new Error("child allocation integrity mismatch");
  }
  return freezeAllocation(normalized);
}

export function validateRunBudgetLedgerRecord(record: RunBudgetLedgerRecord): RunBudgetLedgerRecord {
  if (record.schemaVersion !== "toadaid.run-budget-ledger.v1") throw new TypeError("unsupported run budget ledger schemaVersion");
  const budgetId = boundedId(record.budgetId, "budgetId");
  const runId = boundedId(record.runId, "runId");
  const childTaskId = record.childTaskId === undefined ? undefined : boundedId(record.childTaskId, "childTaskId");
  if (!Number.isSafeInteger(record.revision) || record.revision < 0) throw new TypeError("revision must be a non-negative safe integer");
  const createdAt = canonicalIso(record.createdAt, "createdAt", () => new Date(record.createdAt));
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt", () => new Date(record.updatedAt));
  if (Date.parse(updatedAt) < Date.parse(createdAt)) throw new RangeError("updatedAt must not precede createdAt");
  const limits = normalizeRunBudgetVector(record.limits, "limits");

  let parentBinding: RunBudgetParentBinding | null = null;
  if (record.parentBinding !== null) {
    parentBinding = Object.freeze({
      parentBudgetId: boundedId(record.parentBinding.parentBudgetId, "parentBinding.parentBudgetId"),
      allocationId: boundedId(record.parentBinding.allocationId, "parentBinding.allocationId"),
      allocationSha256: requiredSha(record.parentBinding.allocationSha256, "parentBinding.allocationSha256"),
    });
  }

  if (record.revision === 0 && record.continuity.previousRecordSha256 !== null) throw new TypeError("revision 0 must not have predecessor SHA");
  if (record.revision > 0 && (!record.continuity.previousRecordSha256 || !SHA256_PATTERN.test(record.continuity.previousRecordSha256))) {
    throw new TypeError("non-zero revision requires predecessor SHA");
  }

  const usageReceipts = record.usageReceipts.map(validateUsageReceipt);
  const usageIds = new Set<string>();
  for (const receipt of usageReceipts) {
    if (usageIds.has(receipt.receiptId)) throw new TypeError(`duplicate budget usage receipt: ${receipt.receiptId}`);
    usageIds.add(receipt.receiptId);
  }

  const childAllocations = record.childAllocations.map(validateAllocation);
  const allocationIds = new Set<string>();
  const childBudgetIds = new Set<string>();
  for (const allocation of childAllocations) {
    if (allocationIds.has(allocation.allocationId)) throw new TypeError(`duplicate child allocation: ${allocation.allocationId}`);
    if (childBudgetIds.has(allocation.childBudgetId)) throw new TypeError(`duplicate child budget: ${allocation.childBudgetId}`);
    allocationIds.add(allocation.allocationId);
    childBudgetIds.add(allocation.childBudgetId);
  }

  const normalized = freezeRecord({
    schemaVersion: record.schemaVersion,
    budgetId,
    runId,
    ...(childTaskId ? { childTaskId } : {}),
    revision: record.revision,
    createdAt,
    updatedAt,
    limits,
    parentBinding,
    usageReceipts,
    childAllocations,
    continuity: Object.freeze({ previousRecordSha256: record.continuity.previousRecordSha256 }),
  });

  const remaining = calculateRemaining(normalized);
  for (const metric of RUN_BUDGET_METRICS) {
    const spent = normalized.limits[metric] - remaining[metric];
    if (spent < 0 || spent > normalized.limits[metric]) throw new RangeError(`budget overspent: ${metric}`);
  }
  return normalized;
}

export function sealRunBudgetLedger(record: RunBudgetLedgerRecord): RunBudgetLedgerEnvelope {
  const normalized = validateRunBudgetLedgerRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.run-budget-ledger-envelope.v1",
    record: normalized,
    recordSha256: runBudgetLedgerSha256(normalized),
  });
}

export function validateRunBudgetLedgerEnvelope(envelope: RunBudgetLedgerEnvelope): RunBudgetLedgerEnvelope {
  if (envelope.schemaVersion !== "toadaid.run-budget-ledger-envelope.v1") throw new TypeError("unsupported run budget envelope schemaVersion");
  const record = validateRunBudgetLedgerRecord(envelope.record);
  if (!SHA256_PATTERN.test(envelope.recordSha256) || runBudgetLedgerSha256(record) !== envelope.recordSha256) {
    throw new Error("run budget ledger integrity mismatch");
  }
  return Object.freeze({ schemaVersion: envelope.schemaVersion, record, recordSha256: envelope.recordSha256 });
}

function calculateReserved(record: RunBudgetLedgerRecord): RunBudgetVector {
  let total = zeroRunBudgetVector();
  for (const allocation of record.childAllocations) total = addRunBudgetVectors(total, allocation.limits, "child reservation total");
  return total;
}

function calculateRemaining(record: RunBudgetLedgerRecord): RunBudgetVector {
  const used = sumUsage(record.usageReceipts);
  const reserved = calculateReserved(record);
  const committed = addRunBudgetVectors(used, reserved, "budget committed total");
  for (const metric of RUN_BUDGET_METRICS) {
    if (committed[metric] > record.limits[metric]) throw new RangeError(`budget commitment exceeds limit: ${metric}`);
  }
  return subtractRunBudgetVectors(record.limits, committed);
}

export function remainingRunBudget(envelope: RunBudgetLedgerEnvelope): RunBudgetVector {
  return calculateRemaining(validateRunBudgetLedgerEnvelope(envelope).record);
}

export function exhaustedRunBudgetMetrics(envelope: RunBudgetLedgerEnvelope): readonly RunBudgetMetric[] {
  const remaining = remainingRunBudget(envelope);
  return Object.freeze(RUN_BUDGET_METRICS.filter((metric) => remaining[metric] === 0));
}

export function evaluateRunBudgetAvailability(envelope: RunBudgetLedgerEnvelope, requestedInput: RunBudgetVector): RunBudgetAvailabilityReceipt {
  const current = validateRunBudgetLedgerEnvelope(envelope);
  const requested = normalizeRunBudgetVector(requestedInput, "requested");
  const remainingBefore = calculateRemaining(current.record);
  const exceededMetrics = RUN_BUDGET_METRICS.filter((metric) => requested[metric] > remainingBefore[metric]);
  const allowed = exceededMetrics.length === 0;
  const remainingAfter = allowed ? subtractRunBudgetVectors(remainingBefore, requested) : remainingBefore;
  return Object.freeze({
    schemaVersion: "toadaid.run-budget-availability.v1",
    budgetId: current.record.budgetId,
    ledgerSha256: current.recordSha256,
    requested,
    remainingBefore,
    remainingAfter,
    allowed,
    exceededMetrics: Object.freeze(exceededMetrics),
  });
}

export function assertRunBudgetPredecessor(previousInput: RunBudgetLedgerEnvelope, nextInput: RunBudgetLedgerEnvelope): void {
  const previous = validateRunBudgetLedgerEnvelope(previousInput);
  const next = validateRunBudgetLedgerEnvelope(nextInput);
  if (next.record.budgetId !== previous.record.budgetId || next.record.runId !== previous.record.runId || next.record.childTaskId !== previous.record.childTaskId) {
    throw new Error("run budget identity changed across transition");
  }
  if (next.record.revision !== previous.record.revision + 1 || next.record.continuity.previousRecordSha256 !== previous.recordSha256) {
    throw new Error("run budget predecessor continuity mismatch");
  }
  if (next.record.createdAt !== previous.record.createdAt || Date.parse(next.record.updatedAt) < Date.parse(previous.record.updatedAt)) {
    throw new Error("run budget timestamps moved backward or creation time changed");
  }
  if (sha256(next.record.limits) !== sha256(previous.record.limits) || sha256(next.record.parentBinding) !== sha256(previous.record.parentBinding)) {
    throw new Error("run budget immutable scope changed across transition");
  }
  if (next.record.usageReceipts.length < previous.record.usageReceipts.length || next.record.childAllocations.length < previous.record.childAllocations.length) {
    throw new Error("run budget append-only history was truncated");
  }
  for (let index = 0; index < previous.record.usageReceipts.length; index += 1) {
    if (sha256(next.record.usageReceipts[index]) !== sha256(previous.record.usageReceipts[index])) throw new Error("run budget usage history was rewritten");
  }
  for (let index = 0; index < previous.record.childAllocations.length; index += 1) {
    if (sha256(next.record.childAllocations[index]) !== sha256(previous.record.childAllocations[index])) throw new Error("run budget allocation history was rewritten");
  }
}

export function assertChildRunBudgetBinding(
  parentInput: RunBudgetLedgerEnvelope,
  childInput: RunBudgetLedgerEnvelope,
): RunBudgetChildAllocation {
  const parent = validateRunBudgetLedgerEnvelope(parentInput);
  const child = validateRunBudgetLedgerEnvelope(childInput);
  const binding = child.record.parentBinding;
  if (binding === null) throw new Error("child budget has no parent binding");
  if (binding.parentBudgetId !== parent.record.budgetId) throw new Error("child budget parent identity mismatch");
  const allocation = parent.record.childAllocations.find((item) =>
    item.allocationId === binding.allocationId &&
    item.allocationSha256 === binding.allocationSha256 &&
    item.childBudgetId === child.record.budgetId
  );
  if (!allocation) throw new Error("child budget allocation is not present in parent ledger");
  if (allocation.childRunId !== child.record.runId || allocation.childTaskId !== child.record.childTaskId) {
    throw new Error("child budget run/task identity does not match parent allocation");
  }
  if (sha256(allocation.limits) !== sha256(child.record.limits)) throw new Error("child budget limits do not match parent allocation");
  return allocation;
}

export function serializeRunBudgetLedger(envelope: RunBudgetLedgerEnvelope): string {
  return JSON.stringify(validateRunBudgetLedgerEnvelope(envelope));
}

export function parseRunBudgetLedger(serialized: string): RunBudgetLedgerEnvelope {
  if (typeof serialized !== "string" || serialized.length > 2_000_000) throw new TypeError("serialized run budget ledger is invalid");
  return validateRunBudgetLedgerEnvelope(JSON.parse(serialized) as RunBudgetLedgerEnvelope);
}
