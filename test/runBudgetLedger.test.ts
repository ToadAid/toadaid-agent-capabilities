import test from "node:test";
import assert from "node:assert/strict";
import {
  allocateChildRunBudget,
  assertChildRunBudgetBinding,
  assertRunBudgetPredecessor,
  createRunBudgetLedger,
  evaluateRunBudgetAvailability,
  exhaustedRunBudgetMetrics,
  parseRunBudgetLedger,
  recordRunBudgetUsage,
  remainingRunBudget,
  serializeRunBudgetLedger,
  validateRunBudgetLedgerEnvelope,
} from "../src/runBudgetLedger.js";
import type { RunBudgetRuntime, RunBudgetVector } from "../src/runBudgetLedger.js";

const limits = (overrides: Partial<RunBudgetVector> = {}): RunBudgetVector => ({
  modelRequests: 10,
  inputTokens: 10_000,
  outputTokens: 5_000,
  toolCalls: 20,
  networkRequests: 30,
  retries: 4,
  wallClockMs: 60_000,
  childTasks: 4,
  ...overrides,
});

const zero = (overrides: Partial<RunBudgetVector> = {}): RunBudgetVector => ({
  modelRequests: 0,
  inputTokens: 0,
  outputTokens: 0,
  toolCalls: 0,
  networkRequests: 0,
  retries: 0,
  wallClockMs: 0,
  childTasks: 0,
  ...overrides,
});

function runtime(): RunBudgetRuntime {
  let id = 0;
  let ms = Date.parse("2026-09-25T03:45:00.000Z");
  return {
    randomId: () => `id-${++id}`,
    now: () => new Date(ms += 1000),
  };
}

test("creates sealed root ledger with deterministic remaining budget", () => {
  const ledger = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", createdAt: "2026-09-25T03:45:00.000Z", limits: limits() });
  assert.equal(validateRunBudgetLedgerEnvelope(ledger).record.revision, 0);
  assert.deepEqual(remainingRunBudget(ledger), limits());
});

test("records append-only model usage and computes remaining budget", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() }, rt);
  const next = recordRunBudgetUsage(root, {
    receiptId: "usage-1",
    kind: "MODEL",
    invocationId: "inv-1",
    sourceSha256: "a".repeat(64),
    delta: zero({ modelRequests: 1, inputTokens: 400, outputTokens: 120, wallClockMs: 250 }),
  }, rt);
  assertRunBudgetPredecessor(root, next);
  assert.equal(remainingRunBudget(next).modelRequests, 9);
  assert.equal(remainingRunBudget(next).inputTokens, 9600);
  assert.equal(next.record.usageReceipts.length, 1);
});

test("refuses usage that exceeds any remaining metric", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ toolCalls: 1 }) });
  assert.throws(() => recordRunBudgetUsage(root, { kind: "TOOL", delta: zero({ toolCalls: 2 }) }), /run budget exceeded: toolCalls/);
});

test("generic usage cannot forge child-task consumption", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() });
  assert.throws(() => recordRunBudgetUsage(root, { kind: "OTHER", delta: zero({ childTasks: 1 }) }), /allocateChildRunBudget/);
});

test("child allocation reserves its full budget plus one direct child slot", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ modelRequests: 10, childTasks: 4 }) }, rt);
  const result = allocateChildRunBudget(root, {
    allocationId: "alloc-1",
    childBudgetId: "budget-child",
    childRunId: "run-child",
    childTaskId: "task-child",
    limits: limits({ modelRequests: 3, inputTokens: 1000, outputTokens: 500, toolCalls: 2, networkRequests: 2, retries: 1, wallClockMs: 10_000, childTasks: 1 }),
  }, rt);
  assert.equal(remainingRunBudget(result.parent).modelRequests, 7);
  assert.equal(remainingRunBudget(result.parent).childTasks, 2);
  assert.equal(result.child.record.parentBinding?.allocationId, "alloc-1");
  assert.equal(remainingRunBudget(result.child).modelRequests, 3);
});

test("child ledger must verify against the exact parent allocation", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() }, rt);
  const result = allocateChildRunBudget(root, {
    allocationId: "alloc-bind",
    childBudgetId: "budget-child-bind",
    childRunId: "run-child-bind",
    childTaskId: "task-bind",
    limits: zero({ modelRequests: 2, childTasks: 1 }),
  }, rt);
  assert.equal(assertChildRunBudgetBinding(result.parent, result.child).allocationId, "alloc-bind");
  const other = createRunBudgetLedger({ budgetId: "other-parent", runId: "other-run", limits: limits() }, rt);
  assert.throws(() => assertChildRunBudgetBinding(other, result.child), /parent identity mismatch/);
});

test("child cannot be allocated more than parent remaining", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ modelRequests: 2 }) });
  assert.throws(() => allocateChildRunBudget(root, {
    childRunId: "run-child",
    limits: limits({ modelRequests: 3, inputTokens: 0, outputTokens: 0, toolCalls: 0, networkRequests: 0, retries: 0, wallClockMs: 0, childTasks: 0 }),
  }), /exceeds parent remaining budget: modelRequests/);
});

test("nested child allocation cannot escape the child's own sub-budget", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ childTasks: 5 }) }, rt);
  const child = allocateChildRunBudget(root, {
    childRunId: "run-child",
    childBudgetId: "budget-child",
    limits: limits({ modelRequests: 2, inputTokens: 100, outputTokens: 100, toolCalls: 1, networkRequests: 1, retries: 0, wallClockMs: 1000, childTasks: 1 }),
  }, rt).child;
  assert.throws(() => allocateChildRunBudget(child, {
    childRunId: "grandchild",
    limits: zero({ modelRequests: 3 }),
  }, rt), /exceeds parent remaining budget/);
});

test("parent cannot spend fuel already reserved to a child", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ modelRequests: 4 }) }, rt);
  const parent = allocateChildRunBudget(root, {
    childRunId: "run-child",
    limits: zero({ modelRequests: 3 }),
  }, rt).parent;
  assert.throws(() => recordRunBudgetUsage(parent, { kind: "MODEL", delta: zero({ modelRequests: 2 }) }, rt), /run budget exceeded: modelRequests/);
});

test("child usage does not mutate parent and unused reservation is not silently refunded", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits({ modelRequests: 5 }) }, rt);
  const allocation = allocateChildRunBudget(root, { childRunId: "run-child", limits: zero({ modelRequests: 3 }) }, rt);
  const spentChild = recordRunBudgetUsage(allocation.child, { kind: "MODEL", delta: zero({ modelRequests: 1 }) }, rt);
  assert.equal(remainingRunBudget(spentChild).modelRequests, 2);
  assert.equal(remainingRunBudget(allocation.parent).modelRequests, 2);
});

test("availability receipt is deterministic and operation-specific", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: zero({ modelRequests: 1, retries: 0 }) });
  const model = evaluateRunBudgetAvailability(root, zero({ modelRequests: 1 }));
  assert.equal(model.allowed, true);
  const retry = evaluateRunBudgetAvailability(root, zero({ retries: 1 }));
  assert.equal(retry.allowed, false);
  assert.deepEqual(retry.exceededMetrics, ["retries"]);
});

test("reports exhausted metrics without treating zero retry allowance as global authority", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: zero({ modelRequests: 1 }) });
  assert.ok(exhaustedRunBudgetMetrics(root).includes("retries"));
  assert.equal(evaluateRunBudgetAvailability(root, zero({ modelRequests: 1 })).allowed, true);
});

test("append-only transitions refuse timestamps that move backward", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", createdAt: "2026-09-25T03:45:10.000Z", limits: limits() }, rt);
  assert.throws(() => recordRunBudgetUsage(root, { occurredAt: "2026-09-25T03:45:09.000Z", kind: "TOOL", delta: zero({ toolCalls: 1 }) }, rt), /precedes current budget revision/);
});

test("tampering with a sealed ledger is refused", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() });
  const tampered = { ...root, record: { ...root.record, limits: { ...root.record.limits, toolCalls: 999 } } };
  assert.throws(() => validateRunBudgetLedgerEnvelope(tampered), /integrity mismatch/);
});

test("predecessor check refuses rewritten append-only history", () => {
  const rt = runtime();
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() }, rt);
  const one = recordRunBudgetUsage(root, { receiptId: "usage-1", kind: "TOOL", delta: zero({ toolCalls: 1 }) }, rt);
  const two = recordRunBudgetUsage(one, { receiptId: "usage-2", kind: "NETWORK", delta: zero({ networkRequests: 1 }) }, rt);
  const rewrittenRecord = { ...two.record, usageReceipts: [two.record.usageReceipts[1]!] };
  const rewritten = { ...two, record: rewrittenRecord };
  assert.throws(() => assertRunBudgetPredecessor(one, rewritten), /integrity mismatch|history/);
});

test("serialize/parse preserves sealed durable budget state", () => {
  const root = createRunBudgetLedger({ budgetId: "budget-root", runId: "run-1", limits: limits() });
  assert.deepEqual(parseRunBudgetLedger(serializeRunBudgetLedger(root)), root);
});
