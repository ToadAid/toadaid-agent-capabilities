export type RunBudgetMetric =
  | "modelRequests"
  | "inputTokens"
  | "outputTokens"
  | "toolCalls"
  | "networkRequests"
  | "retries"
  | "wallClockMs"
  | "childTasks";

export interface RunBudgetVector {
  modelRequests: number;
  inputTokens: number;
  outputTokens: number;
  toolCalls: number;
  networkRequests: number;
  retries: number;
  wallClockMs: number;
  childTasks: number;
}

export type RunBudgetUsageKind = "MODEL" | "TOOL" | "NETWORK" | "RETRY" | "WALL_CLOCK" | "OTHER" | "CHILD_ALLOCATION";

export interface RunBudgetUsageReceipt {
  schemaVersion: "toadaid.run-budget-usage.v1";
  receiptId: string;
  kind: RunBudgetUsageKind;
  occurredAt: string;
  invocationId?: string;
  sourceSha256?: string;
  delta: RunBudgetVector;
}

export interface RunBudgetChildAllocation {
  schemaVersion: "toadaid.run-budget-child-allocation.v1";
  allocationId: string;
  childBudgetId: string;
  childRunId: string;
  childTaskId?: string;
  allocatedAt: string;
  parentLedgerSha256Before: string;
  limits: RunBudgetVector;
  allocationSha256: string;
}

export interface RunBudgetParentBinding {
  parentBudgetId: string;
  allocationId: string;
  allocationSha256: string;
}

export interface RunBudgetContinuity {
  previousRecordSha256: string | null;
}

export interface RunBudgetLedgerRecord {
  schemaVersion: "toadaid.run-budget-ledger.v1";
  budgetId: string;
  runId: string;
  childTaskId?: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  limits: RunBudgetVector;
  parentBinding: RunBudgetParentBinding | null;
  usageReceipts: readonly RunBudgetUsageReceipt[];
  childAllocations: readonly RunBudgetChildAllocation[];
  continuity: RunBudgetContinuity;
}

export interface RunBudgetLedgerEnvelope {
  schemaVersion: "toadaid.run-budget-ledger-envelope.v1";
  record: RunBudgetLedgerRecord;
  recordSha256: string;
}

export interface CreateRunBudgetInput {
  budgetId?: string;
  runId: string;
  childTaskId?: string;
  createdAt?: string;
  limits: RunBudgetVector;
}

export interface RunBudgetRuntime {
  now?: () => Date;
  randomId?: () => string;
}

export interface RecordRunBudgetUsageInput {
  receiptId?: string;
  kind: Exclude<RunBudgetUsageKind, "CHILD_ALLOCATION">;
  occurredAt?: string;
  invocationId?: string;
  sourceSha256?: string;
  delta: RunBudgetVector;
}

export interface AllocateChildRunBudgetInput {
  allocationId?: string;
  childBudgetId?: string;
  childRunId: string;
  childTaskId?: string;
  allocatedAt?: string;
  limits: RunBudgetVector;
}

export interface AllocateChildRunBudgetResult {
  parent: RunBudgetLedgerEnvelope;
  allocation: RunBudgetChildAllocation;
  child: RunBudgetLedgerEnvelope;
}

export interface RunBudgetAvailabilityReceipt {
  schemaVersion: "toadaid.run-budget-availability.v1";
  budgetId: string;
  ledgerSha256: string;
  requested: RunBudgetVector;
  remainingBefore: RunBudgetVector;
  remainingAfter: RunBudgetVector;
  allowed: boolean;
  exceededMetrics: readonly RunBudgetMetric[];
}
