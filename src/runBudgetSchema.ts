import { createHash } from "node:crypto";
import type {
  RunBudgetMetric,
  RunBudgetUsageReceipt,
  RunBudgetVector,
} from "./runBudgetTypes.js";

export const RUN_BUDGET_METRICS: readonly RunBudgetMetric[] = Object.freeze([
  "modelRequests",
  "inputTokens",
  "outputTokens",
  "toolCalls",
  "networkRequests",
  "retries",
  "wallClockMs",
  "childTasks",
]);

export const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_COUNTER = Number.MAX_SAFE_INTEGER;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      const item = input[key];
      if (item !== undefined) output[key] = canonicalize(item);
    }
    return output;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function boundedId(value: string, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function optionalSha(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (!SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be SHA-256 hex`);
  return value;
}

export function requiredSha(value: string, label: string): string {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be SHA-256 hex`);
  return value;
}

export function canonicalIso(value: string | undefined, label: string, now: () => Date): string {
  const candidate = value ?? now().toISOString();
  if (typeof candidate !== "string" || !candidate.trim()) throw new TypeError(`${label} must be ISO-8601`);
  const parsed = new Date(candidate);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== candidate) throw new TypeError(`${label} must be canonical ISO-8601`);
  return candidate;
}

function counter(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COUNTER) throw new TypeError(`${label} must be a non-negative safe integer`);
  return value;
}

export function normalizeRunBudgetVector(input: RunBudgetVector, label = "budget"): RunBudgetVector {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new TypeError(`${label} must be an object`);
  const output = {
    modelRequests: counter(input.modelRequests, `${label}.modelRequests`),
    inputTokens: counter(input.inputTokens, `${label}.inputTokens`),
    outputTokens: counter(input.outputTokens, `${label}.outputTokens`),
    toolCalls: counter(input.toolCalls, `${label}.toolCalls`),
    networkRequests: counter(input.networkRequests, `${label}.networkRequests`),
    retries: counter(input.retries, `${label}.retries`),
    wallClockMs: counter(input.wallClockMs, `${label}.wallClockMs`),
    childTasks: counter(input.childTasks, `${label}.childTasks`),
  } satisfies RunBudgetVector;
  return Object.freeze(output);
}

export function zeroRunBudgetVector(): RunBudgetVector {
  return Object.freeze({
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 0,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 0,
    childTasks: 0,
  });
}

export function addRunBudgetVectors(a: RunBudgetVector, b: RunBudgetVector, label = "budget sum"): RunBudgetVector {
  const out = {} as Record<RunBudgetMetric, number>;
  for (const metric of RUN_BUDGET_METRICS) {
    const value = a[metric] + b[metric];
    if (!Number.isSafeInteger(value) || value > MAX_COUNTER) throw new RangeError(`${label}.${metric} exceeds safe integer range`);
    out[metric] = value;
  }
  return Object.freeze(out as unknown as RunBudgetVector);
}

export function subtractRunBudgetVectors(a: RunBudgetVector, b: RunBudgetVector): RunBudgetVector {
  const out = {} as Record<RunBudgetMetric, number>;
  for (const metric of RUN_BUDGET_METRICS) out[metric] = Math.max(0, a[metric] - b[metric]);
  return Object.freeze(out as unknown as RunBudgetVector);
}

export function runBudgetVectorIsZero(value: RunBudgetVector): boolean {
  return RUN_BUDGET_METRICS.every((metric) => value[metric] === 0);
}

export function sumUsage(receipts: readonly RunBudgetUsageReceipt[]): RunBudgetVector {
  let total = zeroRunBudgetVector();
  for (const receipt of receipts) total = addRunBudgetVectors(total, receipt.delta, "usage total");
  return total;
}
