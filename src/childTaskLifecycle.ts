import { createHash } from "node:crypto";

import type { CapabilityAuthorityDecision, CapabilityEffectiveDecision } from "./capabilityPolicy.js";
import {
  assertRunStatePredecessor,
  resolveResumeCapabilityAuthority,
  validateRunStateCapsule,
  type RunResumeAuthorityDecision,
  type RunStateCapsule,
} from "./runStateCapsule.js";

export type ChildTaskStatus = "CREATED" | "RUNNING" | "BLOCKED" | "FAILED" | "COMPLETE";
export type ChildTaskTransitionKind = "START" | "CHECKPOINT" | "BLOCK" | "FAIL" | "RESUME" | "COMPLETE";

export interface ChildTaskContinuity {
  generation: number;
  transition: "CREATE" | ChildTaskTransitionKind;
  previousTaskSha256: string | null;
}

export interface ChildTaskRecord {
  schemaVersion: "toadaid.child-task.v1";
  childTaskId: string;
  parentRunId: string;
  parentChildTaskId: string | null;
  revision: number;
  createdAt: string;
  updatedAt: string;
  status: ChildTaskStatus;
  attempt: number;
  delegatedCapabilities: readonly string[];
  runState: RunStateCapsule;
  continuity: ChildTaskContinuity;
}

export interface ChildTaskEnvelope {
  schemaVersion: "toadaid.child-task-envelope.v1";
  task: ChildTaskRecord;
  taskSha256: string;
}

export interface CreateChildTaskInput {
  childTaskId: string;
  parentRunId: string;
  parentChildTaskId?: string | null;
  createdAt: string;
  delegatedCapabilities?: readonly string[];
  parentAuthority: readonly RunResumeAuthorityDecision[];
  runState: RunStateCapsule;
}

export interface ChildTaskTransition {
  kind: ChildTaskTransitionKind;
  updatedAt: string;
  runState: RunStateCapsule;
}

export type ChildTaskCapabilityReason =
  | "ALLOWED_BY_DELEGATION_PARENT_AND_CHILD"
  | "NOT_DELEGATED"
  | "UNKNOWN_IN_PARENT"
  | "BLOCKED_BY_PARENT"
  | "BLOCKED_BY_CHILD_RUN";

export interface ChildTaskCapabilityDecision {
  schemaVersion: "toadaid.child-task-authority.v1";
  capabilityId: string;
  decision: CapabilityEffectiveDecision;
  reason: ChildTaskCapabilityReason;
  delegated: boolean;
  parentDecision: CapabilityEffectiveDecision | null;
  childDecision: CapabilityEffectiveDecision | null;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_DELEGATED_CAPABILITIES = 256;

function assertId(value: string, label: string): string {
  if (!ID_PATTERN.test(value)) throw new TypeError(`${label} must match ${ID_PATTERN.source}`);
  return value;
}

function assertIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must not be empty`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function normalizeDelegatedCapabilities(values: readonly string[] | undefined): readonly string[] {
  const resolved = values ?? [];
  if (resolved.length > MAX_DELEGATED_CAPABILITIES) {
    throw new RangeError(`delegatedCapabilities exceeds ${MAX_DELEGATED_CAPABILITIES} items`);
  }
  const seen = new Set<string>();
  for (const capabilityId of resolved) {
    if (!CAPABILITY_ID_PATTERN.test(capabilityId)) throw new TypeError(`invalid delegated capability id: ${capabilityId}`);
    if (seen.has(capabilityId)) throw new TypeError(`duplicate delegated capability: ${capabilityId}`);
    seen.add(capabilityId);
  }
  return Object.freeze([...seen].sort());
}

function normalizeParentAuthority(
  authority: readonly RunResumeAuthorityDecision[],
): ReadonlyMap<string, RunResumeAuthorityDecision> {
  const map = new Map<string, RunResumeAuthorityDecision>();
  for (const decision of authority) {
    if (decision.schemaVersion !== "toadaid.run-resume-authority.v1") {
      throw new TypeError(`invalid parent authority schema: ${decision.capabilityId}`);
    }
    if (!CAPABILITY_ID_PATTERN.test(decision.capabilityId)) {
      throw new TypeError(`invalid parent authority capability id: ${decision.capabilityId}`);
    }
    if (map.has(decision.capabilityId)) throw new TypeError(`duplicate parent authority capability: ${decision.capabilityId}`);
    map.set(decision.capabilityId, Object.freeze({ ...decision }));
  }
  return map;
}

function assertDelegationBounded(
  delegatedCapabilities: readonly string[],
  parentAuthority: readonly RunResumeAuthorityDecision[],
): void {
  const parent = normalizeParentAuthority(parentAuthority);
  for (const capabilityId of delegatedCapabilities) {
    const decision = parent.get(capabilityId);
    if (!decision || decision.decision !== "ALLOW") {
      throw new Error(`cannot delegate capability not allowed by parent: ${capabilityId}`);
    }
  }
}

function assertChildRunStateAuthorityBounded(
  runState: RunStateCapsule,
  delegatedCapabilities: readonly string[],
): void {
  const delegated = new Set(delegatedCapabilities);
  for (const decision of runState.authoritySnapshot.decisions) {
    if (decision.decision === "ALLOW" && !delegated.has(decision.capabilityId)) {
      throw new Error(`child run-state ALLOW is outside delegated authority: ${decision.capabilityId}`);
    }
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("child task contains a non-serializable value");
}

function freezeTask(task: ChildTaskRecord): ChildTaskRecord {
  return Object.freeze({
    ...task,
    delegatedCapabilities: Object.freeze([...task.delegatedCapabilities]),
    runState: validateRunStateCapsule(task.runState),
    continuity: Object.freeze({ ...task.continuity }),
  });
}

function assertLifecycleStateAlignment(status: ChildTaskStatus, runState: RunStateCapsule): void {
  if ((status === "CREATED" || status === "RUNNING") && runState.objective.status !== "ACTIVE") {
    throw new Error(`${status} child task requires ACTIVE child objective`);
  }
  if (status === "BLOCKED" && runState.objective.status !== "BLOCKED") {
    throw new Error("BLOCKED child task requires BLOCKED child objective");
  }
  if (status === "COMPLETE" && runState.objective.status !== "COMPLETE") {
    throw new Error("COMPLETE child task requires COMPLETE child objective");
  }
  if (status === "FAILED" && runState.objective.status === "COMPLETE") {
    throw new Error("FAILED child task cannot carry COMPLETE child objective");
  }
}

function normalizeTask(task: ChildTaskRecord): ChildTaskRecord {
  if (task.schemaVersion !== "toadaid.child-task.v1") throw new TypeError("invalid child-task schema");
  const childTaskId = assertId(task.childTaskId, "childTaskId");
  const parentRunId = assertId(task.parentRunId, "parentRunId");
  const parentChildTaskId = task.parentChildTaskId === null ? null : assertId(task.parentChildTaskId, "parentChildTaskId");
  if (parentChildTaskId === childTaskId) throw new TypeError("child task cannot be its own parent");
  if (parentRunId === childTaskId) throw new TypeError("childTaskId must differ from parentRunId");
  if (!Number.isInteger(task.revision) || task.revision < 0) throw new TypeError("child-task revision must be a non-negative integer");
  if (!Number.isInteger(task.attempt) || task.attempt < 0) throw new TypeError("child-task attempt must be a non-negative integer");
  const createdAt = assertIsoTimestamp(task.createdAt, "createdAt");
  const updatedAt = assertIsoTimestamp(task.updatedAt, "updatedAt");
  if (new Date(updatedAt).getTime() < new Date(createdAt).getTime()) throw new TypeError("updatedAt cannot precede createdAt");
  const statuses: readonly ChildTaskStatus[] = ["CREATED", "RUNNING", "BLOCKED", "FAILED", "COMPLETE"];
  if (!statuses.includes(task.status)) throw new TypeError(`invalid child-task status: ${String(task.status)}`);
  if (!task.continuity || !Number.isInteger(task.continuity.generation) || task.continuity.generation < 0) {
    throw new TypeError("child-task continuity generation must be a non-negative integer");
  }
  if (task.continuity.generation !== task.revision) throw new TypeError("child-task continuity generation must equal revision");
  if (task.revision === 0) {
    if (task.continuity.transition !== "CREATE") throw new TypeError("revision 0 child task must use CREATE continuity");
    if (task.continuity.previousTaskSha256 !== null) throw new TypeError("initial child task cannot have a predecessor digest");
  } else {
    if (task.continuity.transition === "CREATE") throw new TypeError("non-initial child task cannot use CREATE continuity");
    if (typeof task.continuity.previousTaskSha256 !== "string" || !SHA256_PATTERN.test(task.continuity.previousTaskSha256)) {
      throw new TypeError("non-initial child task requires previousTaskSha256");
    }
  }
  const delegatedCapabilities = normalizeDelegatedCapabilities(task.delegatedCapabilities);
  const runState = validateRunStateCapsule(task.runState);
  if (runState.runId !== childTaskId) throw new Error("child run-state runId must equal childTaskId");
  assertChildRunStateAuthorityBounded(runState, delegatedCapabilities);
  assertLifecycleStateAlignment(task.status, runState);
  return freezeTask({
    ...task,
    childTaskId,
    parentRunId,
    parentChildTaskId,
    createdAt,
    updatedAt,
    delegatedCapabilities,
    runState,
  });
}

export function createChildTask(input: CreateChildTaskInput): ChildTaskRecord {
  const childTaskId = assertId(input.childTaskId, "childTaskId");
  const parentRunId = assertId(input.parentRunId, "parentRunId");
  const parentChildTaskId = input.parentChildTaskId === undefined || input.parentChildTaskId === null
    ? null
    : assertId(input.parentChildTaskId, "parentChildTaskId");
  if (parentChildTaskId === childTaskId) throw new TypeError("child task cannot be its own parent");
  if (parentRunId === childTaskId) throw new TypeError("childTaskId must differ from parentRunId");
  const createdAt = assertIsoTimestamp(input.createdAt, "createdAt");
  const delegatedCapabilities = normalizeDelegatedCapabilities(input.delegatedCapabilities);
  assertDelegationBounded(delegatedCapabilities, input.parentAuthority);
  const runState = validateRunStateCapsule(input.runState);
  if (runState.runId !== childTaskId) throw new Error("child run-state runId must equal childTaskId");
  if (runState.revision !== 0) throw new Error("new child task requires an initial run-state capsule");
  if (runState.createdAt !== createdAt) throw new Error("child task and child run-state createdAt must match");
  assertChildRunStateAuthorityBounded(runState, delegatedCapabilities);
  if (runState.objective.status !== "ACTIVE") throw new Error("new child task requires ACTIVE child objective");

  return freezeTask({
    schemaVersion: "toadaid.child-task.v1",
    childTaskId,
    parentRunId,
    parentChildTaskId,
    revision: 0,
    createdAt,
    updatedAt: createdAt,
    status: "CREATED",
    attempt: 0,
    delegatedCapabilities,
    runState,
    continuity: Object.freeze({ generation: 0, transition: "CREATE", previousTaskSha256: null }),
  });
}

export function canonicalChildTask(task: ChildTaskRecord): string {
  return canonicalJson(normalizeTask(task));
}

export function childTaskSha256(task: ChildTaskRecord): string {
  return createHash("sha256").update(canonicalChildTask(task)).digest("hex");
}

export function sealChildTask(task: ChildTaskRecord): ChildTaskEnvelope {
  const canonical = normalizeTask(task);
  return Object.freeze({
    schemaVersion: "toadaid.child-task-envelope.v1",
    task: canonical,
    taskSha256: childTaskSha256(canonical),
  });
}

export function serializeChildTask(task: ChildTaskRecord): string {
  return JSON.stringify(sealChildTask(task));
}

export function parseChildTask(serialized: string): ChildTaskRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("child-task envelope must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new TypeError("child-task envelope must be an object");
  const envelope = parsed as Record<string, unknown>;
  if (envelope.schemaVersion !== "toadaid.child-task-envelope.v1") throw new TypeError("invalid child-task envelope schema");
  if (typeof envelope.taskSha256 !== "string" || !SHA256_PATTERN.test(envelope.taskSha256)) {
    throw new TypeError("child-task envelope taskSha256 is invalid");
  }
  const task = normalizeTask(envelope.task as ChildTaskRecord);
  if (childTaskSha256(task) !== envelope.taskSha256) throw new Error("child-task integrity mismatch");
  return task;
}

function nextStatus(current: ChildTaskStatus, kind: ChildTaskTransitionKind): ChildTaskStatus {
  if (current === "CREATED" && kind === "START") return "RUNNING";
  if (current === "RUNNING" && kind === "CHECKPOINT") return "RUNNING";
  if (current === "RUNNING" && kind === "BLOCK") return "BLOCKED";
  if (current === "RUNNING" && kind === "FAIL") return "FAILED";
  if ((current === "BLOCKED" || current === "FAILED") && kind === "RESUME") return "RUNNING";
  if (current === "RUNNING" && kind === "COMPLETE") return "COMPLETE";
  throw new Error(`invalid child-task transition: ${current} -> ${kind}`);
}

export function transitionChildTask(previous: ChildTaskRecord, transition: ChildTaskTransition): ChildTaskRecord {
  const canonicalPrevious = normalizeTask(previous);
  const updatedAt = assertIsoTimestamp(transition.updatedAt, "updatedAt");
  if (new Date(updatedAt).getTime() < new Date(canonicalPrevious.updatedAt).getTime()) {
    throw new TypeError("child-task updatedAt cannot move backwards");
  }
  const runState = validateRunStateCapsule(transition.runState);
  assertRunStatePredecessor(canonicalPrevious.runState, runState);
  if (runState.runId !== canonicalPrevious.childTaskId) throw new Error("child run-state runId changed");
  assertChildRunStateAuthorityBounded(runState, canonicalPrevious.delegatedCapabilities);
  const status = nextStatus(canonicalPrevious.status, transition.kind);

  if ((transition.kind === "START" || transition.kind === "RESUME" || transition.kind === "CHECKPOINT") && runState.objective.status !== "ACTIVE") {
    throw new Error(`${transition.kind} requires ACTIVE child objective`);
  }
  if (transition.kind === "BLOCK" && runState.objective.status !== "BLOCKED") {
    throw new Error("BLOCK transition requires BLOCKED child objective");
  }
  if (transition.kind === "COMPLETE" && runState.objective.status !== "COMPLETE") {
    throw new Error("COMPLETE transition requires COMPLETE child objective");
  }

  return freezeTask({
    ...canonicalPrevious,
    revision: canonicalPrevious.revision + 1,
    updatedAt,
    status,
    attempt: canonicalPrevious.attempt + (transition.kind === "START" || transition.kind === "RESUME" ? 1 : 0),
    runState,
    continuity: Object.freeze({
      generation: canonicalPrevious.continuity.generation + 1,
      transition: transition.kind,
      previousTaskSha256: childTaskSha256(canonicalPrevious),
    }),
  });
}

export function assertChildTaskPredecessor(previous: ChildTaskRecord, next: ChildTaskRecord): void {
  const canonicalPrevious = normalizeTask(previous);
  const canonicalNext = normalizeTask(next);
  if (canonicalNext.childTaskId !== canonicalPrevious.childTaskId) throw new Error("child-task predecessor childTaskId mismatch");
  if (canonicalNext.parentRunId !== canonicalPrevious.parentRunId) throw new Error("child-task predecessor parentRunId mismatch");
  if (canonicalNext.parentChildTaskId !== canonicalPrevious.parentChildTaskId) throw new Error("child-task predecessor parentChildTaskId mismatch");
  if (canonicalNext.createdAt !== canonicalPrevious.createdAt) throw new Error("child-task predecessor createdAt mismatch");
  if (canonicalNext.revision !== canonicalPrevious.revision + 1) throw new Error("child-task revision is not contiguous");
  if (canonicalNext.continuity.generation !== canonicalPrevious.continuity.generation + 1) {
    throw new Error("child-task continuity generation is not contiguous");
  }
  if (canonicalNext.continuity.previousTaskSha256 !== childTaskSha256(canonicalPrevious)) {
    throw new Error("child-task predecessor digest mismatch");
  }
  if (canonicalJson(canonicalNext.delegatedCapabilities) !== canonicalJson(canonicalPrevious.delegatedCapabilities)) {
    throw new Error("child-task continuity cannot widen delegated capabilities");
  }
  assertRunStatePredecessor(canonicalPrevious.runState, canonicalNext.runState);
}

export function resolveChildTaskCapabilityAuthority(
  capabilityId: string,
  task: ChildTaskRecord,
  currentParentAuthority: readonly RunResumeAuthorityDecision[],
  currentChildAuthority: readonly CapabilityAuthorityDecision[],
): ChildTaskCapabilityDecision {
  if (!CAPABILITY_ID_PATTERN.test(capabilityId)) throw new TypeError(`invalid capabilityId: ${capabilityId}`);
  const canonical = normalizeTask(task);
  const delegated = canonical.delegatedCapabilities.includes(capabilityId);
  if (!delegated) {
    return Object.freeze({
      schemaVersion: "toadaid.child-task-authority.v1",
      capabilityId,
      decision: "BLOCK",
      reason: "NOT_DELEGATED",
      delegated: false,
      parentDecision: null,
      childDecision: null,
    });
  }

  const parentMap = normalizeParentAuthority(currentParentAuthority);
  const parent = parentMap.get(capabilityId);
  if (!parent) {
    return Object.freeze({
      schemaVersion: "toadaid.child-task-authority.v1",
      capabilityId,
      decision: "BLOCK",
      reason: "UNKNOWN_IN_PARENT",
      delegated: true,
      parentDecision: null,
      childDecision: null,
    });
  }
  if (parent.decision !== "ALLOW") {
    return Object.freeze({
      schemaVersion: "toadaid.child-task-authority.v1",
      capabilityId,
      decision: "BLOCK",
      reason: "BLOCKED_BY_PARENT",
      delegated: true,
      parentDecision: parent.decision,
      childDecision: null,
    });
  }

  const child = resolveResumeCapabilityAuthority(capabilityId, canonical.runState, currentChildAuthority);
  if (child.decision !== "ALLOW") {
    return Object.freeze({
      schemaVersion: "toadaid.child-task-authority.v1",
      capabilityId,
      decision: "BLOCK",
      reason: "BLOCKED_BY_CHILD_RUN",
      delegated: true,
      parentDecision: parent.decision,
      childDecision: child.decision,
    });
  }

  return Object.freeze({
    schemaVersion: "toadaid.child-task-authority.v1",
    capabilityId,
    decision: "ALLOW",
    reason: "ALLOWED_BY_DELEGATION_PARENT_AND_CHILD",
    delegated: true,
    parentDecision: parent.decision,
    childDecision: child.decision,
  });
}
