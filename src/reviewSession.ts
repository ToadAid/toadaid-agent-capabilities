import { randomUUID } from "node:crypto";

import {
  openCodeReviewPlanSha256,
} from "./openCodeReviewAdapter.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  OpenCodeReviewPlan,
} from "./openCodeReviewAdapter.js";
import type {
  CreateReviewPresentationStateInput,
  CreateReviewSessionInput,
  ResumeReviewSessionInput,
  ReviewPresentationState,
  ReviewRuntimeIdentity,
  ReviewSessionBinding,
  ReviewSessionEnvelope,
  ReviewSessionLineage,
  ReviewSessionRecord,
  ReviewSessionRuntime,
  ReviewSessionTransition,
} from "./reviewSessionTypes.js";

export type * from "./reviewSessionTypes.js";

const MAX_RUNTIME_IDENTITY_CHARS = 256;
const MAX_REVISION = 1_000_000;
const REVIEW_SESSION_TRANSITIONS: readonly ReviewSessionTransition[] = [
  "INITIAL",
  "RESUME_SAME_RUNTIME",
  "RESUME_RUNTIME_TRANSITION",
];

function exactRuntimeText(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_RUNTIME_IDENTITY_CHARS ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function normalizeRuntimeIdentity(
  provider: string,
  model: string,
): ReviewRuntimeIdentity {
  return Object.freeze({
    provider: exactRuntimeText(provider, "provider"),
    model: exactRuntimeText(model, "model"),
  });
}

function validatePlanIdentity(plan: OpenCodeReviewPlan): void {
  if (plan.schemaVersion !== "toadaid.open-code-review-plan.v1") {
    throw new TypeError("unsupported OpenCodeReview plan schemaVersion");
  }
  if (plan.ocrSchemaVersion !== "1") {
    throw new TypeError("unsupported OCR schemaVersion in review plan");
  }
  if (
    plan.mode !== "workspace" &&
    plan.mode !== "range" &&
    plan.mode !== "commit"
  ) {
    throw new TypeError("review plan mode is invalid");
  }
}

function bindingFromInput(
  plan: OpenCodeReviewPlan,
  repositoryIdentitySha256: string,
  reviewedSourceSha256: string,
  rulesSha256: string,
): ReviewSessionBinding {
  validatePlanIdentity(plan);
  return Object.freeze({
    repositoryIdentitySha256: sha(
      repositoryIdentitySha256,
      "repositoryIdentitySha256",
    )!,
    reviewedSourceSha256: sha(reviewedSourceSha256, "reviewedSourceSha256")!,
    rulesSha256: sha(rulesSha256, "rulesSha256")!,
    reviewMode: plan.mode,
    planSha256: openCodeReviewPlanSha256(plan),
  });
}

function normalizeBinding(binding: ReviewSessionBinding): ReviewSessionBinding {
  if (
    binding.reviewMode !== "workspace" &&
    binding.reviewMode !== "range" &&
    binding.reviewMode !== "commit"
  ) {
    throw new TypeError("review session mode is invalid");
  }
  return Object.freeze({
    repositoryIdentitySha256: sha(
      binding.repositoryIdentitySha256,
      "binding.repositoryIdentitySha256",
    )!,
    reviewedSourceSha256: sha(
      binding.reviewedSourceSha256,
      "binding.reviewedSourceSha256",
    )!,
    rulesSha256: sha(binding.rulesSha256, "binding.rulesSha256")!,
    reviewMode: binding.reviewMode,
    planSha256: sha(binding.planSha256, "binding.planSha256")!,
  });
}

function normalizeLineage(
  lineage: ReviewSessionLineage,
  transition: ReviewSessionTransition,
  runtime: ReviewRuntimeIdentity,
  revision: number,
  previousRecordSha256: string | null,
): ReviewSessionLineage {
  if (typeof lineage.runtimeChanged !== "boolean") {
    throw new TypeError("review session lineage.runtimeChanged must be boolean");
  }

  if (revision === 0) {
    if (
      transition !== "INITIAL" ||
      lineage.parentRecordSha256 !== null ||
      lineage.fromRuntime !== null ||
      lineage.runtimeChanged ||
      previousRecordSha256 !== null
    ) {
      throw new TypeError("initial review session lineage is invalid");
    }
  } else {
    if (transition === "INITIAL") {
      throw new TypeError("resumed review session cannot use INITIAL transition");
    }
    const parent = sha(
      lineage.parentRecordSha256,
      "lineage.parentRecordSha256",
    )!;
    const previous = sha(
      previousRecordSha256,
      "continuity.previousRecordSha256",
    )!;
    if (parent !== previous) {
      throw new Error("review session lineage/continuity predecessor mismatch");
    }
    if (lineage.fromRuntime === null) {
      throw new TypeError("resumed review session requires fromRuntime lineage");
    }
  }

  const fromRuntime =
    lineage.fromRuntime === null
      ? null
      : normalizeRuntimeIdentity(
          lineage.fromRuntime.provider,
          lineage.fromRuntime.model,
        );
  const toRuntime = normalizeRuntimeIdentity(
    lineage.toRuntime.provider,
    lineage.toRuntime.model,
  );

  if (
    toRuntime.provider !== runtime.provider ||
    toRuntime.model !== runtime.model
  ) {
    throw new Error("review session lineage target does not match runtime");
  }

  if (revision > 0 && fromRuntime !== null) {
    const changed =
      fromRuntime.provider !== toRuntime.provider ||
      fromRuntime.model !== toRuntime.model;
    if (lineage.runtimeChanged !== changed) {
      throw new Error("review session runtimeChanged lineage is inconsistent");
    }
    if (
      transition === "RESUME_RUNTIME_TRANSITION" &&
      !changed
    ) {
      throw new Error("runtime transition lineage did not change runtime");
    }
    if (
      transition === "RESUME_SAME_RUNTIME" &&
      changed
    ) {
      throw new Error("same-runtime lineage changed provider/model");
    }
  }

  return Object.freeze({
    parentRecordSha256:
      lineage.parentRecordSha256 === null
        ? null
        : sha(lineage.parentRecordSha256, "lineage.parentRecordSha256")!,
    fromRuntime,
    toRuntime,
    runtimeChanged: lineage.runtimeChanged,
  });
}

export function reviewSessionRecordSha256(record: ReviewSessionRecord): string {
  return sha256(record);
}

export function validateReviewSessionRecord(
  record: ReviewSessionRecord,
): ReviewSessionRecord {
  if (record.schemaVersion !== "toadaid.review-session.v1") {
    throw new TypeError("unsupported review session schemaVersion");
  }

  const sessionId = boundedId(record.sessionId, "sessionId");
  if (!REVIEW_SESSION_TRANSITIONS.includes(record.transition)) {
    throw new TypeError("review session transition is invalid");
  }
  if (
    !Number.isSafeInteger(record.revision) ||
    record.revision < 0 ||
    record.revision > MAX_REVISION
  ) {
    throw new RangeError("review session revision is invalid");
  }

  const binding = normalizeBinding(record.binding);
  const runtime = normalizeRuntimeIdentity(
    record.runtime.provider,
    record.runtime.model,
  );
  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RangeError("review session updatedAt is earlier than createdAt");
  }

  const previousRecordSha256 =
    record.continuity.previousRecordSha256 === null
      ? null
      : sha(
          record.continuity.previousRecordSha256,
          "continuity.previousRecordSha256",
        )!;

  const lineage = normalizeLineage(
    record.lineage,
    record.transition,
    runtime,
    record.revision,
    previousRecordSha256,
  );

  return Object.freeze({
    schemaVersion: "toadaid.review-session.v1",
    sessionId,
    revision: record.revision,
    binding,
    runtime,
    transition: record.transition,
    lineage,
    createdAt,
    updatedAt,
    continuity: Object.freeze({ previousRecordSha256 }),
  });
}

export function sealReviewSessionRecord(
  record: ReviewSessionRecord,
): ReviewSessionEnvelope {
  const normalized = validateReviewSessionRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.review-session-envelope.v1",
    record: normalized,
    recordSha256: reviewSessionRecordSha256(normalized),
  });
}

export function validateReviewSessionEnvelope(
  envelope: ReviewSessionEnvelope,
): ReviewSessionEnvelope {
  if (envelope.schemaVersion !== "toadaid.review-session-envelope.v1") {
    throw new TypeError("unsupported review session envelope schemaVersion");
  }
  const record = validateReviewSessionRecord(envelope.record);
  const digest = sha(envelope.recordSha256, "recordSha256")!;
  if (digest !== reviewSessionRecordSha256(record)) {
    throw new Error("review session integrity mismatch");
  }
  return Object.freeze({
    schemaVersion: "toadaid.review-session-envelope.v1",
    record,
    recordSha256: digest,
  });
}

export function assertReviewSessionPredecessor(
  previous: ReviewSessionEnvelope,
  next: ReviewSessionEnvelope,
): void {
  const canonicalPrevious = validateReviewSessionEnvelope(previous);
  const canonicalNext = validateReviewSessionEnvelope(next);

  if (canonicalNext.record.sessionId !== canonicalPrevious.record.sessionId) {
    throw new Error("review session predecessor sessionId mismatch");
  }
  if (canonicalNext.record.createdAt !== canonicalPrevious.record.createdAt) {
    throw new Error("review session predecessor createdAt mismatch");
  }
  if (canonicalNext.record.revision !== canonicalPrevious.record.revision + 1) {
    throw new Error("review session revision is not contiguous");
  }
  if (
    canonicalNext.record.continuity.previousRecordSha256 !==
    canonicalPrevious.recordSha256
  ) {
    throw new Error("review session predecessor digest mismatch");
  }
  if (
    canonicalNext.record.lineage.parentRecordSha256 !==
    canonicalPrevious.recordSha256
  ) {
    throw new Error("review session lineage parent digest mismatch");
  }
  if (
    sha256(canonicalNext.record.binding) !==
    sha256(canonicalPrevious.record.binding)
  ) {
    throw new Error("review session predecessor binding changed");
  }
  if (
    canonicalNext.record.lineage.fromRuntime === null ||
    canonicalNext.record.lineage.fromRuntime.provider !==
      canonicalPrevious.record.runtime.provider ||
    canonicalNext.record.lineage.fromRuntime.model !==
      canonicalPrevious.record.runtime.model
  ) {
    throw new Error("review session predecessor runtime lineage mismatch");
  }
  if (
    Date.parse(canonicalNext.record.updatedAt) <
    Date.parse(canonicalPrevious.record.updatedAt)
  ) {
    throw new RangeError("review session predecessor time moved backwards");
  }
}

function nowIso(
  value: string | undefined,
  label: string,
  runtime?: ReviewSessionRuntime,
): string {
  return canonicalIso(value, label, runtime?.now ?? (() => new Date()));
}

export function createReviewSession(
  input: CreateReviewSessionInput,
  runtime?: ReviewSessionRuntime,
): ReviewSessionEnvelope {
  const binding = bindingFromInput(
    input.plan,
    input.repositoryIdentitySha256,
    input.reviewedSourceSha256,
    input.rulesSha256,
  );
  const runtimeIdentity = normalizeRuntimeIdentity(input.provider, input.model);
  const createdAt = nowIso(input.createdAt, "createdAt", runtime);
  const sessionId = boundedId(
    input.sessionId ?? runtime?.randomId?.() ?? randomUUID(),
    "sessionId",
  );

  return sealReviewSessionRecord({
    schemaVersion: "toadaid.review-session.v1",
    sessionId,
    revision: 0,
    binding,
    runtime: runtimeIdentity,
    transition: "INITIAL",
    lineage: Object.freeze({
      parentRecordSha256: null,
      fromRuntime: null,
      toRuntime: runtimeIdentity,
      runtimeChanged: false,
    }),
    createdAt,
    updatedAt: createdAt,
    continuity: Object.freeze({ previousRecordSha256: null }),
  });
}

function assertResumeBinding(
  prior: ReviewSessionBinding,
  current: ReviewSessionBinding,
): void {
  if (
    prior.repositoryIdentitySha256 !== current.repositoryIdentitySha256
  ) {
    throw new Error("review repository identity changed; new session required");
  }
  if (prior.reviewedSourceSha256 !== current.reviewedSourceSha256) {
    throw new Error("reviewed source changed; new session required");
  }
  if (prior.rulesSha256 !== current.rulesSha256) {
    throw new Error("review rules/config changed; new session required");
  }
  if (prior.reviewMode !== current.reviewMode) {
    throw new Error("review mode changed; new session required");
  }
  if (prior.planSha256 !== current.planSha256) {
    throw new Error("R1 review plan changed; new session required");
  }
}

export function resumeReviewSession(
  envelope: ReviewSessionEnvelope,
  input: ResumeReviewSessionInput,
  runtime?: ReviewSessionRuntime,
): ReviewSessionEnvelope {
  const current = validateReviewSessionEnvelope(envelope);
  if (current.record.revision >= MAX_REVISION) {
    throw new RangeError("review session revision limit reached");
  }

  const binding = bindingFromInput(
    input.plan,
    input.repositoryIdentitySha256,
    input.reviewedSourceSha256,
    input.rulesSha256,
  );
  assertResumeBinding(current.record.binding, binding);

  const nextRuntime = normalizeRuntimeIdentity(input.provider, input.model);
  const runtimeChanged =
    current.record.runtime.provider !== nextRuntime.provider ||
    current.record.runtime.model !== nextRuntime.model;

  if (runtimeChanged && input.acceptRuntimeTransition !== true) {
    throw new Error(
      "provider/model changed; explicit runtime transition acceptance is required",
    );
  }

  const resumedAt = nowIso(input.resumedAt, "resumedAt", runtime);
  if (Date.parse(resumedAt) < Date.parse(current.record.updatedAt)) {
    throw new RangeError("resumedAt is earlier than current session updatedAt");
  }

  const resumed = sealReviewSessionRecord({
    schemaVersion: "toadaid.review-session.v1",
    sessionId: current.record.sessionId,
    revision: current.record.revision + 1,
    binding,
    runtime: nextRuntime,
    transition: runtimeChanged
      ? "RESUME_RUNTIME_TRANSITION"
      : "RESUME_SAME_RUNTIME",
    lineage: Object.freeze({
      parentRecordSha256: current.recordSha256,
      fromRuntime: current.record.runtime,
      toRuntime: nextRuntime,
      runtimeChanged,
    }),
    createdAt: current.record.createdAt,
    updatedAt: resumedAt,
    continuity: Object.freeze({
      previousRecordSha256: current.recordSha256,
    }),
  });
  assertReviewSessionPredecessor(current, resumed);
  return resumed;
}

export function createReviewPresentationState(
  envelope: ReviewSessionEnvelope,
  input: CreateReviewPresentationStateInput = {},
): ReviewPresentationState {
  const session = validateReviewSessionEnvelope(envelope);
  const selectedFindingId =
    input.selectedFindingId == null
      ? null
      : sha(input.selectedFindingId, "selectedFindingId")!;
  const hiddenFindingIds = Object.freeze(
    [...new Set(input.hiddenFindingIds ?? [])]
      .map((id) => sha(id, "hiddenFindingIds[]")!)
      .sort(),
  );

  return Object.freeze({
    schemaVersion: "toadaid.review-presentation-state.v1",
    sessionRecordSha256: session.recordSha256,
    selectedFindingId,
    hiddenFindingIds,
  });
}

export function serializeReviewSession(
  envelope: ReviewSessionEnvelope,
): string {
  return JSON.stringify(validateReviewSessionEnvelope(envelope));
}

export function parseReviewSession(serialized: string): ReviewSessionEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("review session envelope must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TypeError("review session envelope must be an object");
  }
  return validateReviewSessionEnvelope(parsed as ReviewSessionEnvelope);
}
