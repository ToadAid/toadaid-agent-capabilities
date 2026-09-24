import { createHash } from "node:crypto";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import type { WorkspaceDiffReceipt, WorkspaceSnapshot } from "./workspaceTimeTravel.js";

export type OpenCodeReviewMode = "workspace" | "range" | "commit";
export type ReviewCoverageDisposition = "PENDING" | "REVIEWED" | "SKIPPED";
export type ReviewFindingCategory =
  | "bug"
  | "security"
  | "performance"
  | "maintainability"
  | "test"
  | "style"
  | "documentation"
  | "other";
export type ReviewFindingSeverity = "critical" | "high" | "medium" | "low";

export interface OcrDelegatePreviewFile {
  path: string;
  status: string;
  insertions: number;
  deletions: number;
  excludeReason?: string;
}

export interface OcrDelegatePreview {
  schemaVersion: "1";
  mode: OpenCodeReviewMode;
  repository: string;
  from?: string;
  to?: string;
  commit?: string;
  mergeBase?: string;
  background?: string;
  totalFiles: number;
  reviewableCount: number;
  excludedCount: number;
  totalInsertions: number;
  totalDeletions: number;
  reviewableFiles: readonly OcrDelegatePreviewFile[];
  excludedFiles: readonly OcrDelegatePreviewFile[];
}

export interface OcrDelegateRuleGroup {
  groupId: number;
  source: string;
  pattern: string;
  files: readonly string[];
  rule: string;
}

export interface OcrDelegateRules {
  schemaVersion: "1";
  groups: readonly OcrDelegateRuleGroup[];
}

export type OpenCodeReviewTarget =
  | { mode: "workspace" }
  | { mode: "range"; from: string; to: string }
  | { mode: "commit"; commit: string };

export interface OcrArgvInvocation {
  executable: "ocr";
  args: readonly string[];
}

export interface ReviewChecklistEntry {
  key: string;
  path: string;
  status: string;
  insertions: number;
  deletions: number;
  ruleGroupId: number;
}

export interface ReviewBatch {
  batchId: string;
  ruleGroupId: number;
  ruleSource: string;
  rulePattern: string;
  rule: string;
  changeLines: number;
  files: readonly ReviewChecklistEntry[];
}

export interface ReviewChildTaskSpec {
  taskId: string;
  role: "REVIEWER" | "REFLECTION";
  objective: string;
  phase: string;
  delegatedCapabilities: readonly ["review:inspect"];
  batchIds: readonly string[];
}

export interface OpenCodeReviewPlan {
  schemaVersion: "toadaid.open-code-review-plan.v1";
  ocrSchemaVersion: "1";
  mode: OpenCodeReviewMode;
  repository: string;
  target: OpenCodeReviewTarget;
  reviewSurfaceSha256: string;
  checklist: readonly ReviewChecklistEntry[];
  batches: readonly ReviewBatch[];
  childTasks: readonly ReviewChildTaskSpec[];
}

export interface CreateOpenCodeReviewPlanOptions {
  maxFilesPerBatch?: number;
  maxChangeLinesPerBatch?: number;
}

export interface ReviewFindingInput {
  content: string;
  startLine?: number;
  endLine?: number;
  category?: ReviewFindingCategory;
  severity?: ReviewFindingSeverity;
}

export interface ReviewFinding extends ReviewFindingInput {
  findingId: string;
  fileKey: string;
  path: string;
}

export interface ReviewCoverageEntry extends ReviewChecklistEntry {
  disposition: ReviewCoverageDisposition;
  skipReason?: string;
  findings: readonly ReviewFinding[];
}

export interface ReviewCoverageState {
  schemaVersion: "toadaid.open-code-review-coverage-state.v1";
  planSha256: string;
  entries: readonly ReviewCoverageEntry[];
}

export interface OpenCodeReviewReceipt {
  schemaVersion: "toadaid.open-code-review-receipt.v1";
  completedAt: string;
  planSha256: string;
  reviewSurfaceSha256: string;
  totalFiles: number;
  reviewedFiles: number;
  skippedFiles: number;
  coverageRate: number;
  findings: readonly ReviewFinding[];
  skipped: readonly { key: string; path: string; status: string; reason: string }[];
}

export interface ReviewReflectionPacket {
  schemaVersion: "toadaid.open-code-review-reflection.v1";
  reviewReceiptSha256: string;
  totalFiles: number;
  findingCount: number;
  findings: readonly ReviewFinding[];
}

export interface ReviewFixAuthorityBundle {
  reviewFix: CapabilityAuthorityDecision;
  workspaceSnapshot: CapabilityAuthorityDecision;
  workspaceDiff: CapabilityAuthorityDecision;
}

export interface ReviewFixBridge {
  snapshot(label: "before" | "after"): Promise<WorkspaceSnapshot>;
  apply(findings: readonly ReviewFinding[]): Promise<void>;
  diff(before: WorkspaceSnapshot, after: WorkspaceSnapshot): Promise<WorkspaceDiffReceipt>;
}

export interface ReviewFixRequest {
  completedAt: string;
  receipt: OpenCodeReviewReceipt;
  findingIds: readonly string[];
}

export interface ReviewFixReceipt {
  schemaVersion: "toadaid.open-code-review-fix-receipt.v1";
  completedAt: string;
  reviewReceiptSha256: string;
  findingIds: readonly string[];
  beforeSnapshotId: string;
  afterSnapshotId: string;
  diff: WorkspaceDiffReceipt;
}

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_FILES = 20_000;
const MAX_PATH_CHARS = 2_048;
const MAX_RULE_CHARS = 200_000;
const MAX_RULE_GROUPS = 20_000;
const MAX_FINDING_CONTENT = 8_000;
const DEFAULT_MAX_FILES_PER_BATCH = 10;
const DEFAULT_MAX_CHANGE_LINES_PER_BATCH = 2_000;
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const STATUS_PATTERN = /^[A-Z][A-Z0-9_-]{0,63}$/;

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, label: string, maximum = MAX_PATH_CHARS): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${label} must not be empty`);
  if (normalized.length > maximum) throw new RangeError(`${label} exceeds ${maximum} characters`);
  return normalized;
}

function optionalString(value: unknown, label: string, maximum = MAX_PATH_CHARS): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return stringValue(value, label, maximum);
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function positiveInteger(value: number | undefined, fallback: number, label: string, max: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > max) {
    throw new RangeError(`${label} must be an integer between 1 and ${max}`);
  }
  return resolved;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("value is not canonically serializable");
}

function sha256(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

function parseJson(raw: string, label: string): unknown {
  if (typeof raw !== "string") throw new TypeError(`${label} must be a string`);
  if (Buffer.byteLength(raw, "utf8") > MAX_JSON_BYTES) throw new RangeError(`${label} exceeds ${MAX_JSON_BYTES} bytes`);
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new TypeError(`${label} must contain valid JSON`);
  }
}

function safeRelativePath(value: unknown, label: string): string {
  const path = stringValue(value, label);
  if (path.includes("\0")) throw new TypeError(`${label} contains a NUL byte`);
  if (path.startsWith("/") || path.startsWith("\\") || /^[A-Za-z]:[\\/]/.test(path)) throw new TypeError(`${label} must be repository-relative`);
  const parts = path.replace(/\\/g, "/").split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) throw new TypeError(`${label} contains an unsafe path segment`);
  return parts.join("/");
}

function normalizePreviewFile(value: unknown, label: string, excluded: boolean): OcrDelegatePreviewFile {
  const raw = objectValue(value, label);
  const status = stringValue(raw.status, `${label}.status`, 64);
  if (!STATUS_PATTERN.test(status)) throw new TypeError(`${label}.status is invalid`);
  const excludeReason = optionalString(raw.exclude_reason, `${label}.exclude_reason`, 1_000);
  if (excluded && !excludeReason) throw new TypeError(`${label}.exclude_reason is required for excluded files`);
  return Object.freeze({
    path: safeRelativePath(raw.path, `${label}.path`),
    status,
    insertions: nonNegativeInteger(raw.insertions, `${label}.insertions`),
    deletions: nonNegativeInteger(raw.deletions, `${label}.deletions`),
    ...(excludeReason === undefined ? {} : { excludeReason }),
  });
}

function normalizeRef(value: string, label: string): string {
  if (!REF_PATTERN.test(value) || value.includes("..") || value.includes("@{") || value.startsWith("-")) {
    throw new TypeError(`${label} is not an accepted Git ref`);
  }
  return value;
}

function normalizeTarget(target: OpenCodeReviewTarget): OpenCodeReviewTarget {
  if (target.mode === "workspace") return Object.freeze({ mode: "workspace" });
  if (target.mode === "range") return Object.freeze({ mode: "range", from: normalizeRef(target.from, "target.from"), to: normalizeRef(target.to, "target.to") });
  return Object.freeze({ mode: "commit", commit: normalizeRef(target.commit, "target.commit") });
}

function targetFromPreview(preview: OcrDelegatePreview): OpenCodeReviewTarget {
  if (preview.mode === "workspace") return { mode: "workspace" };
  if (preview.mode === "range") {
    if (!preview.from || !preview.to) throw new TypeError("range preview requires from and to");
    return normalizeTarget({ mode: "range", from: preview.from, to: preview.to });
  }
  if (!preview.commit) throw new TypeError("commit preview requires commit");
  return normalizeTarget({ mode: "commit", commit: preview.commit });
}

export function parseOcrDelegatePreviewJson(raw: string): OcrDelegatePreview {
  const value = objectValue(parseJson(raw, "OCR preview JSON"), "OCR preview");
  if (value.schema_version !== "1") throw new TypeError("unsupported OCR delegate preview schema_version");
  const mode = value.mode;
  if (mode !== "workspace" && mode !== "range" && mode !== "commit") throw new TypeError("OCR preview mode is invalid");
  const reviewableRaw = value.reviewable_files;
  const excludedRaw = value.excluded_files;
  if (!Array.isArray(reviewableRaw) || !Array.isArray(excludedRaw)) throw new TypeError("OCR preview file lists must be arrays");
  if (reviewableRaw.length > MAX_FILES || excludedRaw.length > MAX_FILES) throw new RangeError("OCR preview exceeds file-count bound");
  const reviewableFiles = reviewableRaw.map((entry, index) => normalizePreviewFile(entry, `reviewable_files[${index}]`, false));
  const excludedFiles = excludedRaw.map((entry, index) => normalizePreviewFile(entry, `excluded_files[${index}]`, true));
  const reviewableCount = nonNegativeInteger(value.reviewable_count, "reviewable_count");
  const excludedCount = nonNegativeInteger(value.excluded_count, "excluded_count");
  const totalFiles = nonNegativeInteger(value.total_files, "total_files");
  if (reviewableCount !== reviewableFiles.length) throw new TypeError("reviewable_count does not match reviewable_files length");
  if (excludedCount !== excludedFiles.length) throw new TypeError("excluded_count does not match excluded_files length");
  if (totalFiles !== reviewableCount + excludedCount) throw new TypeError("total_files does not match reviewable + excluded counts");
  const identities = new Set<string>();
  for (const entry of reviewableFiles) {
    const identity = `${entry.path}\0${entry.status}`;
    if (identities.has(identity)) throw new TypeError(`duplicate OCR reviewable file identity: ${entry.path} [${entry.status}]`);
    identities.add(identity);
  }
  const from = optionalString(value.from, "from", 256);
  const to = optionalString(value.to, "to", 256);
  const commit = optionalString(value.commit, "commit", 256);
  const mergeBase = optionalString(value.merge_base, "merge_base", 256);
  const background = optionalString(value.background, "background", 8_000);
  const preview: OcrDelegatePreview = Object.freeze({
    schemaVersion: "1",
    mode,
    repository: stringValue(value.repository, "repository"),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
    ...(commit === undefined ? {} : { commit }),
    ...(mergeBase === undefined ? {} : { mergeBase }),
    ...(background === undefined ? {} : { background }),
    totalFiles,
    reviewableCount,
    excludedCount,
    totalInsertions: nonNegativeInteger(value.total_insertions, "total_insertions"),
    totalDeletions: nonNegativeInteger(value.total_deletions, "total_deletions"),
    reviewableFiles: Object.freeze(reviewableFiles),
    excludedFiles: Object.freeze(excludedFiles),
  });
  targetFromPreview(preview);
  return preview;
}

export function parseOcrDelegateRulesJson(raw: string): OcrDelegateRules {
  const value = objectValue(parseJson(raw, "OCR rules JSON"), "OCR rules");
  if (value.schema_version !== "1") throw new TypeError("unsupported OCR delegate rule schema_version");
  if (!Array.isArray(value.groups)) throw new TypeError("OCR rule groups must be an array");
  if (value.groups.length > MAX_RULE_GROUPS) throw new RangeError("OCR rule groups exceed bound");
  const groupIds = new Set<number>();
  const assignedPaths = new Set<string>();
  const groups = value.groups.map((entry, index) => {
    const rawGroup = objectValue(entry, `groups[${index}]`);
    const groupId = nonNegativeInteger(rawGroup.group_id, `groups[${index}].group_id`);
    if (groupIds.has(groupId)) throw new TypeError(`duplicate OCR rule group_id: ${groupId}`);
    groupIds.add(groupId);
    if (!Array.isArray(rawGroup.files)) throw new TypeError(`groups[${index}].files must be an array`);
    const files = rawGroup.files.map((path, fileIndex) => safeRelativePath(path, `groups[${index}].files[${fileIndex}]`));
    if (files.length === 0) throw new TypeError(`groups[${index}] must contain at least one file`);
    for (const path of files) {
      if (assignedPaths.has(path)) throw new TypeError(`OCR rule path appears in more than one group: ${path}`);
      assignedPaths.add(path);
    }
    return Object.freeze({
      groupId,
      source: stringValue(rawGroup.source, `groups[${index}].source`, 1_000),
      pattern: stringValue(rawGroup.pattern, `groups[${index}].pattern`, 2_000),
      files: Object.freeze(files),
      rule: stringValue(rawGroup.rule, `groups[${index}].rule`, MAX_RULE_CHARS),
    });
  });
  return Object.freeze({ schemaVersion: "1", groups: Object.freeze(groups.sort((a, b) => a.groupId - b.groupId)) });
}

export function buildOcrDelegatePreviewInvocation(target: OpenCodeReviewTarget): OcrArgvInvocation {
  const normalized = normalizeTarget(target);
  const args = ["delegate", "preview", "--format", "json"];
  if (normalized.mode === "range") args.push("--from", normalized.from, "--to", normalized.to);
  if (normalized.mode === "commit") args.push("--commit", normalized.commit);
  return Object.freeze({ executable: "ocr", args: Object.freeze(args) });
}

export function buildOcrDelegateRuleInvocations(paths: readonly string[], maxPathsPerCall = 100): readonly OcrArgvInvocation[] {
  const maximum = positiveInteger(maxPathsPerCall, 100, "maxPathsPerCall", 500);
  const normalized = paths.map((path, index) => safeRelativePath(path, `paths[${index}]`));
  if (normalized.length === 0) throw new TypeError("at least one rule path is required");
  const unique = [...new Set(normalized)];
  const invocations: OcrArgvInvocation[] = [];
  for (let index = 0; index < unique.length; index += maximum) {
    invocations.push(Object.freeze({ executable: "ocr", args: Object.freeze(["delegate", "rule", "--format", "json", "--", ...unique.slice(index, index + maximum)]) }));
  }
  return Object.freeze(invocations);
}

function assertAuthority(authority: CapabilityAuthorityDecision, capabilityId: string): void {
  if (authority.schemaVersion !== "toadaid.capability-authority-decision.v1" || authority.capabilityId !== capabilityId || !authority.installed || authority.decision !== "ALLOW") {
    throw new Error(`capability is not authorized for this operation: ${capabilityId}`);
  }
}

function checklistKey(path: string, status: string): string {
  return sha256(`${path}\0${status}`);
}

export function createOpenCodeReviewPlan(
  authority: CapabilityAuthorityDecision,
  preview: OcrDelegatePreview,
  rules: OcrDelegateRules,
  options: CreateOpenCodeReviewPlanOptions = {},
): OpenCodeReviewPlan {
  assertAuthority(authority, "review:inspect");
  const maxFiles = positiveInteger(options.maxFilesPerBatch, DEFAULT_MAX_FILES_PER_BATCH, "maxFilesPerBatch", 50);
  const maxLines = positiveInteger(options.maxChangeLinesPerBatch, DEFAULT_MAX_CHANGE_LINES_PER_BATCH, "maxChangeLinesPerBatch", 100_000);
  const target = targetFromPreview(preview);
  const reviewablePaths = new Set(preview.reviewableFiles.map((entry) => entry.path));
  const ruleByPath = new Map<string, OcrDelegateRuleGroup>();
  for (const group of rules.groups) {
    for (const path of group.files) {
      if (!reviewablePaths.has(path)) throw new TypeError(`OCR rule output contains non-reviewable path: ${path}`);
      ruleByPath.set(path, group);
    }
  }
  for (const path of reviewablePaths) if (!ruleByPath.has(path)) throw new TypeError(`OCR rule output did not account for reviewable path: ${path}`);

  const checklist = preview.reviewableFiles
    .map((entry) => Object.freeze({
      key: checklistKey(entry.path, entry.status),
      path: entry.path,
      status: entry.status,
      insertions: entry.insertions,
      deletions: entry.deletions,
      ruleGroupId: ruleByPath.get(entry.path)!.groupId,
    }))
    .sort((a, b) => a.ruleGroupId - b.ruleGroupId || a.path.localeCompare(b.path) || a.status.localeCompare(b.status));

  const batches: ReviewBatch[] = [];
  for (const group of rules.groups) {
    const groupFiles = checklist.filter((entry) => entry.ruleGroupId === group.groupId);
    let current: ReviewChecklistEntry[] = [];
    let currentLines = 0;
    const flush = (): void => {
      if (current.length === 0) return;
      const batchId = `ocr-batch-${String(group.groupId)}-${String(batches.length + 1).padStart(3, "0")}`;
      batches.push(Object.freeze({ batchId, ruleGroupId: group.groupId, ruleSource: group.source, rulePattern: group.pattern, rule: group.rule, changeLines: currentLines, files: Object.freeze([...current]) }));
      current = [];
      currentLines = 0;
    };
    for (const entry of groupFiles) {
      const lines = entry.insertions + entry.deletions;
      if (current.length > 0 && (current.length >= maxFiles || currentLines + lines > maxLines)) flush();
      current.push(entry);
      currentLines += lines;
      if (current.length >= maxFiles || currentLines >= maxLines) flush();
    }
    flush();
  }

  const reviewerChildren: ReviewChildTaskSpec[] = batches.map((batch) => Object.freeze({
    taskId: `reviewer:${batch.batchId}`,
    role: "REVIEWER",
    objective: `Review OCR batch ${batch.batchId} and account for every assigned file.`,
    phase: "review",
    delegatedCapabilities: Object.freeze(["review:inspect"] as const),
    batchIds: Object.freeze([batch.batchId]),
  }));
  const reflectionChild: ReviewChildTaskSpec = Object.freeze({
    taskId: "reviewer:reflection",
    role: "REFLECTION",
    objective: "Independently reflect on completed review findings and reject unsupported findings.",
    phase: "reflection",
    delegatedCapabilities: Object.freeze(["review:inspect"] as const),
    batchIds: Object.freeze(batches.map((batch) => batch.batchId)),
  });
  const surface = { mode: preview.mode, target, reviewableFiles: checklist, rules: rules.groups };
  return Object.freeze({
    schemaVersion: "toadaid.open-code-review-plan.v1",
    ocrSchemaVersion: "1",
    mode: preview.mode,
    repository: preview.repository,
    target,
    reviewSurfaceSha256: sha256(surface),
    checklist: Object.freeze(checklist),
    batches: Object.freeze(batches),
    childTasks: Object.freeze([...reviewerChildren, reflectionChild]),
  });
}

export function openCodeReviewPlanSha256(plan: OpenCodeReviewPlan): string {
  return sha256(plan);
}

export function createReviewCoverageState(plan: OpenCodeReviewPlan): ReviewCoverageState {
  return Object.freeze({
    schemaVersion: "toadaid.open-code-review-coverage-state.v1",
    planSha256: openCodeReviewPlanSha256(plan),
    entries: Object.freeze(plan.checklist.map((entry) => Object.freeze({ ...entry, disposition: "PENDING" as const, findings: Object.freeze([]) }))),
  });
}

function normalizeFinding(file: ReviewChecklistEntry, input: ReviewFindingInput): ReviewFinding {
  const content = stringValue(input.content, "finding.content", MAX_FINDING_CONTENT);
  if (input.startLine !== undefined && (!Number.isSafeInteger(input.startLine) || input.startLine < 1)) throw new TypeError("finding.startLine must be a positive integer");
  if (input.endLine !== undefined && (!Number.isSafeInteger(input.endLine) || input.endLine < 1)) throw new TypeError("finding.endLine must be a positive integer");
  if (input.startLine !== undefined && input.endLine !== undefined && input.endLine < input.startLine) throw new TypeError("finding.endLine cannot precede startLine");
  const categories: readonly ReviewFindingCategory[] = ["bug", "security", "performance", "maintainability", "test", "style", "documentation", "other"];
  const severities: readonly ReviewFindingSeverity[] = ["critical", "high", "medium", "low"];
  if (input.category !== undefined && !categories.includes(input.category)) throw new TypeError("finding.category is invalid");
  if (input.severity !== undefined && !severities.includes(input.severity)) throw new TypeError("finding.severity is invalid");
  const identity = { fileKey: file.key, content, startLine: input.startLine ?? null, endLine: input.endLine ?? null, category: input.category ?? null, severity: input.severity ?? null };
  return Object.freeze({
    findingId: sha256(identity),
    fileKey: file.key,
    path: file.path,
    content,
    ...(input.startLine === undefined ? {} : { startLine: input.startLine }),
    ...(input.endLine === undefined ? {} : { endLine: input.endLine }),
    ...(input.category === undefined ? {} : { category: input.category }),
    ...(input.severity === undefined ? {} : { severity: input.severity }),
  });
}

function updateCoverageEntry(state: ReviewCoverageState, fileKey: string, update: (entry: ReviewCoverageEntry) => ReviewCoverageEntry): ReviewCoverageState {
  let found = false;
  const entries = state.entries.map((entry) => {
    if (entry.key !== fileKey) return entry;
    found = true;
    if (entry.disposition !== "PENDING") throw new Error(`review coverage entry is already settled: ${fileKey}`);
    return update(entry);
  });
  if (!found) throw new Error(`unknown review checklist key: ${fileKey}`);
  return Object.freeze({ ...state, entries: Object.freeze(entries) });
}

export function markReviewFileReviewed(state: ReviewCoverageState, fileKey: string, findings: readonly ReviewFindingInput[] = []): ReviewCoverageState {
  return updateCoverageEntry(state, fileKey, (entry) => Object.freeze({ ...entry, disposition: "REVIEWED", findings: Object.freeze(findings.map((finding) => normalizeFinding(entry, finding))) }));
}

export function markReviewFileSkipped(state: ReviewCoverageState, fileKey: string, reason: string): ReviewCoverageState {
  const normalizedReason = stringValue(reason, "skip reason", 1_000);
  return updateCoverageEntry(state, fileKey, (entry) => Object.freeze({ ...entry, disposition: "SKIPPED", skipReason: normalizedReason, findings: Object.freeze([]) }));
}

function canonicalIsoTimestamp(value: string, label: string): string {
  const normalized = stringValue(value, label, 64);
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== normalized) throw new TypeError(`${label} must be canonical ISO-8601`);
  return normalized;
}

export function finalizeOpenCodeReview(plan: OpenCodeReviewPlan, state: ReviewCoverageState, completedAt: string): OpenCodeReviewReceipt {
  const planSha256 = openCodeReviewPlanSha256(plan);
  if (state.planSha256 !== planSha256) throw new Error("review coverage state is bound to a different plan");
  const pending = state.entries.filter((entry) => entry.disposition === "PENDING");
  if (pending.length > 0) throw new Error(`review coverage is incomplete: ${pending.length} file(s) still pending`);
  const reviewed = state.entries.filter((entry) => entry.disposition === "REVIEWED");
  const skippedEntries = state.entries.filter((entry) => entry.disposition === "SKIPPED");
  const findings = reviewed.flatMap((entry) => entry.findings).sort((a, b) => a.path.localeCompare(b.path) || a.findingId.localeCompare(b.findingId));
  const skipped = skippedEntries.map((entry) => Object.freeze({ key: entry.key, path: entry.path, status: entry.status, reason: entry.skipReason! }));
  return Object.freeze({
    schemaVersion: "toadaid.open-code-review-receipt.v1",
    completedAt: canonicalIsoTimestamp(completedAt, "completedAt"),
    planSha256,
    reviewSurfaceSha256: plan.reviewSurfaceSha256,
    totalFiles: state.entries.length,
    reviewedFiles: reviewed.length,
    skippedFiles: skippedEntries.length,
    coverageRate: state.entries.length === 0 ? 1 : (reviewed.length + skippedEntries.length) / state.entries.length,
    findings: Object.freeze(findings),
    skipped: Object.freeze(skipped),
  });
}

export function openCodeReviewReceiptSha256(receipt: OpenCodeReviewReceipt): string {
  return sha256(receipt);
}

export function createReviewReflectionPacket(receipt: OpenCodeReviewReceipt): ReviewReflectionPacket {
  return Object.freeze({
    schemaVersion: "toadaid.open-code-review-reflection.v1",
    reviewReceiptSha256: openCodeReviewReceiptSha256(receipt),
    totalFiles: receipt.totalFiles,
    findingCount: receipt.findings.length,
    findings: Object.freeze([...receipt.findings]),
  });
}

export async function executeGovernedReviewFix(request: ReviewFixRequest, authorities: ReviewFixAuthorityBundle, bridge: ReviewFixBridge): Promise<ReviewFixReceipt> {
  assertAuthority(authorities.reviewFix, "review:fix");
  assertAuthority(authorities.workspaceSnapshot, "workspace:snapshot");
  assertAuthority(authorities.workspaceDiff, "workspace:diff");
  const ids = [...new Set(request.findingIds)];
  if (ids.length === 0) throw new TypeError("at least one findingId is required for review fix");
  const findingMap = new Map(request.receipt.findings.map((finding) => [finding.findingId, finding]));
  const selected = ids.map((id) => {
    const finding = findingMap.get(id);
    if (!finding) throw new Error(`review fix references unknown findingId: ${id}`);
    return finding;
  });
  const before = await bridge.snapshot("before");
  await bridge.apply(Object.freeze(selected));
  const after = await bridge.snapshot("after");
  const diff = await bridge.diff(before, after);
  if (diff.schemaVersion !== "toadaid.workspace-diff.v1") throw new Error("review fix bridge returned an invalid workspace diff schema");
  if (diff.fromSnapshotId !== before.snapshotId || diff.toSnapshotId !== after.snapshotId) throw new Error("review fix bridge returned a workspace diff bound to different snapshots");
  return Object.freeze({
    schemaVersion: "toadaid.open-code-review-fix-receipt.v1",
    completedAt: canonicalIsoTimestamp(request.completedAt, "completedAt"),
    reviewReceiptSha256: openCodeReviewReceiptSha256(request.receipt),
    findingIds: Object.freeze(ids),
    beforeSnapshotId: before.snapshotId,
    afterSnapshotId: after.snapshotId,
    diff,
  });
}
