import { randomUUID } from "node:crypto";

import { validateSecurityThreatModelEnvelope } from "./securityAudit.js";
import type {
  SecurityAttackClass,
  SecurityEvidenceRef,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import { boundedId, canonicalIso, sha, sha256 } from "./invocationSchema.js";
import type {
  CreateSecurityCoverageLedgerInput,
  PlanSecurityHunterAssignmentInput,
  RebaseSecurityCoverageLedgerInput,
  RecordSecurityCoverageInput,
  SecurityCoverageArea,
  SecurityCoverageAreaInput,
  SecurityCoverageCell,
  SecurityCoverageDisposition,
  SecurityCoverageGap,
  SecurityCoverageLedgerEnvelope,
  SecurityCoverageLedgerRecord,
  SecurityCoverageRuntime,
  SecurityCoverageSummary,
  SecurityHunterAssignment,
  SecurityHunterBudget,
} from "./securityCoverageTypes.js";

export type * from "./securityCoverageTypes.js";

const MAX_AREAS = 2_000;
const MAX_AREA_PATHS = 2_000;
const MAX_CHANGED_PATHS = 20_000;
const MAX_EVIDENCE_REFS = 2_000;
const MAX_PATH_CHARS = 2_048;
const MAX_TEXT_CHARS = 4_000;
const MAX_REVISION = 1_000_000;
const MAX_INSPECTION_COUNT = 1_000_000_000;

const COVERAGE_DISPOSITIONS: readonly SecurityCoverageDisposition[] = [
  "UNEXPLORED", "THIN", "COVERED",
];

const ATTACK_CLASSES: readonly SecurityAttackClass[] = [
  "AUTHORIZATION_BYPASS",
  "COMMAND_EXECUTION_INJECTION",
  "DESERIALIZATION_OR_INTEGRITY",
  "INPUT_INJECTION",
  "ORIGIN_OR_BROWSER_BOUNDARY",
  "PATH_TRAVERSAL",
  "SECRET_EXPOSURE",
  "SSRF_OR_NETWORK_PIVOT",
  "STATE_TAMPERING",
  "SUPPLY_CHAIN",
];

function exactText(value: string, label: string, maximum = MAX_TEXT_CHARS): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) throw new TypeError(`${label} is invalid`);
  return value;
}

function safeRelativePath(value: string, label: string): string {
  const path = exactText(value, label, MAX_PATH_CHARS).replace(/\\/g, "/");
  if (path.startsWith("/") || /^[A-Za-z]:\//.test(path)) {
    throw new TypeError(`${label} must be repository-relative`);
  }
  const parts = path.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new TypeError(`${label} contains unsafe path segments`);
  }
  return path;
}

function normalizePathList(
  values: readonly string[],
  label: string,
  maximum: number,
  requireNonEmpty: boolean,
): readonly string[] {
  if (!Array.isArray(values) || values.length > maximum || (requireNonEmpty && values.length < 1)) {
    throw new RangeError(`${label} count is invalid`);
  }
  const normalized = values.map((value, index) => safeRelativePath(value, `${label}[${index}]`));
  const unique = [...new Set(normalized)].sort();
  if (unique.length !== normalized.length) throw new Error(`${label} contains duplicate paths`);
  return Object.freeze(unique);
}

function pathWithin(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}/`);
}

function pathIntersects(a: string, b: string): boolean {
  return pathWithin(a, b) || pathWithin(b, a);
}

function pathAllowedByModel(path: string, model: SecurityThreatModelEnvelope): boolean {
  if (!model.record.scope.includePaths.some((root) => pathWithin(path, root))) return false;
  return !model.record.scope.excludePaths.some((root) => pathWithin(path, root));
}

function normalizeAttackClass(value: SecurityAttackClass, label: string): SecurityAttackClass {
  if (!ATTACK_CLASSES.includes(value)) throw new TypeError(`${label} is unsupported`);
  return value;
}

function normalizeDisposition(
  value: SecurityCoverageDisposition,
  label: string,
): SecurityCoverageDisposition {
  if (!COVERAGE_DISPOSITIONS.includes(value)) throw new TypeError(`${label} is unsupported`);
  return value;
}

function normalizeEvidenceRefs(
  refs: readonly SecurityEvidenceRef[],
  label: string,
  requireNonEmpty: boolean,
): readonly SecurityEvidenceRef[] {
  if (!Array.isArray(refs) || refs.length > MAX_EVIDENCE_REFS || (requireNonEmpty && refs.length < 1)) {
    throw new RangeError(`${label} count is invalid`);
  }
  const ids = new Set<string>();
  const normalized = refs.map((ref, index) => {
    const id = boundedId(ref.id, `${label}[${index}].id`);
    if (ids.has(id)) throw new Error(`${label} contains duplicate ids`);
    ids.add(id);
    return Object.freeze({ id, sha256: sha(ref.sha256, `${label}[${index}].sha256`)! });
  });
  return Object.freeze(normalized.sort((a, b) => a.id.localeCompare(b.id)));
}

function normalizeArea(
  input: SecurityCoverageAreaInput | SecurityCoverageArea,
  model: SecurityThreatModelEnvelope,
): SecurityCoverageArea {
  const areaId = boundedId(input.areaId, "areaId");
  const label = exactText(input.label, "area.label");
  const paths = normalizePathList(input.paths, `area.${areaId}.paths`, MAX_AREA_PATHS, true);
  for (const path of paths) {
    if (!pathAllowedByModel(path, model)) {
      throw new Error(`coverage area path is outside threat-model scope: ${path}`);
    }
  }
  const areaSha256 = sha256({ areaId, label, paths });
  if ("areaSha256" in input && sha(input.areaSha256, "areaSha256") !== areaSha256) {
    throw new Error("security coverage area hash mismatch");
  }
  return Object.freeze({ areaId, label, paths, areaSha256 });
}

function normalizeAreas(
  inputs: readonly (SecurityCoverageAreaInput | SecurityCoverageArea)[],
  model: SecurityThreatModelEnvelope,
): readonly SecurityCoverageArea[] {
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > MAX_AREAS) {
    throw new RangeError("security coverage area count is invalid");
  }
  const ids = new Set<string>();
  const areas = inputs.map((input) => {
    const area = normalizeArea(input, model);
    if (ids.has(area.areaId)) throw new Error("security coverage areaId is duplicated");
    ids.add(area.areaId);
    return area;
  });
  return Object.freeze(areas.sort((a, b) => a.areaId.localeCompare(b.areaId)));
}

function modelAttackClasses(model: SecurityThreatModelEnvelope): readonly SecurityAttackClass[] {
  return Object.freeze(
    model.record.attackClasses
      .map((entry) => normalizeAttackClass(entry.attackClass, "model.attackClass"))
      .sort(),
  );
}

function coverageCellId(areaId: string, attackClass: SecurityAttackClass): string {
  return sha256({ areaId, attackClass });
}

function createUnexploredCell(
  area: SecurityCoverageArea,
  attackClass: SecurityAttackClass,
): SecurityCoverageCell {
  return Object.freeze({
    cellId: coverageCellId(area.areaId, attackClass),
    areaId: area.areaId,
    areaSha256: area.areaSha256,
    attackClass,
    disposition: "UNEXPLORED",
    evidenceRefs: Object.freeze([]),
    inspectionCount: 0,
    lastInspectedAt: null,
  });
}

function inspectionBreadthPercent(cells: readonly SecurityCoverageCell[]): number {
  if (cells.length === 0) return 0;
  const inspected = cells.filter((cell) => cell.disposition !== "UNEXPLORED").length;
  return Number(((inspected / cells.length) * 100).toFixed(6));
}

function normalizeInvalidatedCellIds(
  values: readonly string[],
  cells: readonly SecurityCoverageCell[],
): readonly string[] {
  if (!Array.isArray(values) || values.length > cells.length) {
    throw new RangeError("continuity.invalidatedCellIds count is invalid");
  }
  const known = new Set(cells.map((cell) => cell.cellId));
  const normalized = values.map((value, index) =>
    exactText(value, `continuity.invalidatedCellIds[${index}]`, 128),
  );
  const unique = [...new Set(normalized)].sort();
  if (unique.length !== normalized.length) throw new Error("continuity.invalidatedCellIds contains duplicates");
  for (const id of unique) if (!known.has(id)) throw new Error("continuity.invalidatedCellIds contains unknown cell");
  return Object.freeze(unique);
}

function validateCell(
  cell: SecurityCoverageCell,
  area: SecurityCoverageArea,
  allowedAttackClasses: ReadonlySet<SecurityAttackClass>,
): SecurityCoverageCell {
  const attackClass = normalizeAttackClass(cell.attackClass, "cell.attackClass");
  if (!allowedAttackClasses.has(attackClass)) {
    throw new Error("coverage cell attack class is not derived by threat model");
  }
  if (
    boundedId(cell.areaId, "cell.areaId") !== area.areaId ||
    sha(cell.areaSha256, "cell.areaSha256") !== area.areaSha256
  ) throw new Error("coverage cell area binding mismatch");

  const expectedCellId = coverageCellId(area.areaId, attackClass);
  if (exactText(cell.cellId, "cell.cellId", 128) !== expectedCellId) {
    throw new Error("coverage cell identity mismatch");
  }

  const disposition = normalizeDisposition(cell.disposition, "cell.disposition");
  if (
    !Number.isSafeInteger(cell.inspectionCount) ||
    cell.inspectionCount < 0 ||
    cell.inspectionCount > MAX_INSPECTION_COUNT
  ) throw new RangeError("coverage cell inspectionCount is invalid");

  const evidenceRefs = normalizeEvidenceRefs(
    cell.evidenceRefs,
    "cell.evidenceRefs",
    disposition !== "UNEXPLORED",
  );

  let lastInspectedAt: string | null = null;
  if (disposition === "UNEXPLORED") {
    if (cell.inspectionCount !== 0 || evidenceRefs.length !== 0 || cell.lastInspectedAt !== null) {
      throw new Error("UNEXPLORED coverage cell cannot carry inspection evidence");
    }
  } else {
    if (cell.inspectionCount < 1 || cell.lastInspectedAt === null) {
      throw new Error("inspected coverage cell requires count and timestamp");
    }
    lastInspectedAt = canonicalIso(cell.lastInspectedAt, "cell.lastInspectedAt");
  }

  return Object.freeze({
    cellId: expectedCellId,
    areaId: area.areaId,
    areaSha256: area.areaSha256,
    attackClass,
    disposition,
    evidenceRefs,
    inspectionCount: cell.inspectionCount,
    lastInspectedAt,
  });
}

function normalizeBudget(budget: SecurityHunterBudget): SecurityHunterBudget {
  const modelTokens = budget.modelTokens;
  const toolCalls = budget.toolCalls;
  const networkRequests = budget.networkRequests;
  const wallClockMs = budget.wallClockMs;
  for (const [label, value] of Object.entries({
    modelTokens, toolCalls, networkRequests, wallClockMs,
  })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError(`budget.${label} must be a non-negative safe integer`);
    }
  }
  if (modelTokens === 0 && toolCalls === 0 && networkRequests === 0 && wallClockMs === 0) {
    throw new Error("security hunter budget cannot be entirely zero");
  }
  return Object.freeze({ modelTokens, toolCalls, networkRequests, wallClockMs });
}

function dispositionRank(value: SecurityCoverageDisposition): number {
  switch (value) {
    case "UNEXPLORED": return 0;
    case "THIN": return 1;
    case "COVERED": return 2;
  }
}

export function securityCoverageLedgerRecordSha256(
  record: SecurityCoverageLedgerRecord,
): string {
  return sha256(record);
}

export function validateSecurityCoverageLedgerRecord(
  record: SecurityCoverageLedgerRecord,
  modelInput: SecurityThreatModelEnvelope,
): SecurityCoverageLedgerRecord {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  if (record.schemaVersion !== "toadaid.security-coverage-ledger.v1") {
    throw new TypeError("unsupported security coverage ledger schemaVersion");
  }
  if (!Number.isSafeInteger(record.revision) || record.revision < 0 || record.revision > MAX_REVISION) {
    throw new RangeError("security coverage ledger revision is invalid");
  }

  const repositoryIdentitySha256 = sha(record.repositoryIdentitySha256, "repositoryIdentitySha256")!;
  const sourceRevision = exactText(record.sourceRevision, "sourceRevision", 256);
  const sourceTreeSha256 = sha(record.sourceTreeSha256, "sourceTreeSha256")!;
  const threatModelRecordSha256 = sha(record.threatModelRecordSha256, "threatModelRecordSha256")!;
  if (
    repositoryIdentitySha256 !== model.record.binding.repositoryIdentitySha256 ||
    sourceRevision !== model.record.binding.sourceRevision ||
    sourceTreeSha256 !== model.record.binding.sourceTreeSha256 ||
    threatModelRecordSha256 !== model.recordSha256
  ) throw new Error("coverage ledger source/threat-model binding mismatch");

  const areas = normalizeAreas(record.areas, model);
  const areaById = new Map(areas.map((area) => [area.areaId, area]));
  const attackClasses = modelAttackClasses(model);
  const allowedAttackClasses = new Set(attackClasses);
  if (
    !Array.isArray(record.cells) ||
    record.cells.length !== areas.length * attackClasses.length
  ) throw new Error("coverage ledger must contain exact area × attack-class cells");

  const seen = new Set<string>();
  const cells = record.cells.map((cell) => {
    const area = areaById.get(cell.areaId);
    if (!area) throw new Error("coverage cell references unknown area");
    const normalized = validateCell(cell, area, allowedAttackClasses);
    if (seen.has(normalized.cellId)) throw new Error("coverage ledger contains duplicate cell");
    seen.add(normalized.cellId);
    return normalized;
  });

  for (const area of areas) {
    for (const attackClass of attackClasses) {
      if (!seen.has(coverageCellId(area.areaId, attackClass))) {
        throw new Error("coverage ledger is missing area × attack-class cell");
      }
    }
  }
  cells.sort((a, b) =>
    a.areaId.localeCompare(b.areaId) || a.attackClass.localeCompare(b.attackClass),
  );

  const previousLedgerRecordSha256 =
    record.continuity.previousLedgerRecordSha256 === null
      ? null
      : sha(record.continuity.previousLedgerRecordSha256, "continuity.previousLedgerRecordSha256")!;
  if (record.revision === 0 && previousLedgerRecordSha256 !== null) {
    throw new Error("initial coverage ledger cannot have predecessor");
  }
  if (record.revision > 0 && previousLedgerRecordSha256 === null) {
    throw new Error("revised coverage ledger requires predecessor");
  }

  const sourceChangeSha256 =
    record.continuity.sourceChangeSha256 === null
      ? null
      : sha(record.continuity.sourceChangeSha256, "continuity.sourceChangeSha256")!;
  const invalidatedCellIds = normalizeInvalidatedCellIds(
    record.continuity.invalidatedCellIds,
    cells,
  );
  if (sourceChangeSha256 === null && invalidatedCellIds.length > 0) {
    throw new Error("coverage invalidation requires source-change evidence");
  }

  const breadth = inspectionBreadthPercent(cells);
  if (record.inspectionBreadthPercent !== breadth) {
    throw new Error("coverage inspection breadth does not match ledger cells");
  }

  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RangeError("coverage ledger updatedAt is earlier than createdAt");
  }

  return Object.freeze({
    schemaVersion: "toadaid.security-coverage-ledger.v1",
    ledgerId: boundedId(record.ledgerId, "ledgerId"),
    revision: record.revision,
    threatModelRecordSha256,
    repositoryIdentitySha256,
    sourceRevision,
    sourceTreeSha256,
    areas,
    cells: Object.freeze(cells),
    inspectionBreadthPercent: breadth,
    createdAt,
    updatedAt,
    continuity: Object.freeze({
      previousLedgerRecordSha256,
      sourceChangeSha256,
      invalidatedCellIds,
    }),
  });
}

export function sealSecurityCoverageLedgerRecord(
  record: SecurityCoverageLedgerRecord,
  model: SecurityThreatModelEnvelope,
): SecurityCoverageLedgerEnvelope {
  const normalized = validateSecurityCoverageLedgerRecord(record, model);
  return Object.freeze({
    schemaVersion: "toadaid.security-coverage-ledger-envelope.v1",
    record: normalized,
    recordSha256: securityCoverageLedgerRecordSha256(normalized),
  });
}

export function validateSecurityCoverageLedgerEnvelope(
  envelope: SecurityCoverageLedgerEnvelope,
  model: SecurityThreatModelEnvelope,
): SecurityCoverageLedgerEnvelope {
  if (envelope.schemaVersion !== "toadaid.security-coverage-ledger-envelope.v1") {
    throw new TypeError("unsupported security coverage ledger envelope schemaVersion");
  }
  const record = validateSecurityCoverageLedgerRecord(envelope.record, model);
  const digest = sha(envelope.recordSha256, "recordSha256")!;
  if (digest !== securityCoverageLedgerRecordSha256(record)) {
    throw new Error("security coverage ledger integrity mismatch");
  }
  return Object.freeze({
    schemaVersion: "toadaid.security-coverage-ledger-envelope.v1",
    record,
    recordSha256: digest,
  });
}

export function createSecurityCoverageLedger(
  modelInput: SecurityThreatModelEnvelope,
  input: CreateSecurityCoverageLedgerInput,
  runtime: SecurityCoverageRuntime = {},
): SecurityCoverageLedgerEnvelope {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  const areas = normalizeAreas(input.areas, model);
  const cells = areas.flatMap((area) =>
    modelAttackClasses(model).map((attackClass) => createUnexploredCell(area, attackClass)),
  );
  const now = runtime.now ?? (() => new Date());
  const randomId = runtime.randomId ?? randomUUID;
  const createdAt = canonicalIso(input.createdAt ?? now().toISOString(), "createdAt");
  return sealSecurityCoverageLedgerRecord({
    schemaVersion: "toadaid.security-coverage-ledger.v1",
    ledgerId: boundedId(input.ledgerId ?? `security-coverage-${randomId()}`, "ledgerId"),
    revision: 0,
    threatModelRecordSha256: model.recordSha256,
    repositoryIdentitySha256: model.record.binding.repositoryIdentitySha256,
    sourceRevision: model.record.binding.sourceRevision,
    sourceTreeSha256: model.record.binding.sourceTreeSha256,
    areas,
    cells,
    inspectionBreadthPercent: 0,
    createdAt,
    updatedAt: createdAt,
    continuity: Object.freeze({
      previousLedgerRecordSha256: null,
      sourceChangeSha256: null,
      invalidatedCellIds: Object.freeze([]),
    }),
  }, model);
}

export function recordSecurityCoverage(
  modelInput: SecurityThreatModelEnvelope,
  ledgerInput: SecurityCoverageLedgerEnvelope,
  input: RecordSecurityCoverageInput,
  runtime: SecurityCoverageRuntime = {},
): SecurityCoverageLedgerEnvelope {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  const ledger = validateSecurityCoverageLedgerEnvelope(ledgerInput, model);
  const areaId = boundedId(input.areaId, "areaId");
  const attackClass = normalizeAttackClass(input.attackClass, "attackClass");
  const targetDisposition = normalizeDisposition(input.disposition, "disposition");
  if (targetDisposition === "UNEXPLORED") throw new Error("coverage observation cannot target UNEXPLORED");
  const evidenceRefs = normalizeEvidenceRefs(input.evidenceRefs, "evidenceRefs", true);
  const now = runtime.now ?? (() => new Date());
  const inspectedAt = canonicalIso(input.inspectedAt ?? now().toISOString(), "inspectedAt");
  if (Date.parse(inspectedAt) < Date.parse(ledger.record.updatedAt)) {
    throw new RangeError("coverage inspection time moves backward");
  }

  let found = false;
  const cells = ledger.record.cells.map((cell) => {
    if (cell.areaId !== areaId || cell.attackClass !== attackClass) return cell;
    found = true;
    if (cell.disposition === "COVERED") {
      throw new Error("COVERED security coverage cell is terminal");
    }
    const evidenceById = new Map(cell.evidenceRefs.map((ref) => [ref.id, ref]));
    const beforeSize = evidenceById.size;
    for (const ref of evidenceRefs) {
      const previous = evidenceById.get(ref.id);
      if (previous && previous.sha256 !== ref.sha256) {
        throw new Error("coverage evidence id cannot be rebound to different content");
      }
      evidenceById.set(ref.id, ref);
    }
    if (cell.disposition === "THIN" && targetDisposition === "THIN" && evidenceById.size === beforeSize) {
      throw new Error("repeated THIN coverage requires new evidence");
    }

    return Object.freeze({
      ...cell,
      disposition: targetDisposition,
      evidenceRefs: Object.freeze(
        [...evidenceById.values()].sort((a, b) => a.id.localeCompare(b.id)),
      ),
      inspectionCount: cell.inspectionCount + 1,
      lastInspectedAt: inspectedAt,
    });
  });
  if (!found) throw new Error("unknown coverage area × attack-class cell");

  return sealSecurityCoverageLedgerRecord({
    ...ledger.record,
    revision: ledger.record.revision + 1,
    cells,
    inspectionBreadthPercent: inspectionBreadthPercent(cells),
    updatedAt: inspectedAt,
    continuity: Object.freeze({
      previousLedgerRecordSha256: ledger.recordSha256,
      sourceChangeSha256: null,
      invalidatedCellIds: Object.freeze([]),
    }),
  }, model);
}

export function summarizeSecurityCoverage(
  modelInput: SecurityThreatModelEnvelope,
  ledgerInput: SecurityCoverageLedgerEnvelope,
): SecurityCoverageSummary {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  const ledger = validateSecurityCoverageLedgerEnvelope(ledgerInput, model);
  const gaps: SecurityCoverageGap[] = ledger.record.cells
    .filter((cell) => cell.disposition !== "COVERED")
    .sort((a, b) =>
      dispositionRank(a.disposition) - dispositionRank(b.disposition) ||
      a.inspectionCount - b.inspectionCount ||
      a.areaId.localeCompare(b.areaId) ||
      a.attackClass.localeCompare(b.attackClass),
    )
    .map((cell) => Object.freeze({
      cellId: cell.cellId,
      areaId: cell.areaId,
      attackClass: cell.attackClass,
      disposition: cell.disposition as "UNEXPLORED" | "THIN",
      inspectionCount: cell.inspectionCount,
    }));

  return Object.freeze({
    totalCells: ledger.record.cells.length,
    unexploredCells: ledger.record.cells.filter((cell) => cell.disposition === "UNEXPLORED").length,
    thinCells: ledger.record.cells.filter((cell) => cell.disposition === "THIN").length,
    coveredCells: ledger.record.cells.filter((cell) => cell.disposition === "COVERED").length,
    inspectionBreadthPercent: ledger.record.inspectionBreadthPercent,
    gaps: Object.freeze(gaps),
  });
}

export function planNextSecurityHunterAssignment(
  modelInput: SecurityThreatModelEnvelope,
  ledgerInput: SecurityCoverageLedgerEnvelope,
  input: PlanSecurityHunterAssignmentInput,
  runtime: SecurityCoverageRuntime = {},
): SecurityHunterAssignment | null {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  const ledger = validateSecurityCoverageLedgerEnvelope(ledgerInput, model);
  const gap = summarizeSecurityCoverage(model, ledger).gaps[0];
  if (!gap) return null;
  const area = ledger.record.areas.find((entry) => entry.areaId === gap.areaId);
  if (!area) throw new Error("coverage gap references missing area");
  const budget = normalizeBudget(input.budget);
  const now = runtime.now ?? (() => new Date());
  const randomId = runtime.randomId ?? randomUUID;
  const plannedAt = canonicalIso(input.plannedAt ?? now().toISOString(), "plannedAt");
  return Object.freeze({
    schemaVersion: "toadaid.security-hunter-assignment.v1",
    assignmentId: boundedId(input.assignmentId ?? `security-hunter-${randomId()}`, "assignmentId"),
    threatModelRecordSha256: model.recordSha256,
    coverageLedgerRecordSha256: ledger.recordSha256,
    predecessorCoverageDisposition: gap.disposition,
    predecessorInspectionCount: gap.inspectionCount,
    repositoryIdentitySha256: model.record.binding.repositoryIdentitySha256,
    sourceRevision: model.record.binding.sourceRevision,
    sourceTreeSha256: model.record.binding.sourceTreeSha256,
    areaId: area.areaId,
    areaSha256: area.areaSha256,
    scopePaths: area.paths,
    scopeSha256: sha256(area.paths),
    attackClass: gap.attackClass,
    budget,
    budgetSha256: sha256(budget),
    plannedAt,
  });
}

export function rebaseSecurityCoverageLedger(
  previousModelInput: SecurityThreatModelEnvelope,
  previousLedgerInput: SecurityCoverageLedgerEnvelope,
  nextModelInput: SecurityThreatModelEnvelope,
  input: RebaseSecurityCoverageLedgerInput,
  runtime: SecurityCoverageRuntime = {},
): SecurityCoverageLedgerEnvelope {
  const previousModel = validateSecurityThreatModelEnvelope(previousModelInput);
  const previousLedger = validateSecurityCoverageLedgerEnvelope(previousLedgerInput, previousModel);
  const nextModel = validateSecurityThreatModelEnvelope(nextModelInput);
  if (
    previousModel.record.binding.repositoryIdentitySha256 !==
    nextModel.record.binding.repositoryIdentitySha256
  ) throw new Error("coverage lineage cannot cross repositories");

  const changedPaths = normalizePathList(input.changedPaths, "changedPaths", MAX_CHANGED_PATHS, false);
  const sourceTreeChanged =
    previousModel.record.binding.sourceTreeSha256 !==
    nextModel.record.binding.sourceTreeSha256;
  if (sourceTreeChanged && changedPaths.length === 0) {
    throw new Error(
      "changed source tree requires a non-empty changed-path manifest",
    );
  }
  if (!sourceTreeChanged && changedPaths.length > 0) {
    throw new Error(
      "unchanged source tree cannot carry changed paths",
    );
  }
  const areas = normalizeAreas(input.areas, nextModel);
  const previousAreaById = new Map(previousLedger.record.areas.map((area) => [area.areaId, area]));
  const previousCellById = new Map(previousLedger.record.cells.map((cell) => [cell.cellId, cell]));
  const invalidated = new Set<string>();

  const cells = areas.flatMap((area) =>
    modelAttackClasses(nextModel).map((attackClass) => {
      const id = coverageCellId(area.areaId, attackClass);
      const previousArea = previousAreaById.get(area.areaId);
      const previousCell = previousCellById.get(id);
      const areaUnchanged = previousArea?.areaSha256 === area.areaSha256;
      const affected = area.paths.some((areaPath) =>
        changedPaths.some((changedPath) => pathIntersects(areaPath, changedPath)),
      );
      if (areaUnchanged && previousCell && !affected) return Object.freeze({ ...previousCell });
      if (previousCell && previousCell.disposition !== "UNEXPLORED") invalidated.add(id);
      return createUnexploredCell(area, attackClass);
    }),
  );

  const now = runtime.now ?? (() => new Date());
  const rebasedAt = canonicalIso(input.rebasedAt ?? now().toISOString(), "rebasedAt");
  if (Date.parse(rebasedAt) < Date.parse(previousLedger.record.updatedAt)) {
    throw new RangeError("coverage rebase time moves backward");
  }
  const sourceChangeSha256 = sha256({
    fromSourceTreeSha256: previousModel.record.binding.sourceTreeSha256,
    toSourceTreeSha256: nextModel.record.binding.sourceTreeSha256,
    changedPaths,
  });

  return sealSecurityCoverageLedgerRecord({
    schemaVersion: "toadaid.security-coverage-ledger.v1",
    ledgerId: boundedId(input.ledgerId ?? previousLedger.record.ledgerId, "ledgerId"),
    revision: previousLedger.record.revision + 1,
    threatModelRecordSha256: nextModel.recordSha256,
    repositoryIdentitySha256: nextModel.record.binding.repositoryIdentitySha256,
    sourceRevision: nextModel.record.binding.sourceRevision,
    sourceTreeSha256: nextModel.record.binding.sourceTreeSha256,
    areas,
    cells,
    inspectionBreadthPercent: inspectionBreadthPercent(cells),
    createdAt: previousLedger.record.createdAt,
    updatedAt: rebasedAt,
    continuity: Object.freeze({
      previousLedgerRecordSha256: previousLedger.recordSha256,
      sourceChangeSha256,
      invalidatedCellIds: Object.freeze([...invalidated].sort()),
    }),
  }, nextModel);
}

export function serializeSecurityCoverageLedger(
  envelope: SecurityCoverageLedgerEnvelope,
  model: SecurityThreatModelEnvelope,
): string {
  return JSON.stringify(validateSecurityCoverageLedgerEnvelope(envelope, model));
}

export function parseSecurityCoverageLedger(
  serialized: string,
  model: SecurityThreatModelEnvelope,
): SecurityCoverageLedgerEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); }
  catch { throw new TypeError("security coverage ledger serialization is invalid JSON"); }
  return validateSecurityCoverageLedgerEnvelope(
    parsed as SecurityCoverageLedgerEnvelope,
    model,
  );
}
