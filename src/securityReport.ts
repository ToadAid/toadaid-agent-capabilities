import { canonicalIso, sha, sha256 } from "./invocationSchema.js";
import type {
  SecurityEvidenceRef,
  SecurityFindingState,
  SecuritySourceLocation,
} from "./securityAuditTypes.js";
import { summarizeSecurityCoverage } from "./securityCoverage.js";
import type { SecurityCoverageGap, SecurityCoverageSummary } from "./securityCoverageTypes.js";
import { validateSecurityAuditStateEnvelope } from "./securityAuditState.js";
import type {
  SecurityAuditFindingEntry,
  SecurityAuditStateEnvelope,
  SecurityFindingSourceDisposition,
} from "./securityAuditStateTypes.js";
import type {
  SecurityCanonicalFinding,
  SecurityCanonicalFindingsEnvelope,
  SecurityCanonicalFindingsRecord,
  SecurityCanonicalValidatorProvenance,
  SecurityFindingMarkdownView,
  SecurityReportBundle,
  SecurityReportComparison,
  SecurityReportComparisonStatus,
  SecurityReportFindingComparison,
  SecurityReportRiskStatus,
} from "./securityReportTypes.js";

export type * from "./securityReportTypes.js";

const MAX_FINDINGS = 10_000;

function exactText(value: string, label: string, maximum = 4_000): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) throw new TypeError(`${label} is invalid`);
  return value;
}

function normalizeRefs(
  refs: readonly SecurityEvidenceRef[],
  label: string,
): readonly SecurityEvidenceRef[] {
  if (!Array.isArray(refs) || refs.length > 2_000) {
    throw new RangeError(`${label} count is invalid`);
  }
  const seen = new Set<string>();
  const out = refs.map((ref, index) => {
    const id = exactText(ref.id, `${label}[${index}].id`, 256);
    if (seen.has(id)) throw new Error(`${label} contains duplicate ids`);
    seen.add(id);
    return Object.freeze({
      id,
      sha256: sha(ref.sha256, `${label}[${index}].sha256`)! ,
    });
  });
  return Object.freeze(out.sort((a, b) => a.id.localeCompare(b.id)));
}

function normalizeLocations(
  locations: readonly SecuritySourceLocation[],
): readonly SecuritySourceLocation[] {
  if (!Array.isArray(locations) || locations.length < 1 || locations.length > 2_000) {
    throw new RangeError("canonical finding source location count is invalid");
  }
  const out = locations.map((location, index) => {
    const path = exactText(location.path, `sourceLocations[${index}].path`, 2_048).replace(/\\/g, "/");
    if (path.startsWith("/") || /^[A-Za-z]:\//.test(path) || path.split("/").some((part) => !part || part === "." || part === "..")) {
      throw new TypeError(`sourceLocations[${index}].path is unsafe`);
    }
    if (!Number.isSafeInteger(location.startLine) || location.startLine < 1 || !Number.isSafeInteger(location.endLine) || location.endLine < location.startLine) {
      throw new RangeError(`sourceLocations[${index}] line range is invalid`);
    }
    return Object.freeze({ path, startLine: location.startLine, endLine: location.endLine });
  });
  return Object.freeze(out.sort((a, b) => a.path.localeCompare(b.path) || a.startLine - b.startLine || a.endLine - b.endLine));
}

function expectedRisk(
  proofStatus: SecurityFindingState,
  sourceDisposition: SecurityFindingSourceDisposition,
): SecurityReportRiskStatus {
  if (sourceDisposition === "INVALIDATED_SOURCE_CHANGE") return "STALE_SOURCE";
  switch (proofStatus) {
    case "CANDIDATE": return "POTENTIAL";
    case "NEEDS_VALIDATION": return "NEEDS_VALIDATION";
    case "CONFIRMED": return "VERIFIED";
    case "REJECTED": return "DISPROVEN";
  }
}

function canonicalFinding(
  state: SecurityAuditStateEnvelope,
  entry: SecurityAuditFindingEntry,
): SecurityCanonicalFinding {
  const finding = entry.finding;
  const model = state.record.threatModels.find((candidate) =>
    candidate.recordSha256 === finding.record.threatModelRecordSha256,
  );
  if (!model) throw new Error("canonical finding references threat model outside audit history");
  const stateEvidence = finding.record.stateEvidence;
  const validatorProvenance: SecurityCanonicalValidatorProvenance =
    stateEvidence.state === "CONFIRMED"
      ? Object.freeze({ level: "IDENTITY_ONLY", validatorIdentitySha256: stateEvidence.validatorIdentitySha256 })
      : Object.freeze({ level: "NONE", validatorIdentitySha256: null });
  return Object.freeze({
    schemaVersion: "toadaid.security-canonical-finding.v1",
    findingId: finding.record.findingId,
    findingRecordSha256: finding.recordSha256,
    findingRevision: finding.record.revision,
    title: finding.record.title,
    severity: "UNASSESSED",
    riskStatus: expectedRisk(finding.record.state, entry.sourceDisposition),
    attackClass: finding.record.attackClass,
    proofStatus: finding.record.state,
    sourceDisposition: entry.sourceDisposition,
    sourceChangeSha256: entry.sourceChangeSha256,
    affectedRevision: model.record.binding.sourceRevision,
    affectedSourceTreeSha256: model.record.binding.sourceTreeSha256,
    evidenceRefs: finding.record.evidenceRefs,
    proofEvidenceRefs: stateEvidence.state === "CONFIRMED" ? stateEvidence.proofEvidenceRefs : Object.freeze([]),
    disproofEvidenceRefs: stateEvidence.state === "REJECTED" ? stateEvidence.disproofEvidenceRefs : Object.freeze([]),
    sourceLocations: finding.record.sourceLocations,
    validatorProvenance,
    updatedAt: finding.record.updatedAt,
  });
}

function normalizeCanonicalFinding(input: SecurityCanonicalFinding): SecurityCanonicalFinding {
  if (input.schemaVersion !== "toadaid.security-canonical-finding.v1") throw new TypeError("unsupported canonical security finding schemaVersion");
  if (!Number.isSafeInteger(input.findingRevision) || input.findingRevision < 0) throw new RangeError("canonical finding revision is invalid");
  if (input.severity !== "UNASSESSED") throw new Error("SEC7 v1 refuses inferred vulnerability severity; severity must be UNASSESSED");
  const expected = expectedRisk(input.proofStatus, input.sourceDisposition);
  if (input.riskStatus !== expected) throw new Error("canonical finding risk status does not match proof/source truth");
  const sourceChangeSha256 = input.sourceChangeSha256 === null ? null : sha(input.sourceChangeSha256, "sourceChangeSha256")!;
  if (input.sourceDisposition === "CURRENT_REVISION" && sourceChangeSha256 !== null) throw new Error("current canonical finding cannot carry source-change lineage");
  if (input.sourceDisposition !== "CURRENT_REVISION" && sourceChangeSha256 === null) throw new Error("historical canonical finding requires source-change lineage");
  const proofEvidenceRefs = normalizeRefs(input.proofEvidenceRefs, "proofEvidenceRefs");
  const disproofEvidenceRefs = normalizeRefs(input.disproofEvidenceRefs, "disproofEvidenceRefs");
  if (input.proofStatus === "CONFIRMED") {
    if (proofEvidenceRefs.length < 1 || disproofEvidenceRefs.length !== 0 || input.validatorProvenance.level !== "IDENTITY_ONLY" || input.validatorProvenance.validatorIdentitySha256 === null) {
      throw new Error("confirmed canonical finding requires proof and validator identity provenance");
    }
  } else if (input.proofStatus === "REJECTED") {
    if (disproofEvidenceRefs.length < 1 || proofEvidenceRefs.length !== 0) throw new Error("rejected canonical finding requires disproof evidence only");
  } else if (proofEvidenceRefs.length !== 0 || disproofEvidenceRefs.length !== 0) {
    throw new Error("unconfirmed canonical finding cannot claim proof/disproof evidence");
  }
  if (input.proofStatus !== "CONFIRMED" && (input.validatorProvenance.level !== "NONE" || input.validatorProvenance.validatorIdentitySha256 !== null)) {
    throw new Error("non-confirmed canonical finding cannot claim validator provenance");
  }
  return Object.freeze({
    schemaVersion: "toadaid.security-canonical-finding.v1",
    findingId: exactText(input.findingId, "findingId", 256),
    findingRecordSha256: sha(input.findingRecordSha256, "findingRecordSha256")!,
    findingRevision: input.findingRevision,
    title: exactText(input.title, "title"),
    severity: "UNASSESSED",
    riskStatus: expected,
    attackClass: input.attackClass,
    proofStatus: input.proofStatus,
    sourceDisposition: input.sourceDisposition,
    sourceChangeSha256,
    affectedRevision: exactText(input.affectedRevision, "affectedRevision", 256),
    affectedSourceTreeSha256: sha(input.affectedSourceTreeSha256, "affectedSourceTreeSha256")!,
    evidenceRefs: normalizeRefs(input.evidenceRefs, "evidenceRefs"),
    proofEvidenceRefs,
    disproofEvidenceRefs,
    sourceLocations: normalizeLocations(input.sourceLocations),
    validatorProvenance: Object.freeze({
      level: input.validatorProvenance.level,
      validatorIdentitySha256: input.validatorProvenance.validatorIdentitySha256 === null ? null : sha(input.validatorProvenance.validatorIdentitySha256, "validatorIdentitySha256")!,
    }),
    updatedAt: canonicalIso(input.updatedAt, "updatedAt"),
  });
}

function idsForState(findings: readonly SecurityCanonicalFinding[], state: SecurityFindingState): readonly string[] {
  return Object.freeze(findings.filter((finding) => finding.proofStatus === state).map((finding) => finding.findingId).sort());
}

function staleIds(findings: readonly SecurityCanonicalFinding[]): readonly string[] {
  return Object.freeze(findings.filter((finding) => finding.sourceDisposition === "INVALIDATED_SOURCE_CHANGE").map((finding) => finding.findingId).sort());
}

function normalizeSortedIds(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.length > MAX_FINDINGS) throw new RangeError(`${label} count is invalid`);
  const out = values.map((value, index) => exactText(value, `${label}[${index}]`, 256));
  const sorted = [...new Set(out)].sort();
  if (sorted.length !== out.length || JSON.stringify(sorted) !== JSON.stringify(out)) throw new Error(`${label} must be unique and sorted`);
  return Object.freeze(sorted);
}

function coverageGapRank(disposition: "UNEXPLORED" | "THIN"): number {
  return disposition === "UNEXPLORED" ? 0 : 1;
}

function normalizeCoverageGaps(
  gaps: readonly SecurityCoverageGap[],
  summary: SecurityCoverageSummary,
): readonly SecurityCoverageGap[] {
  if (!Array.isArray(gaps) || gaps.length > summary.totalCells) {
    throw new RangeError("coverageSummary.gaps count is invalid");
  }

  const seen = new Set<string>();
  const normalized = gaps.map((gap, index) => {
    const cellId = sha(gap.cellId, `coverageSummary.gaps[${index}].cellId`)!;
    if (seen.has(cellId)) throw new Error("coverageSummary.gaps contains duplicate cellId");
    seen.add(cellId);

    const areaId = exactText(gap.areaId, `coverageSummary.gaps[${index}].areaId`, 256);
    if (
      gap.attackClass !== "AUTHORIZATION_BYPASS" &&
      gap.attackClass !== "COMMAND_EXECUTION_INJECTION" &&
      gap.attackClass !== "DESERIALIZATION_OR_INTEGRITY" &&
      gap.attackClass !== "INPUT_INJECTION" &&
      gap.attackClass !== "ORIGIN_OR_BROWSER_BOUNDARY" &&
      gap.attackClass !== "PATH_TRAVERSAL" &&
      gap.attackClass !== "SECRET_EXPOSURE" &&
      gap.attackClass !== "SSRF_OR_NETWORK_PIVOT" &&
      gap.attackClass !== "STATE_TAMPERING" &&
      gap.attackClass !== "SUPPLY_CHAIN"
    ) {
      throw new TypeError(`coverageSummary.gaps[${index}].attackClass is invalid`);
    }
    if (gap.disposition !== "UNEXPLORED" && gap.disposition !== "THIN") {
      throw new TypeError(`coverageSummary.gaps[${index}].disposition must be UNEXPLORED or THIN`);
    }
    if (!Number.isSafeInteger(gap.inspectionCount) || gap.inspectionCount < 0) {
      throw new RangeError(`coverageSummary.gaps[${index}].inspectionCount is invalid`);
    }
    if (gap.disposition === "UNEXPLORED" && gap.inspectionCount !== 0) {
      throw new Error("UNEXPLORED coverage gap cannot claim inspections");
    }
    if (gap.disposition === "THIN" && gap.inspectionCount < 1) {
      throw new Error("THIN coverage gap requires at least one inspection");
    }
    return Object.freeze({
      cellId,
      areaId,
      attackClass: gap.attackClass,
      disposition: gap.disposition,
      inspectionCount: gap.inspectionCount,
    });
  });

  normalized.sort((a, b) =>
    coverageGapRank(a.disposition) - coverageGapRank(b.disposition) ||
    a.inspectionCount - b.inspectionCount ||
    a.areaId.localeCompare(b.areaId) ||
    a.attackClass.localeCompare(b.attackClass),
  );

  const unexplored = normalized.filter((gap) => gap.disposition === "UNEXPLORED").length;
  const thin = normalized.filter((gap) => gap.disposition === "THIN").length;
  if (
    normalized.length !== summary.unexploredCells + summary.thinCells ||
    unexplored !== summary.unexploredCells ||
    thin !== summary.thinCells
  ) {
    throw new Error("coverageSummary.gaps do not reconcile with unexplored/thin counts");
  }

  return Object.freeze(normalized);
}

function normalizeCanonicalRecord(record: SecurityCanonicalFindingsRecord): SecurityCanonicalFindingsRecord {
  if (record.schemaVersion !== "toadaid.security-canonical-findings.v1") throw new TypeError("unsupported canonical findings schemaVersion");
  if (!Number.isSafeInteger(record.auditStateRevision) || record.auditStateRevision < 0) throw new RangeError("canonical findings audit-state revision is invalid");
  if (!Array.isArray(record.findings) || record.findings.length > MAX_FINDINGS) throw new RangeError("canonical findings count is invalid");
  const seen = new Set<string>();
  const findings = record.findings.map((input) => {
    const finding = normalizeCanonicalFinding(input);
    if (seen.has(finding.findingId)) throw new Error("canonical findings contains duplicate findingId");
    seen.add(finding.findingId);
    return finding;
  }).sort((a, b) => a.findingId.localeCompare(b.findingId));
  const candidateFindingIds = normalizeSortedIds(record.candidateFindingIds, "candidateFindingIds");
  const needsValidationFindingIds = normalizeSortedIds(record.needsValidationFindingIds, "needsValidationFindingIds");
  const confirmedFindingIds = normalizeSortedIds(record.confirmedFindingIds, "confirmedFindingIds");
  const rejectedFindingIds = normalizeSortedIds(record.rejectedFindingIds, "rejectedFindingIds");
  const staleSourceFindingIds = normalizeSortedIds(record.staleSourceFindingIds, "staleSourceFindingIds");
  const expectedLists = [
    [candidateFindingIds, idsForState(findings, "CANDIDATE"), "candidateFindingIds"],
    [needsValidationFindingIds, idsForState(findings, "NEEDS_VALIDATION"), "needsValidationFindingIds"],
    [confirmedFindingIds, idsForState(findings, "CONFIRMED"), "confirmedFindingIds"],
    [rejectedFindingIds, idsForState(findings, "REJECTED"), "rejectedFindingIds"],
    [staleSourceFindingIds, staleIds(findings), "staleSourceFindingIds"],
  ] as const;
  for (const [actual, expected, label] of expectedLists) {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label} does not match canonical findings`);
  }
  const c = record.coverageSummary;
  if (!Number.isSafeInteger(c.totalCells) || !Number.isSafeInteger(c.unexploredCells) || !Number.isSafeInteger(c.thinCells) || !Number.isSafeInteger(c.coveredCells) || c.totalCells < 0 || c.unexploredCells < 0 || c.thinCells < 0 || c.coveredCells < 0) throw new RangeError("coverage summary counts are invalid");
  if (c.unexploredCells + c.thinCells + c.coveredCells !== c.totalCells) throw new Error("coverage summary counts do not add to total");
  if (
    typeof c.inspectionBreadthPercent !== "number" ||
    !Number.isFinite(c.inspectionBreadthPercent) ||
    c.inspectionBreadthPercent < 0 ||
    c.inspectionBreadthPercent > 100
  ) throw new RangeError("coverage inspection breadth is invalid");
  const expectedBreadth = c.totalCells === 0
    ? 0
    : Number((((c.thinCells + c.coveredCells) / c.totalCells) * 100).toFixed(6));
  if (c.inspectionBreadthPercent !== expectedBreadth) {
    throw new Error("coverage inspection breadth does not match canonical counts");
  }
  const coverageGaps = normalizeCoverageGaps(c.gaps, c);
  return Object.freeze({
    schemaVersion: "toadaid.security-canonical-findings.v1",
    auditId: exactText(record.auditId, "auditId", 256),
    auditStateRevision: record.auditStateRevision,
    auditStateRecordSha256: sha(record.auditStateRecordSha256, "auditStateRecordSha256")!,
    repositoryIdentitySha256: sha(record.repositoryIdentitySha256, "repositoryIdentitySha256")!,
    currentSourceRevision: exactText(record.currentSourceRevision, "currentSourceRevision", 256),
    currentSourceTreeSha256: sha(record.currentSourceTreeSha256, "currentSourceTreeSha256")!,
    currentThreatModelRecordSha256: sha(record.currentThreatModelRecordSha256, "currentThreatModelRecordSha256")!,
    generatedFromStateUpdatedAt: canonicalIso(record.generatedFromStateUpdatedAt, "generatedFromStateUpdatedAt"),
    runtimeProvenance: Object.freeze({
      providerIdentitySha256: record.runtimeProvenance.providerIdentitySha256 === null ? null : sha(record.runtimeProvenance.providerIdentitySha256, "providerIdentitySha256")!,
      modelIdentitySha256: record.runtimeProvenance.modelIdentitySha256 === null ? null : sha(record.runtimeProvenance.modelIdentitySha256, "modelIdentitySha256")!,
    }),
    coverageSummary: Object.freeze({
      totalCells: c.totalCells,
      unexploredCells: c.unexploredCells,
      thinCells: c.thinCells,
      coveredCells: c.coveredCells,
      inspectionBreadthPercent: c.inspectionBreadthPercent,
      gaps: coverageGaps,
    }),
    findings: Object.freeze(findings),
    candidateFindingIds,
    needsValidationFindingIds,
    confirmedFindingIds,
    rejectedFindingIds,
    staleSourceFindingIds,
  });
}

export function securityCanonicalFindingsRecordSha256(record: SecurityCanonicalFindingsRecord): string {
  return sha256(record);
}

export function sealCanonicalSecurityFindingsRecord(record: SecurityCanonicalFindingsRecord): SecurityCanonicalFindingsEnvelope {
  const normalized = normalizeCanonicalRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.security-canonical-findings-envelope.v1",
    record: normalized,
    recordSha256: securityCanonicalFindingsRecordSha256(normalized),
  });
}

export function validateCanonicalSecurityFindings(envelope: SecurityCanonicalFindingsEnvelope): SecurityCanonicalFindingsEnvelope {
  if (envelope.schemaVersion !== "toadaid.security-canonical-findings-envelope.v1") throw new TypeError("unsupported canonical findings envelope schemaVersion");
  const record = normalizeCanonicalRecord(envelope.record);
  const digest = sha(envelope.recordSha256, "recordSha256")!;
  if (digest !== securityCanonicalFindingsRecordSha256(record)) throw new Error("canonical findings integrity mismatch");
  return Object.freeze({ schemaVersion: "toadaid.security-canonical-findings-envelope.v1", record, recordSha256: digest });
}

export function buildCanonicalSecurityFindings(stateInput: SecurityAuditStateEnvelope): SecurityCanonicalFindingsEnvelope {
  const state = validateSecurityAuditStateEnvelope(stateInput);
  const currentModel = state.record.threatModels[state.record.threatModels.length - 1]!;
  const findings = Object.freeze(state.record.findings.map((entry) => canonicalFinding(state, entry)).sort((a, b) => a.findingId.localeCompare(b.findingId)));
  return sealCanonicalSecurityFindingsRecord({
    schemaVersion: "toadaid.security-canonical-findings.v1",
    auditId: state.record.auditId,
    auditStateRevision: state.record.revision,
    auditStateRecordSha256: state.recordSha256,
    repositoryIdentitySha256: currentModel.record.binding.repositoryIdentitySha256,
    currentSourceRevision: currentModel.record.binding.sourceRevision,
    currentSourceTreeSha256: currentModel.record.binding.sourceTreeSha256,
    currentThreatModelRecordSha256: currentModel.recordSha256,
    generatedFromStateUpdatedAt: state.record.updatedAt,
    runtimeProvenance: state.record.runtimeProvenance,
    coverageSummary: summarizeSecurityCoverage(currentModel, state.record.coverageLedger),
    findings,
    candidateFindingIds: idsForState(findings, "CANDIDATE"),
    needsValidationFindingIds: idsForState(findings, "NEEDS_VALIDATION"),
    confirmedFindingIds: idsForState(findings, "CONFIRMED"),
    rejectedFindingIds: idsForState(findings, "REJECTED"),
    staleSourceFindingIds: staleIds(findings),
  });
}

export function validateCanonicalSecurityFindingsAgainstState(stateInput: SecurityAuditStateEnvelope, documentInput: SecurityCanonicalFindingsEnvelope): SecurityCanonicalFindingsEnvelope {
  const state = validateSecurityAuditStateEnvelope(stateInput);
  const document = validateCanonicalSecurityFindings(documentInput);
  const expected = buildCanonicalSecurityFindings(state);
  if (document.recordSha256 !== expected.recordSha256) throw new Error("canonical findings do not match authoritative audit state");
  return document;
}

export function serializeCanonicalSecurityFindings(envelopeInput: SecurityCanonicalFindingsEnvelope): string {
  const envelope = validateCanonicalSecurityFindings(envelopeInput);
  return JSON.stringify(envelope, null, 2) + "\n";
}

export function parseCanonicalSecurityFindings(serialized: string): SecurityCanonicalFindingsEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); }
  catch { throw new TypeError("canonical findings serialization is invalid JSON"); }
  return validateCanonicalSecurityFindings(parsed as SecurityCanonicalFindingsEnvelope);
}

function md(value: string): string {
  return value.replace(/([\\`*_[\]<>#])/g, "\\$1");
}

function refsLine(refs: readonly SecurityEvidenceRef[]): string {
  return refs.length === 0 ? "none" : refs.map((ref) => `${md(ref.id)} (\`${ref.sha256}\`)`).join(", ");
}

function locationsLine(locations: readonly SecuritySourceLocation[]): string {
  return locations.map((location) => `\`${location.path}:${location.startLine}-${location.endLine}\``).join(", ");
}

function renderFinding(finding: SecurityCanonicalFinding): string {
  const lines = [
    `# ${md(finding.findingId)} — ${md(finding.title)}`,
    "",
    `- Proof status: **${finding.proofStatus}**`,
    `- Risk status: **${finding.riskStatus}**`,
    `- Severity: **${finding.severity}**`,
    `- Attack class: \`${finding.attackClass}\``,
    `- Source disposition: \`${finding.sourceDisposition}\``,
    `- Affected revision: \`${finding.affectedRevision}\``,
    `- Affected source tree: \`${finding.affectedSourceTreeSha256}\``,
    `- Finding record: \`${finding.findingRecordSha256}\``,
    `- Locations: ${locationsLine(finding.sourceLocations)}`,
    `- Evidence: ${refsLine(finding.evidenceRefs)}`,
    `- Proof evidence: ${refsLine(finding.proofEvidenceRefs)}`,
    `- Disproof evidence: ${refsLine(finding.disproofEvidenceRefs)}`,
    `- Validator provenance: ${finding.validatorProvenance.validatorIdentitySha256 === null ? "none" : `identity-only (\`${finding.validatorProvenance.validatorIdentitySha256}\`)`}`,
  ];
  if (finding.sourceChangeSha256 !== null) lines.push(`- Source-change evidence: \`${finding.sourceChangeSha256}\``);
  lines.push("");
  return lines.join("\n");
}

export function renderSecurityFindingMarkdown(stateInput: SecurityAuditStateEnvelope, findingIdInput: string): string {
  const document = buildCanonicalSecurityFindings(stateInput);
  const findingId = exactText(findingIdInput, "findingId", 256);
  const finding = document.record.findings.find((entry) => entry.findingId === findingId);
  if (!finding) throw new Error("unknown canonical findingId");
  return renderFinding(finding);
}

export function renderSecurityNeedsValidationMarkdown(stateInput: SecurityAuditStateEnvelope): string {
  const document = buildCanonicalSecurityFindings(stateInput);
  const queue = document.record.findings.filter((finding) => finding.proofStatus === "NEEDS_VALIDATION" && finding.sourceDisposition !== "INVALIDATED_SOURCE_CHANGE");
  const lines = ["# NEEDS_VALIDATION Queue", "", `Audit: \`${document.record.auditId}\``, `Source: \`${document.record.currentSourceRevision}\``, ""];
  if (queue.length === 0) lines.push("No current-source findings require validation.", "");
  else {
    for (const finding of queue) lines.push(`- \`${finding.findingId}\` — ${md(finding.title)} — \`${finding.attackClass}\``);
    lines.push("");
  }
  return lines.join("\n");
}

export function renderSecurityAuditReportMarkdown(stateInput: SecurityAuditStateEnvelope): string {
  const document = buildCanonicalSecurityFindings(stateInput);
  const r = document.record;
  const c = r.coverageSummary;
  const count = (state: SecurityFindingState) => r.findings.filter((finding) => finding.proofStatus === state).length;
  const queue = r.findings.filter((finding) => finding.proofStatus === "NEEDS_VALIDATION" && finding.sourceDisposition !== "INVALIDATED_SOURCE_CHANGE");
  const lines = [
    "# Security Audit Report", "",
    `- Audit: \`${r.auditId}\``,
    `- Audit-state revision: \`${r.auditStateRevision}\``,
    `- Audit-state SHA: \`${r.auditStateRecordSha256}\``,
    `- Source revision: \`${r.currentSourceRevision}\``,
    `- Source tree: \`${r.currentSourceTreeSha256}\``,
    `- Canonical findings SHA: \`${document.recordSha256}\``, "",
    "## Finding Summary", "",
    `- Candidate: ${count("CANDIDATE")}`,
    `- Needs validation: ${count("NEEDS_VALIDATION")}`,
    `- Confirmed: ${count("CONFIRMED")}`,
    `- Rejected: ${count("REJECTED")}`,
    `- Stale source: ${r.staleSourceFindingIds.length}`, "",
    "Severity is `UNASSESSED` in SEC7 v1 unless a future governed severity-assessment lane supplies canonical severity evidence.", "",
    "## Coverage Summary", "",
    `- Total cells: ${c.totalCells}`,
    `- Covered: ${c.coveredCells}`,
    `- Thin: ${c.thinCells}`,
    `- Unexplored: ${c.unexploredCells}`,
    `- Inspection breadth: ${c.inspectionBreadthPercent}%`, "",
    "## NEEDS_VALIDATION Queue", "",
  ];
  if (queue.length === 0) lines.push("No current-source findings require validation.");
  else for (const finding of queue) lines.push(`- \`${finding.findingId}\` — ${md(finding.title)}`);
  lines.push("", "## Findings", "");
  if (r.findings.length === 0) lines.push("No canonical findings are recorded.", "");
  else for (const finding of r.findings) lines.push(
    `### ${md(finding.findingId)} — ${md(finding.title)}`, "",
    `- Proof: **${finding.proofStatus}**`,
    `- Risk: **${finding.riskStatus}**`,
    `- Severity: **${finding.severity}**`,
    `- Attack class: \`${finding.attackClass}\``,
    `- Source: \`${finding.sourceDisposition}\``,
    `- Affected revision: \`${finding.affectedRevision}\``,
    `- Locations: ${locationsLine(finding.sourceLocations)}`,
    `- Evidence: ${refsLine(finding.evidenceRefs)}`,
    `- Proof evidence: ${refsLine(finding.proofEvidenceRefs)}`,
    `- Disproof evidence: ${refsLine(finding.disproofEvidenceRefs)}`, "",
  );
  lines.push("## Coverage Gaps", "");
  if (c.gaps.length === 0) lines.push("No coverage gaps remain.", "");
  else {
    for (const gap of c.gaps) lines.push(`- \`${gap.areaId}\` × \`${gap.attackClass}\` — **${gap.disposition}** — inspections: ${gap.inspectionCount}`);
    lines.push("");
  }
  lines.push("## Reporting Law", "", "This report is presentation-only. It cannot confirm a candidate, revive rejected evidence, grant repair authority, execute a fix, or claim that stale source evidence is current.", "");
  return lines.join("\n");
}

export function generateSecurityReportBundle(stateInput: SecurityAuditStateEnvelope): SecurityReportBundle {
  const state = validateSecurityAuditStateEnvelope(stateInput);
  const canonicalFindings = buildCanonicalSecurityFindings(state);
  validateCanonicalSecurityFindingsAgainstState(state, canonicalFindings);
  const findingsJson = serializeCanonicalSecurityFindings(canonicalFindings);
  const reportMarkdown = renderSecurityAuditReportMarkdown(state);
  const needsValidationMarkdown = renderSecurityNeedsValidationMarkdown(state);
  const detailedFindings: SecurityFindingMarkdownView[] = canonicalFindings.record.findings.map((finding) => Object.freeze({ findingId: finding.findingId, markdown: renderSecurityFindingMarkdown(state, finding.findingId) }));
  return Object.freeze({
    schemaVersion: "toadaid.security-report-bundle.v1",
    canonicalFindings,
    findingsJson,
    reportMarkdown,
    needsValidationMarkdown,
    detailedFindings: Object.freeze(detailedFindings),
    findingsJsonSha256: sha256(findingsJson),
    reportMarkdownSha256: sha256(reportMarkdown),
  });
}

function comparisonStatus(previous: SecurityCanonicalFinding | undefined, current: SecurityCanonicalFinding): SecurityReportComparisonStatus {
  if (current.sourceDisposition === "INVALIDATED_SOURCE_CHANGE") return "STALE_SOURCE";
  if (!previous) return "NEW";
  if (previous.proofStatus === "CONFIRMED" && current.proofStatus === "REJECTED") return "FIXED";
  if (previous.proofStatus !== "REJECTED" && previous.proofStatus !== "CONFIRMED" && current.proofStatus === "REJECTED") return "RESOLVED";
  if (previous.proofStatus === "REJECTED" && current.proofStatus !== "REJECTED") return "REGRESSED";
  if (previous.proofStatus === "REJECTED" && current.proofStatus === "REJECTED") return "STILL_CLOSED";
  return "STILL_OPEN";
}

export function compareSecurityReportRevisions(previousStateInput: SecurityAuditStateEnvelope, currentStateInput: SecurityAuditStateEnvelope): SecurityReportComparison {
  const previous = buildCanonicalSecurityFindings(previousStateInput);
  const current = buildCanonicalSecurityFindings(currentStateInput);
  if (previous.record.auditId !== current.record.auditId || previous.record.repositoryIdentitySha256 !== current.record.repositoryIdentitySha256) throw new Error("security report comparison cannot cross audits or repositories");
  if (current.record.auditStateRevision <= previous.record.auditStateRevision) throw new Error("security report comparison requires a later audit-state revision");
  const previousById = new Map(previous.record.findings.map((finding) => [finding.findingId, finding]));
  const currentIds = new Set(current.record.findings.map((finding) => finding.findingId));
  for (const finding of previous.record.findings) if (!currentIds.has(finding.findingId)) throw new Error("security report comparison detected erased durable finding");
  const findings: SecurityReportFindingComparison[] = current.record.findings.map((finding) => {
    const prior = previousById.get(finding.findingId);
    return Object.freeze({
      findingId: finding.findingId,
      status: comparisonStatus(prior, finding),
      previousProofStatus: prior?.proofStatus ?? null,
      currentProofStatus: finding.proofStatus,
      previousFindingRecordSha256: prior?.findingRecordSha256 ?? null,
      currentFindingRecordSha256: finding.findingRecordSha256,
    });
  });
  return Object.freeze({
    schemaVersion: "toadaid.security-report-comparison.v1",
    auditId: current.record.auditId,
    repositoryIdentitySha256: current.record.repositoryIdentitySha256,
    fromAuditStateRevision: previous.record.auditStateRevision,
    toAuditStateRevision: current.record.auditStateRevision,
    fromSourceRevision: previous.record.currentSourceRevision,
    toSourceRevision: current.record.currentSourceRevision,
    findings: Object.freeze(findings),
  });
}

export function renderSecurityReportComparisonMarkdown(previousState: SecurityAuditStateEnvelope, currentState: SecurityAuditStateEnvelope): string {
  const comparison = compareSecurityReportRevisions(previousState, currentState);
  const lines = [
    "# Security Audit Revision Comparison", "",
    `- Audit: \`${comparison.auditId}\``,
    `- From state revision: \`${comparison.fromAuditStateRevision}\``,
    `- To state revision: \`${comparison.toAuditStateRevision}\``,
    `- From source: \`${comparison.fromSourceRevision}\``,
    `- To source: \`${comparison.toSourceRevision}\``, "",
  ];
  for (const status of ["NEW", "FIXED", "RESOLVED", "REGRESSED", "STILL_OPEN", "STILL_CLOSED", "STALE_SOURCE"] as const) {
    lines.push(`## ${status}`, "");
    const rows = comparison.findings.filter((finding) => finding.status === status);
    if (rows.length === 0) lines.push("None.", "");
    else {
      for (const row of rows) lines.push(`- \`${row.findingId}\` — ${row.previousProofStatus ?? "NONE"} → ${row.currentProofStatus}`);
      lines.push("");
    }
  }
  lines.push("`FIXED` means a predecessor-bound CONFIRMED finding became REJECTED in canonical truth. It does not, by itself, prove which code change caused closure. `STALE_SOURCE` is never counted as fixed.", "");
  return lines.join("\n");
}
