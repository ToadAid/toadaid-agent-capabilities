import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  createSecurityFindingCandidate,
  createSecurityThreatModel,
  sealSecurityFindingRecord,
} from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
  recordSecurityCoverage,
} from "../src/securityCoverage.js";
import {
  checkpointSecurityAuditState,
  createSecurityAuditState,
  rebaseSecurityAuditStateSource,
} from "../src/securityAuditState.js";
import {
  buildCanonicalSecurityFindings,
  compareSecurityReportRevisions,
  generateSecurityReportBundle,
  parseCanonicalSecurityFindings,
  renderSecurityAuditReportMarkdown,
  renderSecurityFindingMarkdown,
  renderSecurityNeedsValidationMarkdown,
  renderSecurityReportComparisonMarkdown,
  sealCanonicalSecurityFindingsRecord,
  serializeCanonicalSecurityFindings,
  validateCanonicalSecurityFindingsAgainstState,
} from "../src/securityReport.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const H8 = "8".repeat(64);
const H9 = "9".repeat(64);

function allow(capabilityId: string): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: "ALLOW",
    reason: "AUTHORIZED_BY_POLICY",
    trace: [],
  };
}

function model(sourceRevision: string, sourceTreeSha256: string) {
  return createSecurityThreatModel({
    auditId: "sec7-audit",
    runId: "sec7-run",
    repositoryIdentitySha256: H1,
    sourceRevision,
    sourceTreeSha256,
    scope: { includePaths: ["src"], excludePaths: [] },
    configurationSha256: H2,
    ruleSetSha256: H3,
    architecture: {
      components: [{
        componentId: "policy",
        kind: "SECURITY_CONTROL",
        label: "Policy",
        sourcePaths: ["src/policy/check.ts"],
        riskSignals: ["AUTHORITY_BOUNDARY"],
      }],
      trustBoundaries: [],
    },
    createdAt: sourceRevision === "rev-a" ? "2026-10-03T23:00:00.000Z" : "2026-10-03T23:30:00.000Z",
  });
}

function fixture() {
  const threatModel = model("rev-a", H4);
  let coverage = createSecurityCoverageLedger(threatModel, {
    ledgerId: "sec7-coverage",
    areas: [{ areaId: "policy", label: "Policy", paths: ["src/policy"] }],
    createdAt: "2026-10-03T23:00:00.000Z",
  });
  coverage = recordSecurityCoverage(threatModel, coverage, {
    areaId: "policy",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "coverage-evidence", sha256: H5 }],
    inspectedAt: "2026-10-03T23:01:00.000Z",
  });
  const candidate = createSecurityFindingCandidate(threatModel, {
    findingId: "finding-auth",
    attackClass: "AUTHORIZATION_BYPASS",
    title: "Authorization boundary candidate",
    rationale: "Requires independent validation",
    evidenceRefs: [{ id: "candidate-evidence", sha256: H6 }],
    sourceLocations: [{ path: "src/policy/check.ts", startLine: 10, endLine: 20 }],
    createdAt: "2026-10-03T23:02:00.000Z",
  });
  const needsValidation = sealSecurityFindingRecord({
    ...candidate.record,
    revision: 1,
    state: "NEEDS_VALIDATION",
    stateEvidence: { state: "NEEDS_VALIDATION", reason: "Needs sandbox reproduction" },
    updatedAt: "2026-10-03T23:03:00.000Z",
    continuity: { previousRecordSha256: candidate.recordSha256 },
  });
  const state = createSecurityAuditState({
    threatModel,
    coverageLedger: coverage,
    findings: [{ finding: needsValidation, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
    authoritySnapshot: {
      capturedAt: "2026-10-03T23:00:00.000Z",
      decisions: [allow("host:file-read"), allow("host:session")],
    },
    runtimeProvenance: { providerIdentitySha256: H7, modelIdentitySha256: H8 },
    createdAt: "2026-10-03T23:00:00.000Z",
  });
  return { threatModel, coverage, candidate, needsValidation, state };
}

test("SEC7 canonical findings preserve exact proof/source/evidence truth", () => {
  const { state, needsValidation } = fixture();
  const document = buildCanonicalSecurityFindings(state);
  const finding = document.record.findings[0]!;
  assert.equal(finding.findingRecordSha256, needsValidation.recordSha256);
  assert.equal(finding.proofStatus, "NEEDS_VALIDATION");
  assert.equal(finding.riskStatus, "NEEDS_VALIDATION");
  assert.equal(finding.severity, "UNASSESSED");
  assert.equal(finding.affectedRevision, "rev-a");
});

test("SEC7 findings.json round-trip is deterministic and schema validated", () => {
  const { state } = fixture();
  const document = buildCanonicalSecurityFindings(state);
  const first = serializeCanonicalSecurityFindings(document);
  const parsed = parseCanonicalSecurityFindings(first);
  assert.equal(serializeCanonicalSecurityFindings(parsed), first);
  assert.deepEqual(parsed, document);
});

test("SEC7 report is deterministic and never upgrades NEEDS_VALIDATION", () => {
  const { state } = fixture();
  const first = renderSecurityAuditReportMarkdown(state);
  assert.equal(renderSecurityAuditReportMarkdown(state), first);
  assert.match(first, /Proof: \*\*NEEDS_VALIDATION\*\*/);
  assert.doesNotMatch(first, /Proof: \*\*CONFIRMED\*\*/);
});

test("SEC7 report bundle is bound to authoritative SEC6 state", () => {
  const { state } = fixture();
  const bundle = generateSecurityReportBundle(state);
  assert.equal(bundle.canonicalFindings.record.auditStateRecordSha256, state.recordSha256);
  assert.equal(bundle.detailedFindings.length, 1);
  assert.equal(bundle.findingsJson.endsWith("\n"), true);
  assert.equal(bundle.reportMarkdown.endsWith("\n"), true);
});

test("SEC7 self-consistent forged canonical proof cannot publish against state", () => {
  const { state } = fixture();
  const canonical = buildCanonicalSecurityFindings(state);
  const original = canonical.record.findings[0]!;
  const forged = sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    findings: [{
      ...original,
      proofStatus: "CONFIRMED",
      riskStatus: "VERIFIED",
      proofEvidenceRefs: [{ id: "forged-proof", sha256: H9 }],
      validatorProvenance: { level: "IDENTITY_ONLY", validatorIdentitySha256: H9 },
    }],
    needsValidationFindingIds: [],
    confirmedFindingIds: [original.findingId],
  });
  assert.throws(() => validateCanonicalSecurityFindingsAgainstState(state, forged), /do not match authoritative audit state/);
});

test("SEC7 v1 refuses invented severity", () => {
  const { state } = fixture();
  const canonical = buildCanonicalSecurityFindings(state);
  const finding = canonical.record.findings[0]!;
  assert.throws(() => sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    findings: [{ ...finding, severity: "CRITICAL" as typeof finding.severity }],
  }), /severity must be UNASSESSED/);
});

test("SEC7 NEEDS_VALIDATION queue is mechanical", () => {
  const { state } = fixture();
  const queue = renderSecurityNeedsValidationMarkdown(state);
  assert.match(queue, /finding-auth/);
});

test("SEC7 detailed finding view carries hashes and no proof invention", () => {
  const { state } = fixture();
  const detail = renderSecurityFindingMarkdown(state, "finding-auth");
  assert.match(detail, new RegExp(H6));
  assert.match(detail, /Proof status: \*\*NEEDS_VALIDATION\*\*/);
  assert.match(detail, /Proof evidence: none/);
});

test("SEC7 rejected evidence remains visible", () => {
  const { state, needsValidation } = fixture();
  const rejected = sealSecurityFindingRecord({
    ...needsValidation.record,
    revision: 2,
    state: "REJECTED",
    stateEvidence: { state: "REJECTED", reason: "Disproved", disproofEvidenceRefs: [{ id: "disproof", sha256: H9 }] },
    updatedAt: "2026-10-03T23:04:00.000Z",
    continuity: { previousRecordSha256: needsValidation.recordSha256 },
  });
  const next = checkpointSecurityAuditState(state, {
    updatedAt: "2026-10-03T23:04:00.000Z",
    findings: [{ finding: rejected, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
  });
  const report = renderSecurityAuditReportMarkdown(next);
  assert.match(report, /Proof: \*\*REJECTED\*\*/);
  assert.match(report, new RegExp(H9));
});

test("SEC7 source rebase is STALE_SOURCE, never FIXED", () => {
  const { state } = fixture();
  const rebased = rebaseSecurityAuditStateSource(state, {
    nextThreatModel: model("rev-b", H9),
    areas: [{ areaId: "policy", label: "Policy", paths: ["src/policy"] }],
    changedPaths: ["src/policy/check.ts"],
    rebasedAt: "2026-10-03T23:30:00.000Z",
    currentAuthority: [allow("host:file-read"), allow("host:session")],
  }).state;
  const comparison = compareSecurityReportRevisions(state, rebased);
  assert.equal(comparison.findings[0]?.status, "STALE_SOURCE");
  assert.match(renderSecurityReportComparisonMarkdown(state, rebased), /## STALE_SOURCE/);
});

test("SEC7 confirmed to rejected is FIXED canonical truth", () => {
  const { state, needsValidation } = fixture();
  const confirmed = sealSecurityFindingRecord({
    ...needsValidation.record,
    revision: 2,
    state: "CONFIRMED",
    stateEvidence: { state: "CONFIRMED", validatorIdentitySha256: H7, proofEvidenceRefs: [{ id: "proof", sha256: H8 }] },
    updatedAt: "2026-10-03T23:04:00.000Z",
    continuity: { previousRecordSha256: needsValidation.recordSha256 },
  });
  const confirmedState = checkpointSecurityAuditState(state, {
    updatedAt: "2026-10-03T23:04:00.000Z",
    findings: [{ finding: confirmed, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
  });
  const rejected = sealSecurityFindingRecord({
    ...confirmed.record,
    revision: 3,
    state: "REJECTED",
    stateEvidence: { state: "REJECTED", reason: "Closed", disproofEvidenceRefs: [{ id: "closure", sha256: H9 }] },
    updatedAt: "2026-10-03T23:05:00.000Z",
    continuity: { previousRecordSha256: confirmed.recordSha256 },
  });
  const fixedState = checkpointSecurityAuditState(confirmedState, {
    updatedAt: "2026-10-03T23:05:00.000Z",
    findings: [{ finding: rejected, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
  });
  assert.equal(compareSecurityReportRevisions(confirmedState, fixedState).findings[0]?.status, "FIXED");
});

test("SEC7 rejected to open is REGRESSED", () => {
  const { state, needsValidation } = fixture();
  const rejected = sealSecurityFindingRecord({
    ...needsValidation.record,
    revision: 2,
    state: "REJECTED",
    stateEvidence: { state: "REJECTED", reason: "Disproved", disproofEvidenceRefs: [{ id: "disproof", sha256: H8 }] },
    updatedAt: "2026-10-03T23:04:00.000Z",
    continuity: { previousRecordSha256: needsValidation.recordSha256 },
  });
  const rejectedState = checkpointSecurityAuditState(state, {
    updatedAt: "2026-10-03T23:04:00.000Z",
    findings: [{ finding: rejected, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
  });
  const reopened = sealSecurityFindingRecord({
    ...rejected.record,
    revision: 3,
    state: "NEEDS_VALIDATION",
    stateEvidence: { state: "NEEDS_VALIDATION", reason: "New evidence" },
    updatedAt: "2026-10-03T23:05:00.000Z",
    continuity: { previousRecordSha256: rejected.recordSha256 },
  });
  const regressedState = checkpointSecurityAuditState(rejectedState, {
    updatedAt: "2026-10-03T23:05:00.000Z",
    findings: [{ finding: reopened, sourceDisposition: "CURRENT_REVISION", sourceChangeSha256: null }],
  });
  assert.equal(compareSecurityReportRevisions(rejectedState, regressedState).findings[0]?.status, "REGRESSED");
});

test("SEC7 comparison refuses reverse/same revision", () => {
  const { state } = fixture();
  assert.throws(() => compareSecurityReportRevisions(state, state), /requires a later audit-state revision/);
});

test("SEC7 canonical schema refuses impossible coverage gap truth", () => {
  const { state } = fixture();
  const canonical = buildCanonicalSecurityFindings(state);

  assert.throws(() => sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    coverageSummary: {
      ...canonical.record.coverageSummary,
      gaps: [{
        cellId: H9,
        areaId: "policy",
        attackClass: "AUTHORIZATION_BYPASS",
        disposition: "COVERED" as "UNEXPLORED",
        inspectionCount: -1,
      }],
    },
  }), /disposition must be UNEXPLORED or THIN|inspectionCount is invalid/);

  assert.throws(() => sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    coverageSummary: {
      ...canonical.record.coverageSummary,
      unexploredCells: 0,
      thinCells: 0,
      coveredCells: canonical.record.coverageSummary.totalCells,
    },
  }), /gaps do not reconcile|inspection breadth does not match canonical counts/);
});

test("SEC7 canonical schema requires canonical ISO timestamps", () => {
  const { state } = fixture();
  const canonical = buildCanonicalSecurityFindings(state);
  const finding = canonical.record.findings[0]!;

  assert.throws(() => sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    findings: [{
      ...finding,
      updatedAt: "not-a-timestamp",
    }],
  }), /updatedAt must be canonical ISO-8601/);

  assert.throws(() => sealCanonicalSecurityFindingsRecord({
    ...canonical.record,
    generatedFromStateUpdatedAt: "not-a-timestamp",
  }), /generatedFromStateUpdatedAt must be canonical ISO-8601/);
});
