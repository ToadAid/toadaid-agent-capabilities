import assert from "node:assert/strict";
import test from "node:test";

import { createSecurityThreatModel } from "../src/securityAudit.js";
import {
  createSecurityCoverageLedger,
  parseSecurityCoverageLedger,
  planNextSecurityHunterAssignment,
  rebaseSecurityCoverageLedger,
  recordSecurityCoverage,
  serializeSecurityCoverageLedger,
  summarizeSecurityCoverage,
  validateSecurityCoverageLedgerEnvelope,
} from "../src/securityCoverage.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const NOW = "2026-10-02T16:00:00.000Z";

function model(sourceRevision = "8c76d47", sourceTreeSha256 = H2) {
  return createSecurityThreatModel({
    auditId: `audit-${sourceRevision}`,
    runId: `run-${sourceRevision}`,
    repositoryIdentitySha256: H1,
    sourceRevision,
    sourceTreeSha256,
    scope: { includePaths: ["src"], excludePaths: ["src/generated"] },
    configurationSha256: H3,
    ruleSetSha256: H4,
    architecture: {
      components: [{
        componentId: "api",
        kind: "NETWORK_SERVICE",
        label: "API",
        sourcePaths: ["src/api.ts"],
        riskSignals: ["UNTRUSTED_INPUT", "AUTHORITY_BOUNDARY"],
      }],
      trustBoundaries: [],
    },
    createdAt: NOW,
  });
}

const areas = [
  { areaId: "api", label: "API surface", paths: ["src/api"] },
  { areaId: "policy", label: "Policy core", paths: ["src/policy"] },
] as const;

test("SEC2 creates exact area × attack-class UNEXPLORED ledger", () => {
  const threat = model();
  const ledger = createSecurityCoverageLedger(threat, {
    ledgerId: "coverage-1", areas, createdAt: NOW,
  });
  assert.equal(ledger.record.areas.length, 2);
  assert.equal(ledger.record.cells.length, 4);
  assert.equal(ledger.record.cells.every((cell) => cell.disposition === "UNEXPLORED"), true);
  assert.equal(ledger.record.inspectionBreadthPercent, 0);
});

test("SEC2 refuses coverage areas outside threat-model scope", () => {
  assert.throws(
    () => createSecurityCoverageLedger(model(), {
      areas: [{ areaId: "outside", label: "Outside", paths: ["docs"] }],
    }),
    /outside threat-model scope/,
  );
});

test("SEC2 coverage supports repeated THIN evidence then COVERED without regression", () => {
  const threat = model();
  const initial = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  const thin1 = recordSecurityCoverage(threat, initial, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "trace-1", sha256: H3 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  const thin2 = recordSecurityCoverage(threat, thin1, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "trace-2", sha256: H4 }],
    inspectedAt: "2026-10-02T16:02:00.000Z",
  });
  const covered = recordSecurityCoverage(threat, thin2, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "COVERED",
    evidenceRefs: [{ id: "trace-3", sha256: H5 }],
    inspectedAt: "2026-10-02T16:03:00.000Z",
  });
  const cell = covered.record.cells.find((entry) =>
    entry.areaId === "api" && entry.attackClass === "AUTHORIZATION_BYPASS",
  );
  assert.equal(cell?.disposition, "COVERED");
  assert.equal(cell?.inspectionCount, 3);
  assert.deepEqual(cell?.evidenceRefs.map((ref) => ref.id), ["trace-1", "trace-2", "trace-3"]);
  assert.throws(
    () => recordSecurityCoverage(threat, covered, {
      areaId: "api",
      attackClass: "AUTHORIZATION_BYPASS",
      disposition: "THIN",
      evidenceRefs: [{ id: "trace-4", sha256: H2 }],
    }),
    /COVERED security coverage cell is terminal/,
  );
});

test("SEC2 repeated THIN requires genuinely new evidence", () => {
  const threat = model();
  const initial = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  const thin = recordSecurityCoverage(threat, initial, {
    areaId: "api",
    attackClass: "INPUT_INJECTION",
    disposition: "THIN",
    evidenceRefs: [{ id: "same", sha256: H3 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  assert.throws(
    () => recordSecurityCoverage(threat, thin, {
      areaId: "api",
      attackClass: "INPUT_INJECTION",
      disposition: "THIN",
      evidenceRefs: [{ id: "same", sha256: H3 }],
      inspectedAt: "2026-10-02T16:02:00.000Z",
    }),
    /requires new evidence/,
  );
});

test("SEC2 inspection breadth is breadth evidence, not a security verdict", () => {
  const threat = model();
  let ledger = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  ledger = recordSecurityCoverage(threat, ledger, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "trace", sha256: H3 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  const summary = summarizeSecurityCoverage(threat, ledger);
  assert.equal(summary.totalCells, 4);
  assert.equal(summary.unexploredCells, 3);
  assert.equal(summary.thinCells, 1);
  assert.equal(summary.coveredCells, 0);
  assert.equal(summary.inspectionBreadthPercent, 25);
  assert.equal("secure" in summary, false);
});

test("SEC2 gap analysis prioritizes UNEXPLORED, then least-inspected THIN, deterministically", () => {
  const threat = model();
  let ledger = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  ledger = recordSecurityCoverage(threat, ledger, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "trace", sha256: H3 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  const next = planNextSecurityHunterAssignment(threat, ledger, {
    assignmentId: "hunter-1",
    budget: { modelTokens: 10_000, toolCalls: 20, networkRequests: 0, wallClockMs: 60_000 },
    plannedAt: "2026-10-02T16:02:00.000Z",
  });
  assert.equal(next?.predecessorCoverageDisposition, "UNEXPLORED");
  assert.equal(next?.areaId, "api");
  assert.equal(next?.attackClass, "INPUT_INJECTION");
});

test("SEC2 hunter assignment binds exact source scope budget and predecessor coverage", () => {
  const threat = model();
  const ledger = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  const assignment = planNextSecurityHunterAssignment(threat, ledger, {
    assignmentId: "hunter-bound",
    budget: { modelTokens: 5_000, toolCalls: 10, networkRequests: 1, wallClockMs: 30_000 },
    plannedAt: "2026-10-02T16:01:00.000Z",
  });
  assert.ok(assignment);
  assert.equal(assignment.threatModelRecordSha256, threat.recordSha256);
  assert.equal(assignment.coverageLedgerRecordSha256, ledger.recordSha256);
  assert.equal(assignment.sourceRevision, threat.record.binding.sourceRevision);
  assert.equal(assignment.sourceTreeSha256, threat.record.binding.sourceTreeSha256);
  assert.equal(assignment.predecessorCoverageDisposition, "UNEXPLORED");
  assert.equal(assignment.predecessorInspectionCount, 0);
  assert.equal(assignment.budget.networkRequests, 1);
  assert.equal(typeof assignment.budgetSha256, "string");
});

test("SEC2 changed source invalidates only intersecting area evidence lineage", () => {
  const firstModel = model();
  let firstLedger = createSecurityCoverageLedger(firstModel, { areas, createdAt: NOW });
  for (const [areaId, at] of [["api", "2026-10-02T16:01:00.000Z"], ["policy", "2026-10-02T16:02:00.000Z"]] as const) {
    firstLedger = recordSecurityCoverage(firstModel, firstLedger, {
      areaId,
      attackClass: "AUTHORIZATION_BYPASS",
      disposition: "THIN",
      evidenceRefs: [{ id: `trace-${areaId}`, sha256: areaId === "api" ? H3 : H4 }],
      inspectedAt: at,
    });
  }

  const secondModel = model("next-revision", H5);
  const rebased = rebaseSecurityCoverageLedger(
    firstModel, firstLedger, secondModel,
    { areas, changedPaths: ["src/api/router.ts"], rebasedAt: "2026-10-02T16:03:00.000Z" },
  );
  const api = rebased.record.cells.find((cell) =>
    cell.areaId === "api" && cell.attackClass === "AUTHORIZATION_BYPASS",
  );
  const policy = rebased.record.cells.find((cell) =>
    cell.areaId === "policy" && cell.attackClass === "AUTHORIZATION_BYPASS",
  );
  assert.equal(api?.disposition, "UNEXPLORED");
  assert.equal(policy?.disposition, "THIN");
  assert.equal(rebased.record.continuity.previousLedgerRecordSha256, firstLedger.recordSha256);
  assert.equal(typeof rebased.record.continuity.sourceChangeSha256, "string");
  assert.deepEqual(rebased.record.continuity.invalidatedCellIds, [api?.cellId]);
});

test("SEC2 changed source tree refuses an empty changed-path manifest", () => {
  const firstModel = model();
  let firstLedger = createSecurityCoverageLedger(firstModel, { areas, createdAt: NOW });
  firstLedger = recordSecurityCoverage(firstModel, firstLedger, {
    areaId: "policy",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "policy-trace", sha256: H4 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });

  const secondModel = model("next-revision", H5);
  assert.throws(
    () => rebaseSecurityCoverageLedger(
      firstModel,
      firstLedger,
      secondModel,
      {
        areas,
        changedPaths: [],
        rebasedAt: "2026-10-02T16:02:00.000Z",
      },
    ),
    /changed source tree requires a non-empty changed-path manifest/,
  );
});

test("SEC2 unchanged source tree refuses fabricated changed paths", () => {
  const firstModel = model();
  const firstLedger = createSecurityCoverageLedger(firstModel, {
    areas,
    createdAt: NOW,
  });
  const secondModel = model("same-tree-new-revision", H2);

  assert.throws(
    () => rebaseSecurityCoverageLedger(
      firstModel,
      firstLedger,
      secondModel,
      {
        areas,
        changedPaths: ["src/api/router.ts"],
        rebasedAt: "2026-10-02T16:01:00.000Z",
      },
    ),
    /unchanged source tree cannot carry changed paths/,
  );
});

test("SEC2 unchanged areas carry prior evidence across repeated audits", () => {
  const firstModel = model();
  let firstLedger = createSecurityCoverageLedger(firstModel, { areas, createdAt: NOW });
  firstLedger = recordSecurityCoverage(firstModel, firstLedger, {
    areaId: "policy",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "policy-trace", sha256: H4 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  const secondModel = model("next-revision", H5);
  const rebased = rebaseSecurityCoverageLedger(
    firstModel, firstLedger, secondModel,
    { areas, changedPaths: ["src/api/router.ts"], rebasedAt: "2026-10-02T16:02:00.000Z" },
  );
  const carried = rebased.record.cells.find((cell) =>
    cell.areaId === "policy" && cell.attackClass === "AUTHORIZATION_BYPASS",
  );
  assert.equal(carried?.disposition, "THIN");
  assert.deepEqual(carried?.evidenceRefs.map((ref) => ref.id), ["policy-trace"]);
});

test("SEC2 area-definition drift invalidates that area even without changed-path hint", () => {
  const firstModel = model();
  let firstLedger = createSecurityCoverageLedger(firstModel, { areas, createdAt: NOW });
  firstLedger = recordSecurityCoverage(firstModel, firstLedger, {
    areaId: "policy",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "policy-trace", sha256: H4 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  const secondModel = model("next-revision-same-tree", H2);
  const rebased = rebaseSecurityCoverageLedger(
    firstModel, firstLedger, secondModel,
    {
      areas: [areas[0], {
        areaId: "policy",
        label: "Policy core expanded",
        paths: ["src/policy", "src/security"],
      }],
      changedPaths: [],
      rebasedAt: "2026-10-02T16:02:00.000Z",
    },
  );
  const cell = rebased.record.cells.find((entry) =>
    entry.areaId === "policy" && entry.attackClass === "AUTHORIZATION_BYPASS",
  );
  assert.equal(cell?.disposition, "UNEXPLORED");
  assert.deepEqual(rebased.record.continuity.invalidatedCellIds, [cell?.cellId]);
});

test("SEC2 raw ledgers reject unsupported coverage dispositions at runtime", () => {
  const threat = model();
  const ledger = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  assert.throws(
    () => validateSecurityCoverageLedgerEnvelope({
      ...ledger,
      record: {
        ...ledger.record,
        cells: ledger.record.cells.map((cell, index) =>
          index === 0 ? { ...cell, disposition: "TOTALLY_UNKNOWN" as never } : cell,
        ),
      },
    }, threat),
    /cell\.disposition is unsupported/,
  );
});

test("SEC2 hunter budget is bounded data and cannot be entirely zero", () => {
  const threat = model();
  const ledger = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  assert.throws(
    () => planNextSecurityHunterAssignment(threat, ledger, {
      budget: { modelTokens: 0, toolCalls: 0, networkRequests: 0, wallClockMs: 0 },
    }),
    /cannot be entirely zero/,
  );
});

test("SEC2 coverage evidence ids cannot be rebound to different content", () => {
  const threat = model();
  const initial = createSecurityCoverageLedger(threat, { areas, createdAt: NOW });
  const thin = recordSecurityCoverage(threat, initial, {
    areaId: "api",
    attackClass: "AUTHORIZATION_BYPASS",
    disposition: "THIN",
    evidenceRefs: [{ id: "same-id", sha256: H3 }],
    inspectedAt: "2026-10-02T16:01:00.000Z",
  });
  assert.throws(
    () => recordSecurityCoverage(threat, thin, {
      areaId: "api",
      attackClass: "AUTHORIZATION_BYPASS",
      disposition: "COVERED",
      evidenceRefs: [{ id: "same-id", sha256: H4 }],
      inspectedAt: "2026-10-02T16:02:00.000Z",
    }),
    /cannot be rebound/,
  );
});

test("SEC2 ledger serialization preserves sealed durable coverage truth", () => {
  const threat = model();
  const ledger = createSecurityCoverageLedger(threat, {
    ledgerId: "coverage-roundtrip", areas, createdAt: NOW,
  });
  assert.deepEqual(
    parseSecurityCoverageLedger(serializeSecurityCoverageLedger(ledger, threat), threat),
    ledger,
  );
});
