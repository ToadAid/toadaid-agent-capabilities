import assert from "node:assert/strict";
import test from "node:test";

import {
  createSecurityFindingCandidate,
  createSecurityThreatModel,
  parseSecurityFinding,
  parseSecurityThreatModel,
  sealSecurityFindingRecord,
  serializeSecurityFinding,
  serializeSecurityThreatModel,
  validateSecurityFindingAgainstThreatModel,
  validateSecurityFindingEnvelope,
  validateSecurityThreatModelEnvelope,
} from "../src/securityAudit.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const NOW = "2026-10-02T14:00:00.000Z";

function threatModel() {
  return createSecurityThreatModel(
    {
      auditId: "sec-audit-1",
      runId: "run-sec-1",
      repositoryIdentitySha256: H1,
      sourceRevision: "844582f",
      sourceTreeSha256: H2,
      scope: {
        includePaths: ["src", "scripts"],
        excludePaths: ["src/generated"],
      },
      configurationSha256: H3,
      ruleSetSha256: H4,
      architecture: {
        components: [
          {
            componentId: "api",
            kind: "NETWORK_SERVICE",
            label: "API boundary",
            sourcePaths: ["src/api.ts"],
            riskSignals: [
              "UNTRUSTED_INPUT",
              "NETWORK_ACCESS",
            ],
          },
          {
            componentId: "policy",
            kind: "SECURITY_CONTROL",
            label: "Authority policy",
            sourcePaths: ["src/policy.ts"],
            riskSignals: ["AUTHORITY_BOUNDARY"],
          },
          {
            componentId: "state",
            kind: "DATA_STORE",
            label: "Durable state",
            sourcePaths: ["src/state.ts"],
            riskSignals: ["PERSISTENT_STATE"],
          },
        ],
        trustBoundaries: [
          {
            boundaryId: "api-policy",
            fromComponentId: "api",
            toComponentId: "policy",
            channel: "typed invocation",
            riskSignals: [
              "AUTHORITY_BOUNDARY",
              "SERIALIZATION_BOUNDARY",
            ],
          },
        ],
      },
      createdAt: NOW,
    },
    {
      now: () => new Date(NOW),
      randomId: () => "unused",
    },
  );
}

test("SEC1 seals exact repository/source/scope/config/rules/run truth", () => {
  const model = threatModel();

  assert.equal(model.record.auditId, "sec-audit-1");
  assert.equal(model.record.binding.repositoryIdentitySha256, H1);
  assert.equal(model.record.binding.sourceRevision, "844582f");
  assert.equal(model.record.binding.sourceTreeSha256, H2);
  assert.equal(model.record.binding.configurationSha256, H3);
  assert.equal(model.record.binding.ruleSetSha256, H4);
  assert.equal(model.record.binding.runId, "run-sec-1");
  assert.deepEqual(model.record.scope.includePaths, ["scripts", "src"]);
  assert.equal(
    model.record.architecture.schemaVersion,
    "toadaid.security-architecture-snapshot.v1",
  );
});

test("SEC1 derives only target-supported attack classes from reconnaissance signals", () => {
  const classes = threatModel().record.attackClasses.map(
    (entry) => entry.attackClass,
  );

  assert.deepEqual(classes, [
    "AUTHORIZATION_BYPASS",
    "DESERIALIZATION_OR_INTEGRITY",
    "INPUT_INJECTION",
    "SSRF_OR_NETWORK_PIVOT",
    "STATE_TAMPERING",
  ]);
  assert.equal(
    classes.includes("COMMAND_EXECUTION_INJECTION"),
    false,
  );
  assert.equal(classes.includes("PATH_TRAVERSAL"), false);
  assert.equal(classes.includes("SUPPLY_CHAIN"), false);
});

test("SEC1 attack-class derivation is deterministic across input ordering", () => {
  const first = threatModel();
  const second = createSecurityThreatModel({
    auditId: "sec-audit-2",
    runId: "run-sec-1",
    repositoryIdentitySha256: H1,
    sourceRevision: "844582f",
    sourceTreeSha256: H2,
    scope: {
      includePaths: ["scripts", "src"],
      excludePaths: ["src/generated"],
    },
    configurationSha256: H3,
    ruleSetSha256: H4,
    architecture: {
      components: [...first.record.architecture.components].reverse(),
      trustBoundaries: first.record.architecture.trustBoundaries,
    },
    createdAt: NOW,
  });

  assert.deepEqual(
    second.record.attackClasses,
    first.record.attackClasses,
  );
});

test("SEC1 raw architecture rejects unsupported component kinds at runtime", () => {
  assert.throws(
    () =>
      createSecurityThreatModel({
        auditId: "sec-audit-bad-kind",
        runId: "run-sec-1",
        repositoryIdentitySha256: H1,
        sourceRevision: "844582f",
        sourceTreeSha256: H2,
        scope: {
          includePaths: ["src"],
          excludePaths: [],
        },
        configurationSha256: H3,
        ruleSetSha256: H4,
        architecture: {
          components: [
            {
              componentId: "bad-kind",
              kind: "TOTALLY_UNKNOWN_KIND" as never,
              label: "Bad kind",
              sourcePaths: ["src/bad.ts"],
              riskSignals: ["UNTRUSTED_INPUT"],
            },
          ],
          trustBoundaries: [],
        },
      }),
    /component\.bad-kind\.kind is unsupported/,
  );
});

test("SEC1 trust boundaries must reference known distinct components", () => {
  assert.throws(
    () =>
      createSecurityThreatModel({
        auditId: "sec-audit-bad-boundary",
        runId: "run-sec-1",
        repositoryIdentitySha256: H1,
        sourceRevision: "844582f",
        sourceTreeSha256: H2,
        scope: {
          includePaths: ["src"],
          excludePaths: [],
        },
        configurationSha256: H3,
        ruleSetSha256: H4,
        architecture: {
          components: [
            {
              componentId: "known",
              kind: "MODULE",
              label: "Known module",
              sourcePaths: ["src/known.ts"],
              riskSignals: ["UNTRUSTED_INPUT"],
            },
          ],
          trustBoundaries: [
            {
              boundaryId: "bad",
              fromComponentId: "known",
              toComponentId: "missing",
              channel: "call",
              riskSignals: ["AUTHORITY_BOUNDARY"],
            },
          ],
        },
      }),
    /unknown component/,
  );
});

test("SEC1 threat model refuses generic attack-class invention", () => {
  const model = threatModel();
  assert.throws(
    () =>
      validateSecurityThreatModelEnvelope({
        ...model,
        record: {
          ...model.record,
          attackClasses: [
            ...model.record.attackClasses,
            {
              attackClass: "COMMAND_EXECUTION_INJECTION",
              derivedFromSignals: ["PROCESS_EXECUTION"],
              componentIds: [],
              boundaryIds: [],
            },
          ],
        },
      }),
    /do not match target-derived architecture signals/,
  );
});

test("SEC1 candidate findings bind exact model, derived attack class, evidence, and source", () => {
  const model = threatModel();
  const candidate = createSecurityFindingCandidate(
    model,
    {
      findingId: "finding-1",
      attackClass: "AUTHORIZATION_BYPASS",
      title: "Authority edge may accept stale identity",
      rationale: "Boundary requires validation against current identity.",
      evidenceRefs: [
        { id: "trace-1", sha256: H3 },
      ],
      sourceLocations: [
        {
          path: "src/policy.ts",
          startLine: 10,
          endLine: 18,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.equal(candidate.record.state, "CANDIDATE");
  assert.equal(candidate.record.revision, 0);
  assert.equal(
    candidate.record.threatModelRecordSha256,
    model.recordSha256,
  );
  assert.equal(
    candidate.record.continuity.previousRecordSha256,
    null,
  );
  assert.equal(
    validateSecurityFindingAgainstThreatModel(
      candidate,
      model,
    ).recordSha256,
    candidate.recordSha256,
  );
});

test("SEC1 refuses candidate attack classes not justified by the threat model", () => {
  const model = threatModel();
  assert.throws(
    () =>
      createSecurityFindingCandidate(model, {
        attackClass: "COMMAND_EXECUTION_INJECTION",
        title: "Unsupported suspicion",
        rationale: "There is no process execution signal.",
        evidenceRefs: [{ id: "evidence", sha256: H3 }],
        sourceLocations: [
          {
            path: "src/api.ts",
            startLine: 1,
            endLine: 1,
          },
        ],
      }),
    /not derived by this threat model/,
  );
});

test("SEC1 raw sealed findings reject unsupported attack classes at runtime", () => {
  const candidate = createSecurityFindingCandidate(
    threatModel(),
    {
      attackClass: "INPUT_INJECTION",
      title: "Attack class probe",
      rationale: "Runtime enum validation must be fail-closed.",
      evidenceRefs: [{ id: "trace", sha256: H3 }],
      sourceLocations: [
        {
          path: "src/api.ts",
          startLine: 1,
          endLine: 1,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.throws(
    () =>
      sealSecurityFindingRecord({
        ...candidate.record,
        attackClass:
          "TOTALLY_UNKNOWN_ATTACK_CLASS" as never,
      }),
    /attackClass is unsupported/,
  );
});

test("SEC1 initial findings cannot silently start CONFIRMED", () => {
  const candidate = createSecurityFindingCandidate(
    threatModel(),
    {
      attackClass: "INPUT_INJECTION",
      title: "Input candidate",
      rationale: "Needs adversarial validation.",
      evidenceRefs: [{ id: "input-trace", sha256: H3 }],
      sourceLocations: [
        {
          path: "src/api.ts",
          startLine: 3,
          endLine: 7,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.throws(
    () =>
      sealSecurityFindingRecord({
        ...candidate.record,
        state: "CONFIRMED",
        stateEvidence: {
          state: "CONFIRMED",
          validatorIdentitySha256: H4,
          proofEvidenceRefs: [
            { id: "proof", sha256: H2 },
          ],
        },
      }),
    /initial security finding must be a predecessor-free CANDIDATE/,
  );
});

test("SEC1 confirmed state data requires explicit validator and proof evidence", () => {
  const candidate = createSecurityFindingCandidate(
    threatModel(),
    {
      attackClass: "INPUT_INJECTION",
      title: "Input candidate",
      rationale: "Needs validation.",
      evidenceRefs: [{ id: "trace", sha256: H3 }],
      sourceLocations: [
        {
          path: "src/api.ts",
          startLine: 1,
          endLine: 2,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.throws(
    () =>
      sealSecurityFindingRecord({
        ...candidate.record,
        revision: 1,
        state: "CONFIRMED",
        stateEvidence: {
          state: "CONFIRMED",
          validatorIdentitySha256: H4,
          proofEvidenceRefs: [],
        },
        updatedAt: "2026-10-02T14:01:00.000Z",
        continuity: {
          previousRecordSha256: candidate.recordSha256,
        },
      }),
    /proofEvidenceRefs count is invalid/,
  );
});

test("SEC1 finding source locations are repository-relative and traversal-free", () => {
  assert.throws(
    () =>
      createSecurityFindingCandidate(
        threatModel(),
        {
          attackClass: "INPUT_INJECTION",
          title: "Unsafe location",
          rationale: "Traversal must fail.",
          evidenceRefs: [{ id: "trace", sha256: H3 }],
          sourceLocations: [
            {
              path: "../outside.ts",
              startLine: 1,
              endLine: 1,
            },
          ],
        },
      ),
    /unsafe path segments/,
  );
});

test("SEC1 threat models and findings serialize as sealed plain data", () => {
  const model = threatModel();
  const candidate = createSecurityFindingCandidate(
    model,
    {
      findingId: "finding-roundtrip",
      attackClass: "STATE_TAMPERING",
      title: "State candidate",
      rationale: "Durable state boundary deserves validation.",
      evidenceRefs: [{ id: "state-ref", sha256: H2 }],
      sourceLocations: [
        {
          path: "src/state.ts",
          startLine: 20,
          endLine: 25,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.deepEqual(
    parseSecurityThreatModel(
      serializeSecurityThreatModel(model),
    ),
    model,
  );
  assert.deepEqual(
    parseSecurityFinding(
      serializeSecurityFinding(candidate),
    ),
    candidate,
  );
});

test("SEC1 sealed finding evidence is tamper-evident", () => {
  const candidate = createSecurityFindingCandidate(
    threatModel(),
    {
      attackClass: "INPUT_INJECTION",
      title: "Tamper candidate",
      rationale: "Evidence must remain immutable.",
      evidenceRefs: [{ id: "trace", sha256: H3 }],
      sourceLocations: [
        {
          path: "src/api.ts",
          startLine: 1,
          endLine: 1,
        },
      ],
      createdAt: NOW,
    },
  );

  assert.throws(
    () =>
      validateSecurityFindingEnvelope({
        ...candidate,
        record: {
          ...candidate.record,
          title: "rewritten",
        },
      }),
    /integrity mismatch/,
  );
});
