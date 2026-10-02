import {
  createChildTask,
  sealChildTask,
} from "./childTaskLifecycle.js";
import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import {
  allocateChildRunBudget,
  validateRunBudgetLedgerEnvelope,
} from "./runBudgetLedger.js";
import type {
  RunBudgetVector,
} from "./runBudgetTypes.js";
import {
  createRunStateCapsule,
} from "./runStateCapsule.js";
import type {
  RunAuthoritySnapshot,
} from "./runStateCapsule.js";
import {
  createSecurityFindingCandidate,
  validateSecurityFindingAgainstThreatModel,
  validateSecurityThreatModelEnvelope,
} from "./securityAudit.js";
import type {
  SecurityEvidenceRef,
  SecuritySourceLocation,
} from "./securityAuditTypes.js";
import {
  summarizeSecurityCoverage,
  validateSecurityCoverageLedgerEnvelope,
} from "./securityCoverage.js";
import type {
  SecurityHunterAssignment,
  SecurityHunterBudget,
} from "./securityCoverageTypes.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  CreateSecurityHunterCandidatePacketInput,
  SecurityHunterCandidatePacketEnvelope,
  SecurityHunterCandidatePacketRecord,
  SecurityHunterObservation,
  SecurityHunterObservationInput,
  SecurityHunterObservationPosition,
  SecurityHunterProofStep,
  SecurityHunterProofStepInput,
  SecurityHunterSpawnInput,
  SecurityHunterSpawnReceipt,
} from "./securityHunterTypes.js";

export type * from "./securityHunterTypes.js";

const SECURITY_HUNTER_DELEGATED_CAPABILITIES = Object.freeze([
  "host:file-read",
  "host:session",
] as const);

const MAX_MODEL_REQUESTS = 64;
const MAX_PROOF_STEPS = 64;
const MAX_OBSERVATIONS = 256;
const MAX_TEXT = 4_000;
const MAX_PATH = 2_048;

function exactText(
  value: string,
  label: string,
  maximum = MAX_TEXT,
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function safeRelativePath(
  value: string,
  label: string,
): string {
  const path = exactText(
    value,
    label,
    MAX_PATH,
  ).replace(/\\/g, "/");
  if (
    path.startsWith("/") ||
    /^[A-Za-z]:\//.test(path)
  ) {
    throw new TypeError(
      `${label} must be repository-relative`,
    );
  }
  const parts = path.split("/");
  if (
    parts.length === 0 ||
    parts.some(
      (part) =>
        part.length === 0 ||
        part === "." ||
        part === "..",
    )
  ) {
    throw new TypeError(
      `${label} contains unsafe path segments`,
    );
  }
  return path;
}

function pathWithin(
  path: string,
  root: string,
): boolean {
  return path === root || path.startsWith(`${root}/`);
}

function normalizeSecurityHunterBudget(
  budget: SecurityHunterBudget,
): SecurityHunterBudget {
  const values = {
    modelTokens: budget.modelTokens,
    toolCalls: budget.toolCalls,
    networkRequests: budget.networkRequests,
    wallClockMs: budget.wallClockMs,
  };
  for (const [label, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError(
        `assignment.budget.${label} must be a non-negative safe integer`,
      );
    }
  }
  if (
    values.modelTokens === 0 &&
    values.toolCalls === 0 &&
    values.networkRequests === 0 &&
    values.wallClockMs === 0
  ) {
    throw new Error(
      "security hunter assignment budget cannot be entirely zero",
    );
  }
  return Object.freeze({ ...values });
}

function normalizeQ1Limits(
  assignmentBudget: SecurityHunterBudget,
  limits: RunBudgetVector,
): RunBudgetVector {
  const fields: readonly (keyof RunBudgetVector)[] = [
    "modelRequests",
    "inputTokens",
    "outputTokens",
    "toolCalls",
    "networkRequests",
    "retries",
    "wallClockMs",
    "childTasks",
  ];
  const normalized: RunBudgetVector = { ...limits };
  for (const field of fields) {
    const value = normalized[field];
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError(
        `q1Limits.${field} must be a non-negative safe integer`,
      );
    }
  }

  const modelTokenTotal =
    normalized.inputTokens + normalized.outputTokens;
  if (!Number.isSafeInteger(modelTokenTotal)) {
    throw new RangeError(
      "Q1 input/output token total exceeds safe integer range",
    );
  }
  if (modelTokenTotal > assignmentBudget.modelTokens) {
    throw new RangeError(
      "Q1 token limits exceed security Hunter assignment budget",
    );
  }
  if (normalized.toolCalls > assignmentBudget.toolCalls) {
    throw new RangeError(
      "Q1 tool-call limit exceeds security Hunter assignment budget",
    );
  }
  if (normalized.networkRequests !== 0) {
    throw new Error(
      "SEC3 isolated Hunter network budget must be zero",
    );
  }
  if (
    normalized.networkRequests >
    assignmentBudget.networkRequests
  ) {
    throw new RangeError(
      "Q1 network limit exceeds security Hunter assignment budget",
    );
  }
  if (
    normalized.wallClockMs >
    assignmentBudget.wallClockMs
  ) {
    throw new RangeError(
      "Q1 wall-clock limit exceeds security Hunter assignment budget",
    );
  }

  if (
    normalized.modelRequests < 1 ||
    normalized.modelRequests > MAX_MODEL_REQUESTS
  ) {
    throw new RangeError(
      `SEC3 modelRequests must be between 1 and ${MAX_MODEL_REQUESTS}`,
    );
  }
  if (modelTokenTotal < 1) {
    throw new RangeError(
      "SEC3 Hunter requires a positive Q1 model-token budget",
    );
  }
  if (normalized.retries !== 0) {
    throw new Error(
      "SEC3 isolated Hunter retries must be zero",
    );
  }
  if (normalized.childTasks !== 0) {
    throw new Error(
      "SEC3 isolated Hunter cannot allocate nested child tasks",
    );
  }

  return Object.freeze(
    normalized as unknown as RunBudgetVector,
  );
}

function normalizeChildAuthoritySnapshot(
  snapshot: RunAuthoritySnapshot,
  spawnedAt: string,
): RunAuthoritySnapshot {
  if (snapshot.capturedAt !== spawnedAt) {
    throw new Error(
      "security Hunter authority snapshot must be captured at spawn time",
    );
  }
  if (!Array.isArray(snapshot.decisions)) {
    throw new TypeError(
      "security Hunter authority snapshot decisions must be an array",
    );
  }

  const allowed = snapshot.decisions
    .filter(
      (decision: CapabilityAuthorityDecision) =>
        decision.decision === "ALLOW",
    )
    .map((decision) => decision.capabilityId)
    .sort();

  const expected = [
    ...SECURITY_HUNTER_DELEGATED_CAPABILITIES,
  ].sort();

  if (
    allowed.length !== expected.length ||
    allowed.some((value, index) => value !== expected[index])
  ) {
    throw new Error(
      "SEC3 Hunter child authority may ALLOW only host:file-read and host:session",
    );
  }

  return snapshot;
}

export function securityHunterAssignmentSha256(
  assignment: SecurityHunterAssignment,
): string {
  return sha256(assignment);
}

export function validateSecurityHunterAssignmentBinding(
  assignment: SecurityHunterAssignment,
  threatModelInput: SecurityHunterSpawnInput["threatModel"],
  coverageLedgerInput: SecurityHunterSpawnInput["coverageLedger"],
): SecurityHunterAssignment {
  const threatModel =
    validateSecurityThreatModelEnvelope(threatModelInput);
  const coverageLedger =
    validateSecurityCoverageLedgerEnvelope(
      coverageLedgerInput,
      threatModel,
    );

  if (
    assignment.schemaVersion !==
    "toadaid.security-hunter-assignment.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter assignment schemaVersion",
    );
  }
  boundedId(assignment.assignmentId, "assignmentId");

  if (
    sha(
      assignment.threatModelRecordSha256,
      "assignment.threatModelRecordSha256",
    ) !== threatModel.recordSha256
  ) {
    throw new Error(
      "security Hunter assignment threat-model binding is stale",
    );
  }
  if (
    sha(
      assignment.coverageLedgerRecordSha256,
      "assignment.coverageLedgerRecordSha256",
    ) !== coverageLedger.recordSha256
  ) {
    throw new Error(
      "security Hunter assignment coverage-ledger binding is stale",
    );
  }
  if (
    assignment.repositoryIdentitySha256 !==
      threatModel.record.binding.repositoryIdentitySha256 ||
    assignment.sourceRevision !==
      threatModel.record.binding.sourceRevision ||
    assignment.sourceTreeSha256 !==
      threatModel.record.binding.sourceTreeSha256
  ) {
    throw new Error(
      "security Hunter assignment source binding is stale",
    );
  }

  const area = coverageLedger.record.areas.find(
    (entry) => entry.areaId === assignment.areaId,
  );
  if (!area) {
    throw new Error(
      "security Hunter assignment references unknown area",
    );
  }
  if (
    assignment.areaSha256 !== area.areaSha256 ||
    sha256(assignment.scopePaths) !==
      assignment.scopeSha256 ||
    JSON.stringify(assignment.scopePaths) !==
      JSON.stringify(area.paths)
  ) {
    throw new Error(
      "security Hunter assignment area/scope binding mismatch",
    );
  }

  const summary = summarizeSecurityCoverage(
    threatModel,
    coverageLedger,
  );
  const expectedGap = summary.gaps[0];
  if (!expectedGap) {
    throw new Error(
      "security Hunter assignment exists after coverage is complete",
    );
  }
  if (
    expectedGap.areaId !== assignment.areaId ||
    expectedGap.attackClass !== assignment.attackClass ||
    expectedGap.disposition !==
      assignment.predecessorCoverageDisposition ||
    expectedGap.inspectionCount !==
      assignment.predecessorInspectionCount
  ) {
    throw new Error(
      "security Hunter assignment is not the current deterministic coverage gap",
    );
  }

  const budget = normalizeSecurityHunterBudget(
    assignment.budget,
  );
  if (
    assignment.budgetSha256 !== sha256(budget)
  ) {
    throw new Error(
      "security Hunter assignment budget fingerprint mismatch",
    );
  }

  const plannedAt = canonicalIso(
    assignment.plannedAt,
    "assignment.plannedAt",
  );
  if (
    Date.parse(plannedAt) <
    Date.parse(coverageLedger.record.updatedAt)
  ) {
    throw new RangeError(
      "security Hunter assignment predates current coverage ledger",
    );
  }

  return Object.freeze({
    ...assignment,
    scopePaths: Object.freeze([...assignment.scopePaths]),
    budget,
  });
}

export function spawnSecurityHunterChild(
  input: SecurityHunterSpawnInput,
): SecurityHunterSpawnReceipt {
  const assignment =
    validateSecurityHunterAssignmentBinding(
      input.assignment,
      input.threatModel,
      input.coverageLedger,
    );
  const parentBudget =
    validateRunBudgetLedgerEnvelope(input.parentBudget);
  const spawnedAt = canonicalIso(
    input.createdAt,
    "createdAt",
  );
  if (
    Date.parse(spawnedAt) <
    Date.parse(assignment.plannedAt)
  ) {
    throw new RangeError(
      "security Hunter spawn cannot predate assignment planning",
    );
  }

  const childAuthoritySnapshot =
    normalizeChildAuthoritySnapshot(
      input.childAuthoritySnapshot,
      spawnedAt,
    );
  const q1Limits = normalizeQ1Limits(
    assignment.budget,
    input.q1Limits,
  );

  const assignmentSha256 =
    securityHunterAssignmentSha256(assignment);
  const childTaskId = boundedId(
    input.childTaskId ??
      `security-hunter-${assignmentSha256.slice(0, 24)}`,
    "childTaskId",
  );

  const budgetAllocation = allocateChildRunBudget(
    parentBudget,
    {
      ...(input.allocationId === undefined
        ? {}
        : { allocationId: input.allocationId }),
      ...(input.childBudgetId === undefined
        ? {}
        : { childBudgetId: input.childBudgetId }),
      childRunId: childTaskId,
      childTaskId,
      allocatedAt: spawnedAt,
      limits: q1Limits,
    },
  );

  const runState = createRunStateCapsule({
    runId: childTaskId,
    createdAt: spawnedAt,
    objective: {
      summary:
        `Hunt ${assignment.attackClass} in security area ${assignment.areaId}. Emit candidates and proof plans only.`,
      status: "ACTIVE",
    },
    phase: "security-hunt",
    authoritySnapshot: childAuthoritySnapshot,
    evidenceRefs: [
      {
        id: "sec3-assignment",
        locator:
          `security-hunter-assignment:${assignment.assignmentId}`,
        sha256: assignmentSha256,
      },
      {
        id: "sec3-coverage-ledger",
        locator:
          `security-coverage-ledger:${assignment.coverageLedgerRecordSha256}`,
        sha256: assignment.coverageLedgerRecordSha256,
      },
      {
        id: "sec3-threat-model",
        locator:
          `security-threat-model:${assignment.threatModelRecordSha256}`,
        sha256: assignment.threatModelRecordSha256,
      },
    ],
    work: {
      pending: [
        {
          id: "hunt",
          summary:
            `Inspect only ${assignment.areaId} for ${assignment.attackClass}; preserve supporting, challenging, and uncertain evidence.`,
        },
      ],
    },
  });

  const childTaskRecord = createChildTask({
    childTaskId,
    parentRunId: parentBudget.record.runId,
    parentChildTaskId:
      parentBudget.record.childTaskId ?? null,
    createdAt: spawnedAt,
    delegatedCapabilities:
      SECURITY_HUNTER_DELEGATED_CAPABILITIES,
    parentAuthority: input.parentAuthority,
    runState,
  });
  const childTask = sealChildTask(childTaskRecord);

  const hunterIdentitySha256 = sha256({
    assignmentSha256,
    childTaskSha256: childTask.taskSha256,
    budgetAllocationSha256:
      budgetAllocation.allocation.allocationSha256,
    childBudgetLedgerSha256:
      budgetAllocation.child.recordSha256,
  });

  return Object.freeze({
    schemaVersion: "toadaid.security-hunter-spawn.v1",
    assignment,
    assignmentSha256,
    hunterIdentitySha256,
    attackClass: assignment.attackClass,
    sourceTreeSha256: assignment.sourceTreeSha256,
    sourceScopePaths: Object.freeze(
      [...assignment.scopePaths],
    ),
    delegatedCapabilities:
      SECURITY_HUNTER_DELEGATED_CAPABILITIES,
    childTask,
    parentBudget: budgetAllocation.parent,
    childBudget: budgetAllocation.child,
    budgetAllocationSha256:
      budgetAllocation.allocation.allocationSha256,
    spawnedAt,
  });
}

export function assertSecurityHunterSourcePathAllowed(
  spawn: SecurityHunterSpawnReceipt,
  value: string,
): string {
  if (
    spawn.schemaVersion !==
    "toadaid.security-hunter-spawn.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter spawn schemaVersion",
    );
  }
  const path = safeRelativePath(
    value,
    "security Hunter source path",
  );
  if (
    !spawn.sourceScopePaths.some(
      (root) => pathWithin(path, root),
    )
  ) {
    throw new Error(
      `security Hunter source path is outside assignment scope: ${path}`,
    );
  }
  return path;
}

function normalizeEvidenceRefs(
  refs: readonly SecurityEvidenceRef[] | undefined,
  label: string,
): readonly SecurityEvidenceRef[] {
  const resolved = refs ?? [];
  if (resolved.length > 2_000) {
    throw new RangeError(
      `${label} exceeds evidence-reference bound`,
    );
  }
  const ids = new Set<string>();
  return Object.freeze(
    resolved
      .map((ref, index) => {
        const id = boundedId(
          ref.id,
          `${label}[${index}].id`,
        );
        if (ids.has(id)) {
          throw new Error(
            `${label} contains duplicate evidence id`,
          );
        }
        ids.add(id);
        return Object.freeze({
          id,
          sha256: sha(
            ref.sha256,
            `${label}[${index}].sha256`,
          )!,
        });
      })
      .sort((a, b) => a.id.localeCompare(b.id)),
  );
}

function normalizeSourceLocations(
  spawn: SecurityHunterSpawnReceipt,
  locations: readonly SecuritySourceLocation[],
  label: string,
): readonly SecuritySourceLocation[] {
  if (
    !Array.isArray(locations) ||
    locations.length < 1 ||
    locations.length > 2_000
  ) {
    throw new RangeError(
      `${label} source-location count is invalid`,
    );
  }
  return Object.freeze(
    locations
      .map((location, index) => {
        if (
          !Number.isSafeInteger(location.startLine) ||
          location.startLine < 1 ||
          !Number.isSafeInteger(location.endLine) ||
          location.endLine < location.startLine
        ) {
          throw new RangeError(
            `${label}[${index}] line range is invalid`,
          );
        }
        return Object.freeze({
          path: assertSecurityHunterSourcePathAllowed(
            spawn,
            location.path,
          ),
          startLine: location.startLine,
          endLine: location.endLine,
        });
      })
      .sort(
        (a, b) =>
          a.path.localeCompare(b.path) ||
          a.startLine - b.startLine ||
          a.endLine - b.endLine,
      ),
  );
}

function normalizeProofPlan(
  steps: readonly SecurityHunterProofStepInput[],
): readonly SecurityHunterProofStep[] {
  if (
    !Array.isArray(steps) ||
    steps.length < 1 ||
    steps.length > MAX_PROOF_STEPS
  ) {
    throw new RangeError(
      "security Hunter proof plan step count is invalid",
    );
  }
  const ids = new Set<string>();
  return Object.freeze(
    steps
      .map((step, index) => {
        const stepId = boundedId(
          step.stepId,
          `proofPlan[${index}].stepId`,
        );
        if (ids.has(stepId)) {
          throw new Error(
            "security Hunter proof plan has duplicate stepId",
          );
        }
        ids.add(stepId);
        return Object.freeze({
          stepId,
          description: exactText(
            step.description,
            `proofPlan[${index}].description`,
          ),
          expectedEvidenceRefs:
            normalizeEvidenceRefs(
              step.expectedEvidenceRefs,
              `proofPlan[${index}].expectedEvidenceRefs`,
            ),
        });
      })
      .sort((a, b) => a.stepId.localeCompare(b.stepId)),
  );
}

function normalizeObservationPosition(
  value: SecurityHunterObservationPosition,
): SecurityHunterObservationPosition {
  const allowed:
    readonly SecurityHunterObservationPosition[] = [
      "SUPPORTS_CANDIDATE",
      "CHALLENGES_CANDIDATE",
      "UNCERTAIN",
    ];
  if (!allowed.includes(value)) {
    throw new TypeError(
      "unsupported security Hunter observation position",
    );
  }
  return value;
}

function normalizeObservations(
  spawn: SecurityHunterSpawnReceipt,
  observations:
    readonly SecurityHunterObservationInput[] | undefined,
): readonly SecurityHunterObservation[] {
  const resolved = observations ?? [];
  if (resolved.length > MAX_OBSERVATIONS) {
    throw new RangeError(
      "security Hunter observation count exceeds bound",
    );
  }
  const ids = new Set<string>();
  return Object.freeze(
    resolved
      .map((observation, index) => {
        const observationId = boundedId(
          observation.observationId,
          `observations[${index}].observationId`,
        );
        if (ids.has(observationId)) {
          throw new Error(
            "security Hunter observations contain duplicate ids",
          );
        }
        ids.add(observationId);
        return Object.freeze({
          observationId,
          position: normalizeObservationPosition(
            observation.position,
          ),
          summary: exactText(
            observation.summary,
            `observations[${index}].summary`,
          ),
          evidenceRefs: normalizeEvidenceRefs(
            observation.evidenceRefs,
            `observations[${index}].evidenceRefs`,
          ),
          sourceLocations: normalizeSourceLocations(
            spawn,
            observation.sourceLocations,
            `observations[${index}].sourceLocations`,
          ),
        });
      })
      .sort((a, b) =>
        a.observationId.localeCompare(b.observationId),
      ),
  );
}

export function validateSecurityHunterSpawnReceipt(
  threatModelInput: SecurityHunterSpawnInput["threatModel"],
  coverageLedgerInput: SecurityHunterSpawnInput["coverageLedger"],
  spawn: SecurityHunterSpawnReceipt,
): SecurityHunterSpawnReceipt {
  if (
    spawn.schemaVersion !==
    "toadaid.security-hunter-spawn.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter spawn schemaVersion",
    );
  }

  const threatModel =
    validateSecurityThreatModelEnvelope(threatModelInput);
  const assignment =
    validateSecurityHunterAssignmentBinding(
      spawn.assignment,
      threatModel,
      coverageLedgerInput,
    );
  const assignmentSha256 =
    securityHunterAssignmentSha256(assignment);

  if (
    sha(
      spawn.assignmentSha256,
      "spawn.assignmentSha256",
    ) !== assignmentSha256
  ) {
    throw new Error(
      "security Hunter spawn assignment digest mismatch",
    );
  }
  if (
    spawn.attackClass !== assignment.attackClass
  ) {
    throw new Error(
      "security Hunter spawn attack class differs from assignment",
    );
  }
  if (
    sha(
      spawn.sourceTreeSha256,
      "spawn.sourceTreeSha256",
    ) !== assignment.sourceTreeSha256
  ) {
    throw new Error(
      "security Hunter spawn source tree differs from assignment",
    );
  }
  if (
    JSON.stringify(spawn.sourceScopePaths) !==
    JSON.stringify(assignment.scopePaths)
  ) {
    throw new Error(
      "security Hunter spawn source scope differs from assignment",
    );
  }

  const expectedCapabilities =
    SECURITY_HUNTER_DELEGATED_CAPABILITIES;
  if (
    JSON.stringify(spawn.delegatedCapabilities) !==
    JSON.stringify(expectedCapabilities)
  ) {
    throw new Error(
      "security Hunter spawn delegated capability set is invalid",
    );
  }

  if (
    spawn.childTask.schemaVersion !==
    "toadaid.child-task-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter child-task envelope schemaVersion",
    );
  }
  const childTask = sealChildTask(
    spawn.childTask.task,
  );
  if (
    sha(
      spawn.childTask.taskSha256,
      "spawn.childTask.taskSha256",
    ) !== childTask.taskSha256
  ) {
    throw new Error(
      "security Hunter child-task integrity mismatch",
    );
  }
  if (
    JSON.stringify(
      childTask.task.delegatedCapabilities,
    ) !== JSON.stringify(expectedCapabilities)
  ) {
    throw new Error(
      "security Hunter child-task delegation differs from SEC3 allowlist",
    );
  }
  if (
    childTask.task.runState.phase !== "security-hunt"
  ) {
    throw new Error(
      "security Hunter child-task phase is invalid",
    );
  }

  const evidenceById = new Map(
    childTask.task.runState.evidenceRefs.map(
      (entry) => [entry.id, entry.sha256] as const,
    ),
  );
  const requiredEvidence = [
    ["sec3-assignment", assignmentSha256],
    [
      "sec3-coverage-ledger",
      assignment.coverageLedgerRecordSha256,
    ],
    [
      "sec3-threat-model",
      assignment.threatModelRecordSha256,
    ],
  ] as const;
  for (const [id, expectedSha] of requiredEvidence) {
    if (evidenceById.get(id) !== expectedSha) {
      throw new Error(
        `security Hunter child-task evidence binding mismatch: ${id}`,
      );
    }
  }

  const parentBudget =
    validateRunBudgetLedgerEnvelope(
      spawn.parentBudget,
    );
  const childBudget =
    validateRunBudgetLedgerEnvelope(
      spawn.childBudget,
    );
  const budgetAllocationSha256 = sha(
    spawn.budgetAllocationSha256,
    "spawn.budgetAllocationSha256",
  )!;

  if (
    childTask.task.parentRunId !==
    parentBudget.record.runId
  ) {
    throw new Error(
      "security Hunter child-task parent run differs from Q1 parent budget",
    );
  }
  if (
    (childTask.task.parentChildTaskId ?? null) !==
    (parentBudget.record.childTaskId ?? null)
  ) {
    throw new Error(
      "security Hunter child-task parent task differs from Q1 parent budget",
    );
  }
  if (
    childBudget.record.runId !==
      childTask.task.childTaskId ||
    childBudget.record.childTaskId !==
      childTask.task.childTaskId
  ) {
    throw new Error(
      "security Hunter child budget is not bound to the P5 child task",
    );
  }

  const parentBinding =
    childBudget.record.parentBinding;
  if (
    parentBinding === null ||
    parentBinding.parentBudgetId !==
      parentBudget.record.budgetId ||
    parentBinding.allocationSha256 !==
      budgetAllocationSha256
  ) {
    throw new Error(
      "security Hunter child budget parent binding mismatch",
    );
  }

  const allocation =
    parentBudget.record.childAllocations.find(
      (entry) =>
        entry.allocationSha256 ===
        budgetAllocationSha256,
    );
  if (!allocation) {
    throw new Error(
      "security Hunter budget allocation is absent from parent ledger",
    );
  }
  if (
    allocation.allocationId !==
      parentBinding.allocationId ||
    allocation.childBudgetId !==
      childBudget.record.budgetId ||
    allocation.childRunId !==
      childTask.task.childTaskId ||
    allocation.childTaskId !==
      childTask.task.childTaskId ||
    JSON.stringify(allocation.limits) !==
      JSON.stringify(childBudget.record.limits)
  ) {
    throw new Error(
      "security Hunter Q1 allocation lineage mismatch",
    );
  }

  const spawnedAt = canonicalIso(
    spawn.spawnedAt,
    "spawn.spawnedAt",
  );
  if (
    childTask.task.createdAt !== spawnedAt ||
    childBudget.record.createdAt !== spawnedAt ||
    allocation.allocatedAt !== spawnedAt
  ) {
    throw new Error(
      "security Hunter spawn time differs across P5/Q1 lineage",
    );
  }

  const expectedHunterIdentitySha256 = sha256({
    assignmentSha256,
    childTaskSha256: childTask.taskSha256,
    budgetAllocationSha256,
    childBudgetLedgerSha256:
      childBudget.recordSha256,
  });
  if (
    sha(
      spawn.hunterIdentitySha256,
      "spawn.hunterIdentitySha256",
    ) !== expectedHunterIdentitySha256
  ) {
    throw new Error(
      "security Hunter identity digest mismatch",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-hunter-spawn.v1",
    assignment,
    assignmentSha256,
    hunterIdentitySha256:
      expectedHunterIdentitySha256,
    attackClass: assignment.attackClass,
    sourceTreeSha256:
      assignment.sourceTreeSha256,
    sourceScopePaths: Object.freeze(
      [...assignment.scopePaths],
    ),
    delegatedCapabilities:
      SECURITY_HUNTER_DELEGATED_CAPABILITIES,
    childTask,
    parentBudget,
    childBudget,
    budgetAllocationSha256,
    spawnedAt,
  });
}

export function securityHunterCandidatePacketRecordSha256(
  record: SecurityHunterCandidatePacketRecord,
): string {
  return sha256(record);
}

export function createSecurityHunterCandidatePacket(
  threatModelInput: SecurityHunterSpawnInput["threatModel"],
  coverageLedgerInput: SecurityHunterSpawnInput["coverageLedger"],
  spawnInput: SecurityHunterSpawnReceipt,
  input: CreateSecurityHunterCandidatePacketInput,
): SecurityHunterCandidatePacketEnvelope {
  const threatModel =
    validateSecurityThreatModelEnvelope(threatModelInput);
  const spawn = validateSecurityHunterSpawnReceipt(
    threatModel,
    coverageLedgerInput,
    spawnInput,
  );

  const sourceLocations = normalizeSourceLocations(
    spawn,
    input.sourceLocations,
    "candidate.sourceLocations",
  );
  const candidate = createSecurityFindingCandidate(
    threatModel,
    {
      ...(input.findingId === undefined
        ? {}
        : { findingId: input.findingId }),
      attackClass: spawn.attackClass,
      title: input.title,
      rationale: input.rationale,
      evidenceRefs: input.evidenceRefs,
      sourceLocations,
      createdAt: input.createdAt ?? input.emittedAt,
    },
  );
  if (candidate.record.state !== "CANDIDATE") {
    throw new Error(
      "SEC3 Hunter may emit only CANDIDATE findings",
    );
  }

  const proofPlan = normalizeProofPlan(
    input.proofPlan,
  );
  const observations = normalizeObservations(
    spawn,
    input.observations,
  );
  const emittedAt = canonicalIso(
    input.emittedAt,
    "emittedAt",
  );
  if (
    Date.parse(emittedAt) <
    Date.parse(spawn.spawnedAt)
  ) {
    throw new RangeError(
      "security Hunter output cannot predate spawn",
    );
  }

  const record: SecurityHunterCandidatePacketRecord =
    Object.freeze({
      schemaVersion:
        "toadaid.security-hunter-candidate-packet.v1",
      hunterIdentitySha256:
        spawn.hunterIdentitySha256,
      assignmentSha256: spawn.assignmentSha256,
      childTaskSha256: spawn.childTask.taskSha256,
      childBudgetLedgerSha256:
        spawn.childBudget.recordSha256,
      sourceTreeSha256: spawn.sourceTreeSha256,
      attackClass: spawn.attackClass,
      candidate:
        validateSecurityFindingAgainstThreatModel(
          candidate,
          threatModel,
        ),
      proofPlan,
      observations,
      emittedAt,
    });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-hunter-candidate-packet-envelope.v1",
    record,
    recordSha256:
      securityHunterCandidatePacketRecordSha256(record),
  });
}
