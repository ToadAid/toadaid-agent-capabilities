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
  sealSecurityFindingRecord,
  validateSecurityFindingAgainstThreatModel,
  validateSecurityFindingEnvelope,
  validateSecurityThreatModelEnvelope,
} from "./securityAudit.js";
import type {
  SecurityEvidenceRef,
  SecurityFindingEnvelope,
  SecuritySourceLocation,
} from "./securityAuditTypes.js";
import {
  securityHunterCandidatePacketRecordSha256,
  validateSecurityHunterSpawnReceipt,
} from "./securityHunter.js";
import type {
  SecurityHunterCandidatePacketEnvelope,
} from "./securityHunterTypes.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  SecurityAuditRuntimeProvenance,
  SecurityReverificationEnvelope,
  SecurityReverificationInput,
  SecurityReverificationRecord,
  SecurityValidationDecisionEnvelope,
  SecurityValidationDecisionInput,
  SecurityValidationDecisionRecord,
  SecurityValidatorSpawnInput,
  SecurityValidatorSpawnReceipt,
} from "./securityValidatorTypes.js";

export type * from "./securityValidatorTypes.js";

const SECURITY_VALIDATOR_DELEGATED_CAPABILITIES =
  Object.freeze([
    "host:file-read",
    "host:session",
  ] as const);

const MAX_TEXT = 4_000;
const MAX_EVIDENCE_REFS = 2_000;
const MAX_SOURCE_LOCATIONS = 2_000;
const MAX_MODEL_REQUESTS = 64;

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

function normalizeRuntimeProvenance(
  provenance: SecurityAuditRuntimeProvenance | undefined,
): SecurityAuditRuntimeProvenance | null {
  if (provenance === undefined) return null;
  return Object.freeze({
    providerId: exactText(
      provenance.providerId,
      "runtimeProvenance.providerId",
      256,
    ),
    modelId: exactText(
      provenance.modelId,
      "runtimeProvenance.modelId",
      256,
    ),
  });
}

function normalizeEvidenceRefs(
  refs: readonly SecurityEvidenceRef[] | undefined,
  label: string,
  requireNonEmpty: boolean,
): readonly SecurityEvidenceRef[] {
  const resolved = refs ?? [];
  if (
    !Array.isArray(resolved) ||
    resolved.length > MAX_EVIDENCE_REFS ||
    (requireNonEmpty && resolved.length < 1)
  ) {
    throw new RangeError(`${label} count is invalid`);
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

function locationKey(
  location: SecuritySourceLocation,
): string {
  return [
    location.path,
    location.startLine,
    location.endLine,
  ].join(":");
}

function normalizeCheckedSourceLocations(
  locations: readonly SecuritySourceLocation[] | undefined,
  candidate: SecurityFindingEnvelope,
  label: string,
  requireNonEmpty: boolean,
): readonly SecuritySourceLocation[] {
  const resolved = locations ?? [];
  if (
    !Array.isArray(resolved) ||
    resolved.length > MAX_SOURCE_LOCATIONS ||
    (requireNonEmpty && resolved.length < 1)
  ) {
    throw new RangeError(
      `${label} source-location count is invalid`,
    );
  }

  const allowed = new Set(
    candidate.record.sourceLocations.map(locationKey),
  );
  const seen = new Set<string>();
  const normalized = resolved.map(
    (location, index) => {
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
      const normalizedLocation = Object.freeze({
        path: exactText(
          location.path,
          `${label}[${index}].path`,
          2_048,
        ),
        startLine: location.startLine,
        endLine: location.endLine,
      });
      const key = locationKey(normalizedLocation);
      if (!allowed.has(key)) {
        throw new Error(
          `${label} must match an exact candidate source location`,
        );
      }
      if (seen.has(key)) {
        throw new Error(
          `${label} contains duplicate source locations`,
        );
      }
      seen.add(key);
      return normalizedLocation;
    },
  );

  return Object.freeze(
    normalized.sort(
      (a, b) =>
        a.path.localeCompare(b.path) ||
        a.startLine - b.startLine ||
        a.endLine - b.endLine,
    ),
  );
}

function normalizeChildAuthoritySnapshot(
  snapshot: RunAuthoritySnapshot,
  spawnedAt: string,
): RunAuthoritySnapshot {
  if (snapshot.capturedAt !== spawnedAt) {
    throw new Error(
      "security validator authority snapshot must be captured at spawn time",
    );
  }
  if (!Array.isArray(snapshot.decisions)) {
    throw new TypeError(
      "security validator authority snapshot decisions must be an array",
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
    ...SECURITY_VALIDATOR_DELEGATED_CAPABILITIES,
  ].sort();
  if (
    allowed.length !== expected.length ||
    allowed.some(
      (value, index) => value !== expected[index],
    )
  ) {
    throw new Error(
      "SEC4 validator child authority may ALLOW only host:file-read and host:session",
    );
  }
  return snapshot;
}

function normalizeQ1Limits(
  assignmentBudget: {
    readonly modelTokens: number;
    readonly toolCalls: number;
    readonly networkRequests: number;
    readonly wallClockMs: number;
  },
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

  const tokenTotal =
    normalized.inputTokens +
    normalized.outputTokens;
  if (!Number.isSafeInteger(tokenTotal)) {
    throw new RangeError(
      "SEC4 Q1 token total exceeds safe integer range",
    );
  }
  if (
    normalized.modelRequests < 1 ||
    normalized.modelRequests > MAX_MODEL_REQUESTS
  ) {
    throw new RangeError(
      `SEC4 modelRequests must be between 1 and ${MAX_MODEL_REQUESTS}`,
    );
  }
  if (tokenTotal < 1) {
    throw new RangeError(
      "SEC4 validator requires positive model-token budget",
    );
  }
  if (normalized.networkRequests !== 0) {
    throw new Error(
      "SEC4 validator network budget must be zero",
    );
  }
  if (normalized.retries !== 0) {
    throw new Error(
      "SEC4 validator retries must be zero",
    );
  }
  if (normalized.childTasks !== 0) {
    throw new Error(
      "SEC4 validator cannot allocate nested child tasks",
    );
  }
  if (tokenTotal > assignmentBudget.modelTokens) {
    throw new RangeError(
      "SEC4 Q1 token limits exceed Hunter assignment budget",
    );
  }
  if (normalized.toolCalls > assignmentBudget.toolCalls) {
    throw new RangeError(
      "SEC4 Q1 tool-call limit exceeds Hunter assignment budget",
    );
  }
  if (
    normalized.wallClockMs >
    assignmentBudget.wallClockMs
  ) {
    throw new RangeError(
      "SEC4 Q1 wall-clock limit exceeds Hunter assignment budget",
    );
  }
  return Object.freeze(normalized);
}

export function validateSecurityHunterCandidatePacketForValidation(
  threatModelInput: SecurityValidatorSpawnInput["threatModel"],
  coverageLedgerInput: SecurityValidatorSpawnInput["coverageLedger"],
  hunterSpawnInput: SecurityValidatorSpawnInput["hunterSpawn"],
  packetInput: SecurityHunterCandidatePacketEnvelope,
): SecurityHunterCandidatePacketEnvelope {
  const threatModel =
    validateSecurityThreatModelEnvelope(threatModelInput);
  const hunterSpawn =
    validateSecurityHunterSpawnReceipt(
      threatModel,
      coverageLedgerInput,
      hunterSpawnInput,
    );

  if (
    packetInput.schemaVersion !==
    "toadaid.security-hunter-candidate-packet-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter candidate packet envelope schemaVersion",
    );
  }
  if (
    packetInput.record.schemaVersion !==
    "toadaid.security-hunter-candidate-packet.v1"
  ) {
    throw new TypeError(
      "unsupported security Hunter candidate packet schemaVersion",
    );
  }
  const recordSha256 = sha(
    packetInput.recordSha256,
    "candidatePacket.recordSha256",
  )!;
  if (
    recordSha256 !==
    securityHunterCandidatePacketRecordSha256(
      packetInput.record,
    )
  ) {
    throw new Error(
      "security Hunter candidate packet integrity mismatch",
    );
  }

  const candidate =
    validateSecurityFindingAgainstThreatModel(
      packetInput.record.candidate,
      threatModel,
    );
  if (candidate.record.state !== "CANDIDATE") {
    throw new Error(
      "SEC4 validation requires a CANDIDATE finding",
    );
  }

  const bindings = [
    [
      packetInput.record.hunterIdentitySha256,
      hunterSpawn.hunterIdentitySha256,
      "Hunter identity",
    ],
    [
      packetInput.record.assignmentSha256,
      hunterSpawn.assignmentSha256,
      "assignment",
    ],
    [
      packetInput.record.childTaskSha256,
      hunterSpawn.childTask.taskSha256,
      "Hunter child task",
    ],
    [
      packetInput.record.childBudgetLedgerSha256,
      hunterSpawn.childBudget.recordSha256,
      "Hunter child budget",
    ],
    [
      packetInput.record.sourceTreeSha256,
      hunterSpawn.sourceTreeSha256,
      "source tree",
    ],
    [
      packetInput.record.attackClass,
      hunterSpawn.attackClass,
      "attack class",
    ],
  ] as const;
  for (const [actual, expected, label] of bindings) {
    if (actual !== expected) {
      throw new Error(
        `security Hunter candidate packet ${label} binding mismatch`,
      );
    }
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-hunter-candidate-packet-envelope.v1",
    record: Object.freeze({
      ...packetInput.record,
      candidate,
    }),
    recordSha256,
  });
}

function createNeedsValidationFinding(
  candidate: SecurityFindingEnvelope,
  reason: string,
  updatedAt: string,
): SecurityFindingEnvelope {
  return sealSecurityFindingRecord({
    ...candidate.record,
    revision: candidate.record.revision + 1,
    state: "NEEDS_VALIDATION",
    stateEvidence: {
      state: "NEEDS_VALIDATION",
      reason: exactText(reason, "validation reason"),
    },
    updatedAt,
    continuity: Object.freeze({
      previousRecordSha256:
        candidate.recordSha256,
    }),
  });
}

export function spawnSecurityValidatorChild(
  input: SecurityValidatorSpawnInput,
): SecurityValidatorSpawnReceipt {
  const threatModel =
    validateSecurityThreatModelEnvelope(
      input.threatModel,
    );
  const hunterSpawn =
    validateSecurityHunterSpawnReceipt(
      threatModel,
      input.coverageLedger,
      input.hunterSpawn,
    );
  const candidatePacket =
    validateSecurityHunterCandidatePacketForValidation(
      threatModel,
      input.coverageLedger,
      hunterSpawn,
      input.candidatePacket,
    );

  const validatorIdentitySha256 = sha(
    input.validatorIdentitySha256,
    "validatorIdentitySha256",
  )!;
  if (
    validatorIdentitySha256 ===
    hunterSpawn.hunterIdentitySha256
  ) {
    throw new Error(
      "SEC4 self-validation is refused: validator identity must differ from Hunter identity",
    );
  }

  const spawnedAt = canonicalIso(
    input.createdAt,
    "createdAt",
  );
  if (
    Date.parse(spawnedAt) <
    Date.parse(candidatePacket.record.emittedAt)
  ) {
    throw new RangeError(
      "security validator spawn cannot predate candidate emission",
    );
  }

  const childAuthoritySnapshot =
    normalizeChildAuthoritySnapshot(
      input.childAuthoritySnapshot,
      spawnedAt,
    );
  const q1Limits = normalizeQ1Limits(
    hunterSpawn.assignment.budget,
    input.q1Limits,
  );
  const parentBudget =
    validateRunBudgetLedgerEnvelope(
      input.parentBudget,
    );

  const childTaskId = boundedId(
    input.childTaskId ??
      `security-validator-${candidatePacket.recordSha256.slice(0, 24)}`,
    "childTaskId",
  );
  if (
    childTaskId ===
    hunterSpawn.childTask.task.childTaskId
  ) {
    throw new Error(
      "SEC4 validator must run in a fresh child task distinct from the Hunter",
    );
  }

  const allocation = allocateChildRunBudget(
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

  const validationFinding =
    createNeedsValidationFinding(
      candidatePacket.record.candidate,
      "Fresh independent adversarial validation is in progress.",
      spawnedAt,
    );

  const runState = createRunStateCapsule({
    runId: childTaskId,
    createdAt: spawnedAt,
    objective: {
      summary:
        "Attempt to disprove the candidate first. Confirm only if bounded read-only reproduction evidence survives adversarial review.",
      status: "ACTIVE",
    },
    phase: "security-validation",
    authoritySnapshot: childAuthoritySnapshot,
    evidenceRefs: [
      {
        id: "sec4-candidate-packet",
        locator:
          `security-hunter-candidate:${candidatePacket.recordSha256}`,
        sha256: candidatePacket.recordSha256,
      },
      {
        id: "sec4-candidate-finding",
        locator:
          `security-finding:${candidatePacket.record.candidate.recordSha256}`,
        sha256:
          candidatePacket.record.candidate.recordSha256,
      },
      {
        id: "sec4-hunter-identity",
        locator:
          `security-hunter:${hunterSpawn.hunterIdentitySha256}`,
        sha256: hunterSpawn.hunterIdentitySha256,
      },
    ],
    work: {
      pending: [{
        id: "disprove",
        summary:
          "Seek disconfirming evidence before accepting the candidate; active proof execution remains outside SEC4.",
      }],
    },
  });

  const childTask = sealChildTask(
    createChildTask({
      childTaskId,
      parentRunId: parentBudget.record.runId,
      parentChildTaskId:
        parentBudget.record.childTaskId ?? null,
      createdAt: spawnedAt,
      delegatedCapabilities:
        SECURITY_VALIDATOR_DELEGATED_CAPABILITIES,
      parentAuthority: input.parentAuthority,
      runState,
    }),
  );

  const budgetAllocationSha256 =
    allocation.allocation.allocationSha256;
  const validatorExecutionSha256 = sha256({
    validatorIdentitySha256,
    hunterIdentitySha256:
      hunterSpawn.hunterIdentitySha256,
    candidatePacketSha256:
      candidatePacket.recordSha256,
    childTaskSha256: childTask.taskSha256,
    budgetAllocationSha256,
    childBudgetLedgerSha256:
      allocation.child.recordSha256,
  });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-validator-spawn.v1",
    validatorIdentitySha256,
    validatorExecutionSha256,
    hunterIdentitySha256:
      hunterSpawn.hunterIdentitySha256,
    candidatePacketSha256:
      candidatePacket.recordSha256,
    candidateFindingSha256:
      candidatePacket.record.candidate.recordSha256,
    sourceTreeSha256:
      hunterSpawn.sourceTreeSha256,
    runtimeProvenance:
      normalizeRuntimeProvenance(
        input.runtimeProvenance,
      ),
    delegatedCapabilities:
      SECURITY_VALIDATOR_DELEGATED_CAPABILITIES,
    validationFinding,
    childTask,
    parentBudget: allocation.parent,
    childBudget: allocation.child,
    budgetAllocationSha256,
    spawnedAt,
  });
}

export function validateSecurityValidatorSpawnReceipt(
  threatModelInput: SecurityValidatorSpawnInput["threatModel"],
  coverageLedgerInput: SecurityValidatorSpawnInput["coverageLedger"],
  hunterSpawnInput: SecurityValidatorSpawnInput["hunterSpawn"],
  candidatePacketInput: SecurityHunterCandidatePacketEnvelope,
  spawn: SecurityValidatorSpawnReceipt,
): SecurityValidatorSpawnReceipt {
  if (
    spawn.schemaVersion !==
    "toadaid.security-validator-spawn.v1"
  ) {
    throw new TypeError(
      "unsupported security validator spawn schemaVersion",
    );
  }

  const threatModel =
    validateSecurityThreatModelEnvelope(
      threatModelInput,
    );
  const hunterSpawn =
    validateSecurityHunterSpawnReceipt(
      threatModel,
      coverageLedgerInput,
      hunterSpawnInput,
    );
  const candidatePacket =
    validateSecurityHunterCandidatePacketForValidation(
      threatModel,
      coverageLedgerInput,
      hunterSpawn,
      candidatePacketInput,
    );

  const validatorIdentitySha256 = sha(
    spawn.validatorIdentitySha256,
    "spawn.validatorIdentitySha256",
  )!;
  if (
    validatorIdentitySha256 ===
    hunterSpawn.hunterIdentitySha256
  ) {
    throw new Error(
      "SEC4 self-validation is refused: validator identity must differ from Hunter identity",
    );
  }
  if (
    spawn.hunterIdentitySha256 !==
      hunterSpawn.hunterIdentitySha256 ||
    spawn.candidatePacketSha256 !==
      candidatePacket.recordSha256 ||
    spawn.candidateFindingSha256 !==
      candidatePacket.record.candidate.recordSha256 ||
    spawn.sourceTreeSha256 !==
      hunterSpawn.sourceTreeSha256
  ) {
    throw new Error(
      "security validator spawn provenance binding mismatch",
    );
  }
  if (
    JSON.stringify(spawn.delegatedCapabilities) !==
    JSON.stringify(
      SECURITY_VALIDATOR_DELEGATED_CAPABILITIES,
    )
  ) {
    throw new Error(
      "security validator spawn delegated capability set is invalid",
    );
  }

  const childTask = sealChildTask(
    spawn.childTask.task,
  );
  if (
    childTask.taskSha256 !==
    spawn.childTask.taskSha256
  ) {
    throw new Error(
      "security validator child-task integrity mismatch",
    );
  }
  if (
    childTask.task.childTaskId ===
    hunterSpawn.childTask.task.childTaskId
  ) {
    throw new Error(
      "security validator child task must differ from Hunter child task",
    );
  }
  if (
    childTask.task.runState.phase !==
    "security-validation"
  ) {
    throw new Error(
      "security validator child-task phase is invalid",
    );
  }
  if (
    JSON.stringify(
      childTask.task.delegatedCapabilities,
    ) !==
    JSON.stringify(
      SECURITY_VALIDATOR_DELEGATED_CAPABILITIES,
    )
  ) {
    throw new Error(
      "security validator child-task delegation is invalid",
    );
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
      "security validator child budget parent binding mismatch",
    );
  }
  const allocation =
    parentBudget.record.childAllocations.find(
      (entry) =>
        entry.allocationSha256 ===
        budgetAllocationSha256,
    );
  if (
    !allocation ||
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
      "security validator Q1 allocation lineage mismatch",
    );
  }

  const validationFinding =
    validateSecurityFindingAgainstThreatModel(
      spawn.validationFinding,
      threatModel,
    );
  const candidate =
    candidatePacket.record.candidate;
  if (
    validationFinding.record.state !==
      "NEEDS_VALIDATION" ||
    validationFinding.record.revision !==
      candidate.record.revision + 1 ||
    validationFinding.record.continuity
      .previousRecordSha256 !==
      candidate.recordSha256 ||
    validationFinding.record.findingId !==
      candidate.record.findingId ||
    validationFinding.record.attackClass !==
      candidate.record.attackClass ||
    validationFinding.record.threatModelRecordSha256 !==
      candidate.record.threatModelRecordSha256
  ) {
    throw new Error(
      "security validator NEEDS_VALIDATION predecessor binding mismatch",
    );
  }

  const spawnedAt = canonicalIso(
    spawn.spawnedAt,
    "spawn.spawnedAt",
  );
  if (
    childTask.task.createdAt !== spawnedAt ||
    childBudget.record.createdAt !== spawnedAt ||
    allocation.allocatedAt !== spawnedAt ||
    validationFinding.record.updatedAt !== spawnedAt
  ) {
    throw new Error(
      "security validator spawn time differs across validation lineage",
    );
  }

  const validatorExecutionSha256 = sha256({
    validatorIdentitySha256,
    hunterIdentitySha256:
      hunterSpawn.hunterIdentitySha256,
    candidatePacketSha256:
      candidatePacket.recordSha256,
    childTaskSha256: childTask.taskSha256,
    budgetAllocationSha256,
    childBudgetLedgerSha256:
      childBudget.recordSha256,
  });
  if (
    sha(
      spawn.validatorExecutionSha256,
      "spawn.validatorExecutionSha256",
    ) !== validatorExecutionSha256
  ) {
    throw new Error(
      "security validator execution identity mismatch",
    );
  }

  return Object.freeze({
    ...spawn,
    validatorIdentitySha256,
    validatorExecutionSha256,
    runtimeProvenance:
      spawn.runtimeProvenance === null
        ? null
        : normalizeRuntimeProvenance(
            spawn.runtimeProvenance,
          ),
    validationFinding,
    childTask,
    parentBudget,
    childBudget,
    budgetAllocationSha256,
    spawnedAt,
  });
}

export function securityValidationDecisionRecordSha256(
  record: SecurityValidationDecisionRecord,
): string {
  return sha256(record);
}

export function resolveSecurityValidation(
  threatModelInput: SecurityValidatorSpawnInput["threatModel"],
  coverageLedgerInput: SecurityValidatorSpawnInput["coverageLedger"],
  hunterSpawnInput: SecurityValidatorSpawnInput["hunterSpawn"],
  candidatePacketInput: SecurityHunterCandidatePacketEnvelope,
  spawnInput: SecurityValidatorSpawnReceipt,
  input: SecurityValidationDecisionInput,
): SecurityValidationDecisionEnvelope {
  const threatModel =
    validateSecurityThreatModelEnvelope(
      threatModelInput,
    );
  const spawn =
    validateSecurityValidatorSpawnReceipt(
      threatModel,
      coverageLedgerInput,
      hunterSpawnInput,
      candidatePacketInput,
      spawnInput,
    );
  const candidatePacket =
    validateSecurityHunterCandidatePacketForValidation(
      threatModel,
      coverageLedgerInput,
      hunterSpawnInput,
      candidatePacketInput,
    );
  const candidate =
    candidatePacket.record.candidate;
  const decidedAt = canonicalIso(
    input.decidedAt,
    "decidedAt",
  );
  if (
    Date.parse(decidedAt) <
    Date.parse(spawn.spawnedAt)
  ) {
    throw new RangeError(
      "security validation decision cannot predate validator spawn",
    );
  }

  let validationEvidenceRefs:
    readonly SecurityEvidenceRef[];
  let checkedSourceLocations:
    readonly SecuritySourceLocation[];
  let resultFinding: SecurityFindingEnvelope;

  switch (input.disposition) {
    case "NEEDS_VALIDATION":
      validationEvidenceRefs =
        normalizeEvidenceRefs(
          input.evidenceRefs,
          "validation.evidenceRefs",
          false,
        );
      checkedSourceLocations =
        normalizeCheckedSourceLocations(
          input.checkedSourceLocations,
          candidate,
          "validation.checkedSourceLocations",
          false,
        );
      resultFinding = sealSecurityFindingRecord({
        ...spawn.validationFinding.record,
        revision:
          spawn.validationFinding.record.revision + 1,
        state: "NEEDS_VALIDATION",
        stateEvidence: {
          state: "NEEDS_VALIDATION",
          reason: exactText(
            input.reason,
            "validation reason",
          ),
        },
        updatedAt: decidedAt,
        continuity: Object.freeze({
          previousRecordSha256:
            spawn.validationFinding.recordSha256,
        }),
      });
      break;

    case "CONFIRMED":
      validationEvidenceRefs =
        normalizeEvidenceRefs(
          input.proofEvidenceRefs,
          "validation.proofEvidenceRefs",
          true,
        );
      checkedSourceLocations =
        normalizeCheckedSourceLocations(
          input.reproducedSourceLocations,
          candidate,
          "validation.reproducedSourceLocations",
          true,
        );
      resultFinding = sealSecurityFindingRecord({
        ...spawn.validationFinding.record,
        revision:
          spawn.validationFinding.record.revision + 1,
        state: "CONFIRMED",
        stateEvidence: {
          state: "CONFIRMED",
          validatorIdentitySha256:
            spawn.validatorIdentitySha256,
          proofEvidenceRefs:
            validationEvidenceRefs,
        },
        updatedAt: decidedAt,
        continuity: Object.freeze({
          previousRecordSha256:
            spawn.validationFinding.recordSha256,
        }),
      });
      break;

    case "REJECTED":
      validationEvidenceRefs =
        normalizeEvidenceRefs(
          input.disproofEvidenceRefs,
          "validation.disproofEvidenceRefs",
          true,
        );
      checkedSourceLocations =
        normalizeCheckedSourceLocations(
          input.checkedSourceLocations,
          candidate,
          "validation.checkedSourceLocations",
          true,
        );
      resultFinding = sealSecurityFindingRecord({
        ...spawn.validationFinding.record,
        revision:
          spawn.validationFinding.record.revision + 1,
        state: "REJECTED",
        stateEvidence: {
          state: "REJECTED",
          reason: exactText(
            input.reason,
            "rejection reason",
          ),
          disproofEvidenceRefs:
            validationEvidenceRefs,
        },
        updatedAt: decidedAt,
        continuity: Object.freeze({
          previousRecordSha256:
            spawn.validationFinding.recordSha256,
        }),
      });
      break;

    default:
      throw new TypeError(
        "unsupported security validation disposition",
      );
  }

  const record: SecurityValidationDecisionRecord =
    Object.freeze({
      schemaVersion:
        "toadaid.security-validation-decision.v1",
      disposition: input.disposition,
      validatorIdentitySha256:
        spawn.validatorIdentitySha256,
      hunterIdentitySha256:
        spawn.hunterIdentitySha256,
      validatorExecutionSha256:
        spawn.validatorExecutionSha256,
      candidatePacketSha256:
        spawn.candidatePacketSha256,
      predecessorFindingSha256:
        spawn.validationFinding.recordSha256,
      sourceTreeSha256:
        spawn.sourceTreeSha256,
      validationMode:
        "READ_ONLY_ADVERSARIAL_REVIEW",
      validationEvidenceRefs,
      checkedSourceLocations,
      resultFinding:
        validateSecurityFindingAgainstThreatModel(
          resultFinding,
          threatModel,
        ),
      decidedAt,
    });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1",
    record,
    recordSha256:
      securityValidationDecisionRecordSha256(record),
  });
}

export function validateSecurityValidationDecisionEnvelope(
  envelope: SecurityValidationDecisionEnvelope,
): SecurityValidationDecisionEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-validation-decision-envelope.v1" ||
    envelope.record.schemaVersion !==
    "toadaid.security-validation-decision.v1"
  ) {
    throw new TypeError(
      "unsupported security validation decision schemaVersion",
    );
  }

  const dispositions = new Set([
    "NEEDS_VALIDATION",
    "CONFIRMED",
    "REJECTED",
  ]);
  if (!dispositions.has(envelope.record.disposition)) {
    throw new TypeError(
      "unsupported security validation disposition",
    );
  }

  const recordSha256 = sha(
    envelope.recordSha256,
    "validationDecision.recordSha256",
  )!;
  if (
    recordSha256 !==
    securityValidationDecisionRecordSha256(
      envelope.record,
    )
  ) {
    throw new Error(
      "security validation decision integrity mismatch",
    );
  }

  const resultFinding =
    validateSecurityFindingEnvelope(
      envelope.record.resultFinding,
    );
  if (
    resultFinding.record.state !==
    envelope.record.disposition
  ) {
    throw new Error(
      "security validation disposition does not match result finding state",
    );
  }
  if (
    envelope.record.validationMode !==
    "READ_ONLY_ADVERSARIAL_REVIEW"
  ) {
    throw new Error(
      "security validation mode is unsupported",
    );
  }

  const validatorIdentitySha256 = sha(
    envelope.record.validatorIdentitySha256,
    "validatorIdentitySha256",
  )!;
  const hunterIdentitySha256 = sha(
    envelope.record.hunterIdentitySha256,
    "hunterIdentitySha256",
  )!;
  if (
    validatorIdentitySha256 ===
    hunterIdentitySha256
  ) {
    throw new Error(
      "security validation self-confirmation provenance is invalid",
    );
  }

  const requireTerminalEvidence =
    envelope.record.disposition !==
    "NEEDS_VALIDATION";
  const validationEvidenceRefs =
    normalizeEvidenceRefs(
      envelope.record.validationEvidenceRefs,
      "validationDecision.validationEvidenceRefs",
      requireTerminalEvidence,
    );
  const checkedSourceLocations =
    normalizeCheckedSourceLocations(
      envelope.record.checkedSourceLocations,
      resultFinding,
      "validationDecision.checkedSourceLocations",
      requireTerminalEvidence,
    );

  const predecessorFindingSha256 = sha(
    envelope.record.predecessorFindingSha256,
    "predecessorFindingSha256",
  )!;
  if (
    resultFinding.record.continuity
      .previousRecordSha256 !==
    predecessorFindingSha256
  ) {
    throw new Error(
      "security validation result finding predecessor binding mismatch",
    );
  }

  const decidedAt = canonicalIso(
    envelope.record.decidedAt,
    "decidedAt",
  );
  if (
    resultFinding.record.updatedAt !==
    decidedAt
  ) {
    throw new Error(
      "security validation result finding timestamp differs from decision",
    );
  }

  switch (envelope.record.disposition) {
    case "CONFIRMED": {
      const stateEvidence =
        resultFinding.record.stateEvidence;
      if (
        stateEvidence.state !== "CONFIRMED" ||
        stateEvidence.validatorIdentitySha256 !==
          validatorIdentitySha256 ||
        sha256(stateEvidence.proofEvidenceRefs) !==
          sha256(validationEvidenceRefs)
      ) {
        throw new Error(
          "security CONFIRMED decision proof/state binding mismatch",
        );
      }
      break;
    }
    case "REJECTED": {
      const stateEvidence =
        resultFinding.record.stateEvidence;
      if (
        stateEvidence.state !== "REJECTED" ||
        sha256(
          stateEvidence.disproofEvidenceRefs,
        ) !== sha256(validationEvidenceRefs)
      ) {
        throw new Error(
          "security REJECTED decision disproof/state binding mismatch",
        );
      }
      break;
    }
    case "NEEDS_VALIDATION":
      if (
        resultFinding.record.stateEvidence.state !==
        "NEEDS_VALIDATION"
      ) {
        throw new Error(
          "security NEEDS_VALIDATION state evidence mismatch",
        );
      }
      break;
    default:
      throw new TypeError(
        "unsupported security validation disposition",
      );
  }

  const validatorExecutionSha256 = sha(
    envelope.record.validatorExecutionSha256,
    "validatorExecutionSha256",
  )!;
  const candidatePacketSha256 = sha(
    envelope.record.candidatePacketSha256,
    "candidatePacketSha256",
  )!;
  const sourceTreeSha256 = sha(
    envelope.record.sourceTreeSha256,
    "sourceTreeSha256",
  )!;

  return Object.freeze({
    schemaVersion:
      "toadaid.security-validation-decision-envelope.v1",
    record: Object.freeze({
      ...envelope.record,
      validatorIdentitySha256,
      hunterIdentitySha256,
      validatorExecutionSha256,
      candidatePacketSha256,
      predecessorFindingSha256,
      sourceTreeSha256,
      validationEvidenceRefs,
      checkedSourceLocations,
      resultFinding,
      decidedAt,
    }),
    recordSha256,
  });
}

export function validateSecurityValidationDecisionAgainstLineage(
  threatModelInput: SecurityValidatorSpawnInput["threatModel"],
  coverageLedgerInput: SecurityValidatorSpawnInput["coverageLedger"],
  hunterSpawnInput: SecurityValidatorSpawnInput["hunterSpawn"],
  candidatePacketInput: SecurityHunterCandidatePacketEnvelope,
  validatorSpawnInput: SecurityValidatorSpawnReceipt,
  envelope: SecurityValidationDecisionEnvelope,
): SecurityValidationDecisionEnvelope {
  const threatModel =
    validateSecurityThreatModelEnvelope(
      threatModelInput,
    );
  const hunterSpawn =
    validateSecurityHunterSpawnReceipt(
      threatModel,
      coverageLedgerInput,
      hunterSpawnInput,
    );
  const candidatePacket =
    validateSecurityHunterCandidatePacketForValidation(
      threatModel,
      coverageLedgerInput,
      hunterSpawn,
      candidatePacketInput,
    );
  const validatorSpawn =
    validateSecurityValidatorSpawnReceipt(
      threatModel,
      coverageLedgerInput,
      hunterSpawn,
      candidatePacket,
      validatorSpawnInput,
    );
  const decision =
    validateSecurityValidationDecisionEnvelope(
      envelope,
    );

  if (
    decision.record.validatorIdentitySha256 !==
      validatorSpawn.validatorIdentitySha256 ||
    decision.record.hunterIdentitySha256 !==
      hunterSpawn.hunterIdentitySha256 ||
    decision.record.validatorExecutionSha256 !==
      validatorSpawn.validatorExecutionSha256 ||
    decision.record.candidatePacketSha256 !==
      candidatePacket.recordSha256 ||
    decision.record.predecessorFindingSha256 !==
      validatorSpawn.validationFinding.recordSha256 ||
    decision.record.sourceTreeSha256 !==
      validatorSpawn.sourceTreeSha256
  ) {
    throw new Error(
      "security validation decision authoritative lineage binding mismatch",
    );
  }

  const predecessor =
    validatorSpawn.validationFinding;
  const result =
    decision.record.resultFinding;
  if (
    result.record.revision !==
      predecessor.record.revision + 1 ||
    result.record.continuity
      .previousRecordSha256 !==
      predecessor.recordSha256 ||
    result.record.findingId !==
      predecessor.record.findingId ||
    result.record.threatModelRecordSha256 !==
      predecessor.record.threatModelRecordSha256 ||
    result.record.attackClass !==
      predecessor.record.attackClass ||
    result.record.title !==
      predecessor.record.title ||
    result.record.createdAt !==
      predecessor.record.createdAt ||
    sha256(result.record.evidenceRefs) !==
      sha256(predecessor.record.evidenceRefs) ||
    sha256(result.record.sourceLocations) !==
      sha256(predecessor.record.sourceLocations)
  ) {
    throw new Error(
      "security validation result finding rewrites predecessor identity or evidence",
    );
  }

  if (
    Date.parse(decision.record.decidedAt) <
    Date.parse(validatorSpawn.spawnedAt)
  ) {
    throw new RangeError(
      "security validation decision predates authoritative validator spawn",
    );
  }

  return decision;
}

export function securityReverificationRecordSha256(
  record: SecurityReverificationRecord,
): string {
  return sha256(record);
}

export function independentlyReverifyConfirmedFinding(
  threatModelInput: SecurityValidatorSpawnInput["threatModel"],
  coverageLedgerInput: SecurityValidatorSpawnInput["coverageLedger"],
  hunterSpawnInput: SecurityValidatorSpawnInput["hunterSpawn"],
  candidatePacketInput: SecurityHunterCandidatePacketEnvelope,
  validatorSpawnInput: SecurityValidatorSpawnReceipt,
  validationDecisionInput:
    SecurityValidationDecisionEnvelope,
  input: SecurityReverificationInput,
): SecurityReverificationEnvelope {
  const validationDecision =
    validateSecurityValidationDecisionAgainstLineage(
      threatModelInput,
      coverageLedgerInput,
      hunterSpawnInput,
      candidatePacketInput,
      validatorSpawnInput,
      validationDecisionInput,
    );
  if (
    validationDecision.record.disposition !==
      "CONFIRMED" ||
    validationDecision.record.resultFinding.record.state !==
      "CONFIRMED"
  ) {
    throw new Error(
      "independent re-verification requires a CONFIRMED validation decision",
    );
  }

  const reVerifierIdentitySha256 = sha(
    input.reVerifierIdentitySha256,
    "reVerifierIdentitySha256",
  )!;
  if (
    reVerifierIdentitySha256 ===
      validationDecision.record.hunterIdentitySha256 ||
    reVerifierIdentitySha256 ===
      validationDecision.record.validatorIdentitySha256
  ) {
    throw new Error(
      "SEC4 independent re-verifier identity must differ from Hunter and validator identities",
    );
  }

  const evidenceRefs = normalizeEvidenceRefs(
    input.evidenceRefs,
    "reverification.evidenceRefs",
    true,
  );
  const checkedSourceLocations =
    normalizeCheckedSourceLocations(
      input.checkedSourceLocations,
      validationDecision.record.resultFinding,
      "reverification.checkedSourceLocations",
      true,
    );
  const reviewedAt = canonicalIso(
    input.reviewedAt,
    "reviewedAt",
  );
  if (
    Date.parse(reviewedAt) <
    Date.parse(validationDecision.record.decidedAt)
  ) {
    throw new RangeError(
      "security re-verification cannot predate validation decision",
    );
  }

  const record: SecurityReverificationRecord =
    Object.freeze({
      schemaVersion:
        "toadaid.security-reverification.v1",
      disposition:
        input.verified ? "VERIFIED" : "NEEDS_REVIEW",
      reVerifierIdentitySha256,
      validatorIdentitySha256:
        validationDecision.record.validatorIdentitySha256,
      hunterIdentitySha256:
        validationDecision.record.hunterIdentitySha256,
      validationDecisionSha256:
        validationDecision.recordSha256,
      confirmedFindingSha256:
        validationDecision.record.resultFinding.recordSha256,
      sourceTreeSha256:
        validationDecision.record.sourceTreeSha256,
      evidenceRefs,
      checkedSourceLocations,
      runtimeProvenance:
        normalizeRuntimeProvenance(
          input.runtimeProvenance,
        ),
      reason: exactText(
        input.reason,
        "reverification reason",
      ),
      reviewedAt,
    });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-reverification-envelope.v1",
    record,
    recordSha256:
      securityReverificationRecordSha256(record),
  });
}
