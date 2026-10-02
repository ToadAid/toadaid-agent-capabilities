import {
  assertChildTaskPredecessor,
  childTaskSha256,
  sealChildTask,
} from "./childTaskLifecycle.js";
import type {
  ChildTaskRecord,
} from "./childTaskLifecycle.js";
import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import {
  checkpointRunStateCapsule,
  createRunStateCapsule,
  resumeRunStateCapsule,
  runStateCapsuleSha256,
  serializeRunStateCapsule,
  validateRunStateCapsule,
} from "./runStateCapsule.js";
import type {
  RunEvidenceReference,
  RunStateCapsule,
} from "./runStateCapsule.js";
import {
  validateSecurityFindingAgainstThreatModel,
  validateSecurityFindingEnvelope,
  validateSecurityThreatModelEnvelope,
} from "./securityAudit.js";
import type {
  SecurityFindingEnvelope,
  SecurityThreatModelEnvelope,
} from "./securityAuditTypes.js";
import {
  rebaseSecurityCoverageLedger,
  validateSecurityCoverageLedgerEnvelope,
} from "./securityCoverage.js";
import type {
  SecurityCoverageLedgerEnvelope,
} from "./securityCoverageTypes.js";
import type {
  CheckpointSecurityAuditStateInput,
  CreateSecurityAuditStateInput,
  RebaseSecurityAuditStateInput,
  ResumeSecurityAuditStateInput,
  SecurityAuditChildLineageEntry,
  SecurityAuditChildRole,
  SecurityAuditFindingEntry,
  SecurityAuditResumeOutcome,
  SecurityAuditStateRuntimeProvenance,
  SecurityAuditStateEnvelope,
  SecurityAuditStateRecord,
  SecurityAuditStateStatus,
  SecurityAuditStateTransition,
  SecurityFindingSourceDisposition,
} from "./securityAuditStateTypes.js";

export type * from "./securityAuditStateTypes.js";

const MAX_MODELS = 1_000;
const MAX_FINDINGS = 10_000;
const MAX_CHILD_TASKS = 5_000;
const MAX_REVISION = 1_000_000;
const PATH_MAX = 2_048;

const STATE_STATUSES:
  readonly SecurityAuditStateStatus[] = [
    "ACTIVE",
    "BLOCKED",
    "COMPLETE",
  ];

const STATE_TRANSITIONS:
  readonly SecurityAuditStateTransition[] = [
    "INITIAL",
    "CHECKPOINT",
    "RESUME",
    "SOURCE_REBASE",
    "PROVIDER_CHANGE",
  ];

const FINDING_DISPOSITIONS:
  readonly SecurityFindingSourceDisposition[] = [
    "CURRENT_REVISION",
    "CARRIED_UNCHANGED",
    "INVALIDATED_SOURCE_CHANGE",
  ];

const CHILD_ROLES:
  readonly SecurityAuditChildRole[] = [
    "HUNTER",
    "VALIDATOR",
    "REVERIFIER",
  ];

function exactText(
  value: string,
  label: string,
  maximum = 4_000,
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

function relativePath(
  value: string,
  label: string,
): string {
  const normalized = exactText(
    value,
    label,
    PATH_MAX,
  ).replace(/\\/g, "/");
  if (
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized)
  ) {
    throw new TypeError(
      `${label} must be repository-relative`,
    );
  }
  const parts = normalized.split("/");
  if (
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
  return normalized;
}

function pathWithin(
  path: string,
  root: string,
): boolean {
  return (
    path === root ||
    path.startsWith(`${root}/`)
  );
}

function pathIntersects(
  a: string,
  b: string,
): boolean {
  return (
    pathWithin(a, b) ||
    pathWithin(b, a)
  );
}

function normalizeChangedPaths(
  values: readonly string[],
): readonly string[] {
  if (!Array.isArray(values)) {
    throw new TypeError(
      "changedPaths must be an array",
    );
  }
  const normalized = values.map(
    (value, index) =>
      relativePath(
        value,
        `changedPaths[${index}]`,
      ),
  );
  const unique = [...new Set(normalized)].sort();
  if (unique.length !== normalized.length) {
    throw new Error(
      "changedPaths contains duplicates",
    );
  }
  return Object.freeze(unique);
}

function normalizeRuntimeProvenance(
  input:
    | SecurityAuditStateRuntimeProvenance
    | undefined,
): SecurityAuditStateRuntimeProvenance {
  return Object.freeze({
    providerIdentitySha256:
      input?.providerIdentitySha256 === null ||
      input?.providerIdentitySha256 === undefined
        ? null
        : sha(
            input.providerIdentitySha256,
            "providerIdentitySha256",
          )!,
    modelIdentitySha256:
      input?.modelIdentitySha256 === null ||
      input?.modelIdentitySha256 === undefined
        ? null
        : sha(
            input.modelIdentitySha256,
            "modelIdentitySha256",
          )!,
  });
}

function runtimeChanged(
  before: SecurityAuditStateRuntimeProvenance,
  after: SecurityAuditStateRuntimeProvenance,
): boolean {
  return sha256(before) !== sha256(after);
}

function objectiveStatus(
  status: SecurityAuditStateStatus,
): "ACTIVE" | "BLOCKED" | "COMPLETE" {
  return status;
}

function validateThreatModels(
  models: readonly SecurityThreatModelEnvelope[],
  currentShaInput: string,
): readonly SecurityThreatModelEnvelope[] {
  if (
    !Array.isArray(models) ||
    models.length < 1 ||
    models.length > MAX_MODELS
  ) {
    throw new RangeError(
      "security audit threat-model history count is invalid",
    );
  }
  const validated = models.map(
    validateSecurityThreatModelEnvelope,
  );
  const currentSha = sha(
    currentShaInput,
    "currentThreatModelRecordSha256",
  )!;
  const current =
    validated[validated.length - 1]!;
  if (current.recordSha256 !== currentSha) {
    throw new Error(
      "current threat model must be the final history entry",
    );
  }

  const first = validated[0]!;
  const seen = new Set<string>();
  for (const model of validated) {
    if (seen.has(model.recordSha256)) {
      throw new Error(
        "security audit threat-model history contains duplicates",
      );
    }
    seen.add(model.recordSha256);
    if (
      model.record.auditId !== first.record.auditId ||
      model.record.binding.runId !==
        first.record.binding.runId ||
      model.record.binding
        .repositoryIdentitySha256 !==
        first.record.binding.repositoryIdentitySha256 ||
      model.record.binding.configurationSha256 !==
        first.record.binding.configurationSha256 ||
      model.record.binding.ruleSetSha256 !==
        first.record.binding.ruleSetSha256 ||
      model.record.binding.scopeSha256 !==
        first.record.binding.scopeSha256
    ) {
      throw new Error(
        "security audit threat-model history crosses audit/repository/config/rules/scope identity",
      );
    }
  }
  return Object.freeze(validated);
}

function modelBySha(
  models: readonly SecurityThreatModelEnvelope[],
): ReadonlyMap<string, SecurityThreatModelEnvelope> {
  return new Map(
    models.map((model) => [
      model.recordSha256,
      model,
    ]),
  );
}

function normalizeFindingEntries(
  entries:
    readonly SecurityAuditFindingEntry[],
  models: readonly SecurityThreatModelEnvelope[],
  currentModel: SecurityThreatModelEnvelope,
): readonly SecurityAuditFindingEntry[] {
  if (
    !Array.isArray(entries) ||
    entries.length > MAX_FINDINGS
  ) {
    throw new RangeError(
      "security audit finding count is invalid",
    );
  }
  const modelsBySha = modelBySha(models);
  const ids = new Set<string>();

  const normalized = entries.map(
    (entry, index) => {
      const finding =
        validateSecurityFindingEnvelope(
          entry.finding,
        );
      const model = modelsBySha.get(
        finding.record
          .threatModelRecordSha256,
      );
      if (!model) {
        throw new Error(
          "security audit finding references a threat model outside durable history",
        );
      }
      validateSecurityFindingAgainstThreatModel(
        finding,
        model,
      );
      if (ids.has(finding.record.findingId)) {
        throw new Error(
          "security audit state stores only one current envelope per findingId",
        );
      }
      ids.add(finding.record.findingId);

      if (
        !FINDING_DISPOSITIONS.includes(
          entry.sourceDisposition,
        )
      ) {
        throw new TypeError(
          `findings[${index}].sourceDisposition is invalid`,
        );
      }

      const sourceChangeSha256 =
        entry.sourceChangeSha256 === null
          ? null
          : sha(
              entry.sourceChangeSha256,
              `findings[${index}].sourceChangeSha256`,
            )!;

      if (
        entry.sourceDisposition ===
        "CURRENT_REVISION"
      ) {
        if (
          finding.record
            .threatModelRecordSha256 !==
          currentModel.recordSha256
        ) {
          throw new Error(
            "CURRENT_REVISION finding must bind the current threat model",
          );
        }
        if (sourceChangeSha256 !== null) {
          throw new Error(
            "CURRENT_REVISION finding cannot carry source-change invalidation",
          );
        }
      } else {
        if (
          finding.record
            .threatModelRecordSha256 ===
          currentModel.recordSha256
        ) {
          throw new Error(
            "historical finding disposition cannot bind the current threat model",
          );
        }
        if (sourceChangeSha256 === null) {
          throw new Error(
            "historical finding disposition requires source-change lineage",
          );
        }
      }

      return Object.freeze({
        finding,
        sourceDisposition:
          entry.sourceDisposition,
        sourceChangeSha256,
      });
    },
  );

  return Object.freeze(
    normalized.sort((a, b) =>
      a.finding.record.findingId.localeCompare(
        b.finding.record.findingId,
      ),
    ),
  );
}

function normalizeChildTasks(
  entries:
    readonly SecurityAuditChildLineageEntry[],
  models: readonly SecurityThreatModelEnvelope[],
  currentModel: SecurityThreatModelEnvelope,
): readonly SecurityAuditChildLineageEntry[] {
  if (
    !Array.isArray(entries) ||
    entries.length > MAX_CHILD_TASKS
  ) {
    throw new RangeError(
      "security audit child-task count is invalid",
    );
  }
  const sourceTrees = new Set(
    models.map(
      (model) =>
        model.record.binding.sourceTreeSha256,
    ),
  );
  const ids = new Set<string>();

  const normalized = entries.map(
    (entry, index) => {
      if (!CHILD_ROLES.includes(entry.role)) {
        throw new TypeError(
          `childTasks[${index}].role is invalid`,
        );
      }
      if (
        entry.sourceDisposition !==
          "CURRENT_SOURCE" &&
        entry.sourceDisposition !==
          "HISTORICAL_SOURCE"
      ) {
        throw new TypeError(
          `childTasks[${index}].sourceDisposition is invalid`,
        );
      }

      const task = sealChildTask(
        entry.task,
      ).task;
      const taskSha = childTaskSha256(task);
      if (
        sha(
          entry.taskSha256,
          `childTasks[${index}].taskSha256`,
        ) !== taskSha
      ) {
        throw new Error(
          "security audit child-task hash mismatch",
        );
      }
      if (
        ids.has(task.childTaskId)
      ) {
        throw new Error(
          "security audit childTaskId is duplicated",
        );
      }
      ids.add(task.childTaskId);

      const sourceTreeSha256 = sha(
        entry.sourceTreeSha256,
        `childTasks[${index}].sourceTreeSha256`,
      )!;
      if (!sourceTrees.has(sourceTreeSha256)) {
        throw new Error(
          "security audit child task references source outside threat-model history",
        );
      }
      const isCurrent =
        sourceTreeSha256 ===
        currentModel.record.binding
          .sourceTreeSha256;
      if (
        isCurrent !==
        (entry.sourceDisposition ===
          "CURRENT_SOURCE")
      ) {
        throw new Error(
          "security audit child source disposition does not match source tree",
        );
      }

      return Object.freeze({
        role: entry.role,
        sourceTreeSha256,
        sourceDisposition:
          entry.sourceDisposition,
        task,
        taskSha256: taskSha,
      });
    },
  );

  return Object.freeze(
    normalized.sort((a, b) =>
      a.task.childTaskId.localeCompare(
        b.task.childTaskId,
      ),
    ),
  );
}

function stateEvidenceRefs(
  currentModel: SecurityThreatModelEnvelope,
  coverage:
    SecurityCoverageLedgerEnvelope,
  findings:
    readonly SecurityAuditFindingEntry[],
  childTasks:
    readonly SecurityAuditChildLineageEntry[],
): readonly RunEvidenceReference[] {
  const refs: RunEvidenceReference[] = [
    {
      id: "security-threat-model",
      locator:
        `security://threat-model/${currentModel.recordSha256}`,
      sha256: currentModel.recordSha256,
    },
    {
      id: "security-coverage-ledger",
      locator:
        `security://coverage/${coverage.recordSha256}`,
      sha256: coverage.recordSha256,
    },
  ];
  for (const entry of findings) {
    refs.push({
      id:
        `security-finding-${entry.finding.record.findingId}`,
      locator:
        `security://finding/${entry.finding.recordSha256}`,
      sha256:
        entry.finding.recordSha256,
    });
  }
  for (const entry of childTasks) {
    refs.push({
      id:
        `security-child-${entry.task.childTaskId}`,
      locator:
        `security://child/${entry.taskSha256}`,
      sha256: entry.taskSha256,
    });
  }
  return Object.freeze(
    refs.sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
  );
}

function assertRunStateEvidenceBinding(
  runState: RunStateCapsule,
  expected:
    readonly RunEvidenceReference[],
): void {
  const canonical =
    validateRunStateCapsule(runState);
  if (
    sha256(canonical.evidenceRefs) !==
    sha256(expected)
  ) {
    throw new Error(
      "security audit P4 run-state evidence binding mismatch",
    );
  }
}

function stateRecordSha256(
  record: SecurityAuditStateRecord,
): string {
  return sha256(record);
}

export function securityAuditStateRecordSha256(
  record: SecurityAuditStateRecord,
): string {
  return stateRecordSha256(record);
}

function normalizeStateRecord(
  record: SecurityAuditStateRecord,
): SecurityAuditStateRecord {
  if (
    record.schemaVersion !==
    "toadaid.security-audit-state.v1"
  ) {
    throw new TypeError(
      "unsupported security audit state schemaVersion",
    );
  }
  if (
    !Number.isSafeInteger(record.revision) ||
    record.revision < 0 ||
    record.revision > MAX_REVISION
  ) {
    throw new RangeError(
      "security audit state revision is invalid",
    );
  }
  if (!STATE_STATUSES.includes(record.status)) {
    throw new TypeError(
      "security audit state status is invalid",
    );
  }
  if (
    !STATE_TRANSITIONS.includes(
      record.continuity.transition,
    )
  ) {
    throw new TypeError(
      "security audit state transition is invalid",
    );
  }

  const threatModels = validateThreatModels(
    record.threatModels,
    record.currentThreatModelRecordSha256,
  );
  const currentModel =
    threatModels[threatModels.length - 1]!;
  const auditId = boundedId(
    record.auditId,
    "auditId",
  );
  if (
    auditId !== currentModel.record.auditId
  ) {
    throw new Error(
      "security audit state auditId mismatch",
    );
  }

  const coverageLedger =
    validateSecurityCoverageLedgerEnvelope(
      record.coverageLedger,
      currentModel,
    );
  const findings = normalizeFindingEntries(
    record.findings,
    threatModels,
    currentModel,
  );
  const childTasks = normalizeChildTasks(
    record.childTasks,
    threatModels,
    currentModel,
  );
  const runtimeProvenance =
    normalizeRuntimeProvenance(
      record.runtimeProvenance,
    );
  const runState =
    validateRunStateCapsule(
      record.runState,
    );

  const createdAt = canonicalIso(
    record.createdAt,
    "createdAt",
  );
  const updatedAt = canonicalIso(
    record.updatedAt,
    "updatedAt",
  );
  if (
    Date.parse(updatedAt) <
    Date.parse(createdAt)
  ) {
    throw new RangeError(
      "security audit state updatedAt cannot precede createdAt",
    );
  }
  if (
    runState.runId !==
      currentModel.record.binding.runId ||
    runState.revision !== record.revision ||
    runState.createdAt !== createdAt ||
    runState.updatedAt !== updatedAt ||
    runState.objective.status !==
      objectiveStatus(record.status)
  ) {
    throw new Error(
      "security audit state P4 run-state continuity mismatch",
    );
  }

  const expectedEvidence = stateEvidenceRefs(
    currentModel,
    coverageLedger,
    findings,
    childTasks,
  );
  assertRunStateEvidenceBinding(
    runState,
    expectedEvidence,
  );

  const previousStateRecordSha256 =
    record.continuity
      .previousStateRecordSha256 === null
      ? null
      : sha(
          record.continuity
            .previousStateRecordSha256,
          "continuity.previousStateRecordSha256",
        )!;
  if (
    record.revision === 0 &&
    (
      record.continuity.transition !==
        "INITIAL" ||
      previousStateRecordSha256 !== null
    )
  ) {
    throw new Error(
      "initial security audit state requires predecessor-free INITIAL continuity",
    );
  }
  if (
    record.revision > 0 &&
    (
      record.continuity.transition ===
        "INITIAL" ||
      previousStateRecordSha256 === null
    )
  ) {
    throw new Error(
      "revised security audit state requires predecessor continuity",
    );
  }

  const sourceChangeSha256 =
    record.continuity
      .sourceChangeSha256 === null
      ? null
      : sha(
          record.continuity
            .sourceChangeSha256,
          "continuity.sourceChangeSha256",
        )!;
  const providerChangeSha256 =
    record.continuity
      .providerChangeSha256 === null
      ? null
      : sha(
          record.continuity
            .providerChangeSha256,
          "continuity.providerChangeSha256",
        )!;

  if (
    record.continuity.transition ===
      "SOURCE_REBASE"
  ) {
    if (sourceChangeSha256 === null) {
      throw new Error(
        "SOURCE_REBASE requires source-change evidence",
      );
    }
  } else if (sourceChangeSha256 !== null) {
    throw new Error(
      "non-source-rebase transition cannot carry source-change evidence",
    );
  }

  if (
    record.continuity.transition ===
      "PROVIDER_CHANGE"
  ) {
    if (providerChangeSha256 === null) {
      throw new Error(
        "PROVIDER_CHANGE requires provider-change evidence",
      );
    }
  } else if (providerChangeSha256 !== null) {
    throw new Error(
      "non-provider-change transition cannot carry provider-change evidence",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-audit-state.v1",
    auditId,
    revision: record.revision,
    status: record.status,
    threatModels,
    currentThreatModelRecordSha256:
      currentModel.recordSha256,
    coverageLedger,
    findings,
    childTasks,
    runtimeProvenance,
    runState,
    createdAt,
    updatedAt,
    continuity: Object.freeze({
      previousStateRecordSha256,
      transition:
        record.continuity.transition,
      sourceChangeSha256,
      providerChangeSha256,
    }),
  });
}

export function sealSecurityAuditStateRecord(
  record: SecurityAuditStateRecord,
): SecurityAuditStateEnvelope {
  const normalized =
    normalizeStateRecord(record);
  return Object.freeze({
    schemaVersion:
      "toadaid.security-audit-state-envelope.v1",
    record: normalized,
    recordSha256:
      stateRecordSha256(normalized),
  });
}

export function validateSecurityAuditStateEnvelope(
  envelope: SecurityAuditStateEnvelope,
): SecurityAuditStateEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-audit-state-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security audit state envelope schemaVersion",
    );
  }
  const record =
    normalizeStateRecord(envelope.record);
  const recordSha256 = sha(
    envelope.recordSha256,
    "recordSha256",
  )!;
  if (
    recordSha256 !==
    stateRecordSha256(record)
  ) {
    throw new Error(
      "security audit state integrity mismatch",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-audit-state-envelope.v1",
    record,
    recordSha256,
  });
}

function currentModel(
  state: SecurityAuditStateEnvelope,
): SecurityThreatModelEnvelope {
  return state.record.threatModels[
    state.record.threatModels.length - 1
  ]!;
}

function normalizeInitialFindings(
  entries:
    readonly SecurityAuditFindingEntry[]
      | undefined,
  model: SecurityThreatModelEnvelope,
): readonly SecurityAuditFindingEntry[] {
  return normalizeFindingEntries(
    (entries ?? []).map((entry) => ({
      ...entry,
      sourceDisposition:
        "CURRENT_REVISION" as const,
      sourceChangeSha256: null,
    })),
    [model],
    model,
  );
}

function normalizeInitialChildTasks(
  entries:
    readonly SecurityAuditChildLineageEntry[]
      | undefined,
  model: SecurityThreatModelEnvelope,
): readonly SecurityAuditChildLineageEntry[] {
  return normalizeChildTasks(
    (entries ?? []).map((entry) => ({
      ...entry,
      sourceTreeSha256:
        model.record.binding.sourceTreeSha256,
      sourceDisposition:
        "CURRENT_SOURCE" as const,
    })),
    [model],
    model,
  );
}

export function createSecurityAuditState(
  input: CreateSecurityAuditStateInput,
): SecurityAuditStateEnvelope {
  const model =
    validateSecurityThreatModelEnvelope(
      input.threatModel,
    );
  const coverage =
    validateSecurityCoverageLedgerEnvelope(
      input.coverageLedger,
      model,
    );
  const findings = normalizeInitialFindings(
    input.findings,
    model,
  );
  const childTasks =
    normalizeInitialChildTasks(
      input.childTasks,
      model,
    );
  const runtimeProvenance =
    normalizeRuntimeProvenance(
      input.runtimeProvenance,
    );
  const createdAt = canonicalIso(
    input.createdAt,
    "createdAt",
  );

  const evidenceRefs = stateEvidenceRefs(
    model,
    coverage,
    findings,
    childTasks,
  );
  const runState =
    createRunStateCapsule({
      runId:
        model.record.binding.runId,
      createdAt,
      objective: {
        summary:
          `Security audit ${model.record.auditId}`,
        status: "ACTIVE",
      },
      phase: "SECURITY_AUDIT",
      authoritySnapshot:
        input.authoritySnapshot,
      evidenceRefs,
      artifactRefs: [],
    });

  return sealSecurityAuditStateRecord({
    schemaVersion:
      "toadaid.security-audit-state.v1",
    auditId: model.record.auditId,
    revision: 0,
    status: "ACTIVE",
    threatModels: Object.freeze([model]),
    currentThreatModelRecordSha256:
      model.recordSha256,
    coverageLedger: coverage,
    findings,
    childTasks,
    runtimeProvenance,
    runState,
    createdAt,
    updatedAt: createdAt,
    continuity: Object.freeze({
      previousStateRecordSha256: null,
      transition: "INITIAL",
      sourceChangeSha256: null,
      providerChangeSha256: null,
    }),
  });
}

function assertFindingEvolution(
  before:
    readonly SecurityAuditFindingEntry[],
  after:
    readonly SecurityAuditFindingEntry[],
): void {
  const previous = new Map(
    before.map((entry) => [
      entry.finding.record.findingId,
      entry,
    ]),
  );
  const nextById = new Map(
    after.map((entry) => [
      entry.finding.record.findingId,
      entry,
    ]),
  );

  for (const prior of before) {
    if (
      !nextById.has(
        prior.finding.record.findingId,
      )
    ) {
      throw new Error(
        "security audit checkpoint cannot drop an existing finding",
      );
    }
  }

  for (const next of after) {
    const prior = previous.get(
      next.finding.record.findingId,
    );
    if (!prior) {
      if (
        next.sourceDisposition !==
          "CURRENT_REVISION" ||
        next.sourceChangeSha256 !== null
      ) {
        throw new Error(
          "security audit checkpoint can append only current-revision findings",
        );
      }
      continue;
    }

    if (
      next.sourceDisposition !==
        prior.sourceDisposition ||
      next.sourceChangeSha256 !==
        prior.sourceChangeSha256
    ) {
      throw new Error(
        "security audit checkpoint cannot rewrite finding source provenance",
      );
    }

    if (
      next.finding.recordSha256 ===
      prior.finding.recordSha256
    ) {
      continue;
    }
    if (
      next.finding.record.revision !==
        prior.finding.record.revision + 1 ||
      next.finding.record.continuity
        .previousRecordSha256 !==
        prior.finding.recordSha256 ||
      next.finding.record.createdAt !==
        prior.finding.record.createdAt ||
      next.finding.record.attackClass !==
        prior.finding.record.attackClass
    ) {
      throw new Error(
        "security audit finding update must be contiguous predecessor-bound evolution",
      );
    }
  }
}

function assertChildEvolution(
  before:
    readonly SecurityAuditChildLineageEntry[],
  after:
    readonly SecurityAuditChildLineageEntry[],
): void {
  const previous = new Map(
    before.map((entry) => [
      entry.task.childTaskId,
      entry,
    ]),
  );
  const nextById = new Map(
    after.map((entry) => [
      entry.task.childTaskId,
      entry,
    ]),
  );

  for (const prior of before) {
    if (
      !nextById.has(
        prior.task.childTaskId,
      )
    ) {
      throw new Error(
        "security audit checkpoint cannot drop existing child lineage",
      );
    }
  }

  for (const next of after) {
    const prior = previous.get(
      next.task.childTaskId,
    );
    if (!prior) {
      if (
        next.sourceDisposition !==
        "CURRENT_SOURCE"
      ) {
        throw new Error(
          "security audit checkpoint can append only current-source child lineage",
        );
      }
      continue;
    }

    if (next.role !== prior.role) {
      throw new Error(
        "security audit checkpoint cannot relabel child role",
      );
    }
    if (
      next.sourceTreeSha256 !==
        prior.sourceTreeSha256 ||
      next.sourceDisposition !==
        prior.sourceDisposition
    ) {
      throw new Error(
        "security audit checkpoint cannot rewrite child source provenance",
      );
    }

    if (
      next.taskSha256 === prior.taskSha256
    ) {
      continue;
    }
    assertChildTaskPredecessor(
      prior.task,
      next.task,
    );
  }
}

export function checkpointSecurityAuditState(
  previousInput:
    SecurityAuditStateEnvelope,
  input: CheckpointSecurityAuditStateInput,
): SecurityAuditStateEnvelope {
  const previous =
    validateSecurityAuditStateEnvelope(
      previousInput,
    );
  const model = currentModel(previous);
  const status =
    input.status ?? previous.record.status;
  if (!STATE_STATUSES.includes(status)) {
    throw new TypeError(
      "checkpoint security audit status is invalid",
    );
  }

  const findings =
    input.findings === undefined
      ? previous.record.findings
      : normalizeFindingEntries(
          input.findings,
          previous.record.threatModels,
          model,
        );
  const childTasks =
    input.childTasks === undefined
      ? previous.record.childTasks
      : normalizeChildTasks(
          input.childTasks,
          previous.record.threatModels,
          model,
        );
  assertFindingEvolution(
    previous.record.findings,
    findings,
  );
  assertChildEvolution(
    previous.record.childTasks,
    childTasks,
  );

  const runtimeProvenance =
    input.runtimeProvenance === undefined
      ? previous.record.runtimeProvenance
      : normalizeRuntimeProvenance(
          input.runtimeProvenance,
        );
  const providerChanged = runtimeChanged(
    previous.record.runtimeProvenance,
    runtimeProvenance,
  );
  const updatedAt = canonicalIso(
    input.updatedAt,
    "updatedAt",
  );
  if (
    Date.parse(updatedAt) <
    Date.parse(previous.record.updatedAt)
  ) {
    throw new RangeError(
      "security audit checkpoint time moves backward",
    );
  }

  const evidenceRefs = stateEvidenceRefs(
    model,
    previous.record.coverageLedger,
    findings,
    childTasks,
  );
  const runState =
    checkpointRunStateCapsule(
      previous.record.runState,
      {
        updatedAt,
        reason: "CHECKPOINT",
        objective: {
          summary:
            previous.record.runState
              .objective.summary,
          status: objectiveStatus(status),
        },
        phase: providerChanged
          ? "SECURITY_AUDIT_PROVIDER_CHANGE"
          : "SECURITY_AUDIT",
        evidenceRefs,
      },
    );

  const transition:
    SecurityAuditStateTransition =
    providerChanged
      ? "PROVIDER_CHANGE"
      : "CHECKPOINT";
  const providerChangeSha256 =
    providerChanged
      ? sha256({
          before:
            previous.record
              .runtimeProvenance,
          after: runtimeProvenance,
        })
      : null;

  return sealSecurityAuditStateRecord({
    ...previous.record,
    revision:
      previous.record.revision + 1,
    status,
    findings,
    childTasks,
    runtimeProvenance,
    runState,
    updatedAt,
    continuity: Object.freeze({
      previousStateRecordSha256:
        previous.recordSha256,
      transition,
      sourceChangeSha256: null,
      providerChangeSha256,
    }),
  });
}

function exactResumeBinding(
  state: SecurityAuditStateEnvelope,
  input: ResumeSecurityAuditStateInput,
): void {
  const model = currentModel(state);
  const binding = model.record.binding;
  const expected = {
    repositoryIdentitySha256:
      sha(
        input.repositoryIdentitySha256,
        "resume.repositoryIdentitySha256",
      )!,
    sourceRevision: exactText(
      input.sourceRevision,
      "resume.sourceRevision",
      256,
    ),
    sourceTreeSha256: sha(
      input.sourceTreeSha256,
      "resume.sourceTreeSha256",
    )!,
    configurationSha256: sha(
      input.configurationSha256,
      "resume.configurationSha256",
    )!,
    ruleSetSha256: sha(
      input.ruleSetSha256,
      "resume.ruleSetSha256",
    )!,
  };
  for (
    const [key, value] of
    Object.entries(expected)
  ) {
    if (
      binding[
        key as keyof typeof expected
      ] !== value
    ) {
      throw new Error(
        `security audit exact resume identity mismatch: ${key}; use explicit source rebase for source drift`,
      );
    }
  }
}

function freshCurrentAuthorityProjection(
  currentAuthority:
    readonly CapabilityAuthorityDecision[],
): readonly CapabilityAuthorityDecision[] {
  if (!Array.isArray(currentAuthority)) {
    throw new TypeError(
      "currentAuthority must be an array",
    );
  }
  const seen = new Set<string>();
  const normalized = currentAuthority.map(
    (decision, index) => {
      if (
        decision.schemaVersion !==
        "toadaid.capability-authority-decision.v1"
      ) {
        throw new TypeError(
          `currentAuthority[${index}] has unsupported schemaVersion`,
        );
      }
      const capabilityId = exactText(
        decision.capabilityId,
        `currentAuthority[${index}].capabilityId`,
        128,
      );
      if (seen.has(capabilityId)) {
        throw new Error(
          "currentAuthority contains duplicate capability ids",
        );
      }
      seen.add(capabilityId);
      if (
        decision.decision !== "ALLOW" &&
        decision.decision !== "BLOCK"
      ) {
        throw new TypeError(
          `currentAuthority[${index}].decision is invalid`,
        );
      }
      return Object.freeze({
        ...decision,
        capabilityId,
        trace: Object.freeze([
          ...decision.trace,
        ]),
      });
    },
  );
  return Object.freeze(
    normalized.sort((a, b) =>
      a.capabilityId.localeCompare(
        b.capabilityId,
      ),
    ),
  );
}

export function resumeSecurityAuditState(
  serialized: string,
  input: ResumeSecurityAuditStateInput,
): SecurityAuditResumeOutcome {
  const previous =
    parseSecurityAuditState(serialized);
  exactResumeBinding(previous, input);

  const resumedAt = canonicalIso(
    input.resumedAt,
    "resumedAt",
  );
  const runtimeProvenance =
    input.runtimeProvenance === undefined
      ? previous.record.runtimeProvenance
      : normalizeRuntimeProvenance(
          input.runtimeProvenance,
        );
  const providerChanged = runtimeChanged(
    previous.record.runtimeProvenance,
    runtimeProvenance,
  );

  const runState =
    resumeRunStateCapsule(
      serializeRunStateCapsule(
        previous.record.runState,
      ),
      resumedAt,
    );

  const transition:
    SecurityAuditStateTransition =
    providerChanged
      ? "PROVIDER_CHANGE"
      : "RESUME";
  const providerChangeSha256 =
    providerChanged
      ? sha256({
          before:
            previous.record
              .runtimeProvenance,
          after: runtimeProvenance,
        })
      : null;

  const state =
    sealSecurityAuditStateRecord({
      ...previous.record,
      revision:
        previous.record.revision + 1,
      runtimeProvenance,
      runState,
      updatedAt: resumedAt,
      continuity: Object.freeze({
        previousStateRecordSha256:
          previous.recordSha256,
        transition,
        sourceChangeSha256: null,
        providerChangeSha256,
      }),
    });

  return Object.freeze({
    state,
    resumeAuthority:
      freshCurrentAuthorityProjection(
        input.currentAuthority,
      ),
  });
}

function findingAffected(
  finding: SecurityFindingEnvelope,
  changedPaths: readonly string[],
): boolean {
  return finding.record.sourceLocations.some(
    (location) =>
      changedPaths.some((changedPath) =>
        pathIntersects(
          location.path,
          changedPath,
        ),
      ),
  );
}

export function rebaseSecurityAuditStateSource(
  previousInput:
    SecurityAuditStateEnvelope,
  input: RebaseSecurityAuditStateInput,
): SecurityAuditResumeOutcome {
  const previous =
    validateSecurityAuditStateEnvelope(
      previousInput,
    );
  const priorModel = currentModel(previous);
  const nextModel =
    validateSecurityThreatModelEnvelope(
      input.nextThreatModel,
    );

  if (
    nextModel.record.auditId !==
      priorModel.record.auditId ||
    nextModel.record.binding.runId !==
      priorModel.record.binding.runId ||
    nextModel.record.binding
      .repositoryIdentitySha256 !==
      priorModel.record.binding
        .repositoryIdentitySha256 ||
    nextModel.record.binding
      .configurationSha256 !==
      priorModel.record.binding
        .configurationSha256 ||
    nextModel.record.binding
      .ruleSetSha256 !==
      priorModel.record.binding.ruleSetSha256 ||
    nextModel.record.binding.scopeSha256 !==
      priorModel.record.binding.scopeSha256
  ) {
    throw new Error(
      "security audit source rebase cannot cross audit/repository/config/rules/scope identity",
    );
  }
  if (
    nextModel.record.binding
      .sourceTreeSha256 ===
    priorModel.record.binding.sourceTreeSha256
  ) {
    throw new Error(
      "security audit source rebase requires a changed source tree",
    );
  }

  const changedPaths =
    normalizeChangedPaths(
      input.changedPaths,
    );
  const coverage =
    rebaseSecurityCoverageLedger(
      priorModel,
      previous.record.coverageLedger,
      nextModel,
      {
        areas: input.areas,
        changedPaths,
        rebasedAt: input.rebasedAt,
      },
    );
  const sourceChangeSha256 =
    coverage.record.continuity
      .sourceChangeSha256;
  if (sourceChangeSha256 === null) {
    throw new Error(
      "security coverage source rebase did not produce source-change evidence",
    );
  }

  const threatModels = Object.freeze([
    ...previous.record.threatModels,
    nextModel,
  ]);

  const findings = Object.freeze(
    previous.record.findings
      .map((entry) => {
        if (
          entry.sourceDisposition ===
          "INVALIDATED_SOURCE_CHANGE"
        ) {
          return entry;
        }
        const affected = findingAffected(
          entry.finding,
          changedPaths,
        );
        return Object.freeze({
          finding: entry.finding,
          sourceDisposition:
            affected
              ? "INVALIDATED_SOURCE_CHANGE" as const
              : "CARRIED_UNCHANGED" as const,
          sourceChangeSha256,
        });
      })
      .sort((a, b) =>
        a.finding.record.findingId
          .localeCompare(
            b.finding.record.findingId,
          ),
      ),
  );

  const childTasks = Object.freeze(
    previous.record.childTasks
      .map((entry) =>
        Object.freeze({
          ...entry,
          sourceDisposition:
            "HISTORICAL_SOURCE" as const,
        }),
      )
      .sort((a, b) =>
        a.task.childTaskId.localeCompare(
          b.task.childTaskId,
        ),
      ),
  );

  const runtimeProvenance =
    input.runtimeProvenance === undefined
      ? previous.record.runtimeProvenance
      : normalizeRuntimeProvenance(
          input.runtimeProvenance,
        );
  const rebasedAt = canonicalIso(
    input.rebasedAt,
    "rebasedAt",
  );
  const evidenceRefs = stateEvidenceRefs(
    nextModel,
    coverage,
    findings,
    childTasks,
  );
  const runState =
    checkpointRunStateCapsule(
      previous.record.runState,
      {
        updatedAt: rebasedAt,
        reason: "CHECKPOINT",
        objective: {
          summary:
            previous.record.runState
              .objective.summary,
          status: "ACTIVE",
        },
        phase:
          "SECURITY_AUDIT_SOURCE_REBASE",
        evidenceRefs,
      },
    );

  const state =
    sealSecurityAuditStateRecord({
      ...previous.record,
      revision:
        previous.record.revision + 1,
      status: "ACTIVE",
      threatModels,
      currentThreatModelRecordSha256:
        nextModel.recordSha256,
      coverageLedger: coverage,
      findings,
      childTasks,
      runtimeProvenance,
      runState,
      updatedAt: rebasedAt,
      continuity: Object.freeze({
        previousStateRecordSha256:
          previous.recordSha256,
        transition: "SOURCE_REBASE",
        sourceChangeSha256,
        providerChangeSha256: null,
      }),
    });

  return Object.freeze({
    state,
    resumeAuthority:
      freshCurrentAuthorityProjection(
        input.currentAuthority,
      ),
  });
}

export function serializeSecurityAuditState(
  envelope: SecurityAuditStateEnvelope,
): string {
  return JSON.stringify(
    validateSecurityAuditStateEnvelope(
      envelope,
    ),
  );
}

export function parseSecurityAuditState(
  serialized: string,
): SecurityAuditStateEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError(
      "security audit state serialization is invalid JSON",
    );
  }
  return validateSecurityAuditStateEnvelope(
    parsed as SecurityAuditStateEnvelope,
  );
}

export function assertSecurityAuditStatePredecessor(
  previousInput:
    SecurityAuditStateEnvelope,
  nextInput:
    SecurityAuditStateEnvelope,
): void {
  const previous =
    validateSecurityAuditStateEnvelope(
      previousInput,
    );
  const next =
    validateSecurityAuditStateEnvelope(
      nextInput,
    );
  if (
    next.record.auditId !==
      previous.record.auditId ||
    next.record.createdAt !==
      previous.record.createdAt ||
    next.record.revision !==
      previous.record.revision + 1 ||
    next.record.continuity
      .previousStateRecordSha256 !==
      previous.recordSha256
  ) {
    throw new Error(
      "security audit state predecessor continuity mismatch",
    );
  }
  if (
    next.record.runState.continuity
      .previousCapsuleSha256 !==
      runStateCapsuleSha256(
        previous.record.runState,
      )
  ) {
    throw new Error(
      "security audit state P4 predecessor continuity mismatch",
    );
  }
}
