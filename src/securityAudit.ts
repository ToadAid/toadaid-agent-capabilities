import { randomUUID } from "node:crypto";

import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  CreateSecurityFindingCandidateInput,
  CreateSecurityThreatModelInput,
  SecurityArchitectureComponent,
  SecurityArchitectureComponentInput,
  SecurityArchitectureSnapshot,
  SecurityArchitectureSnapshotInput,
  SecurityAttackClass,
  SecurityAttackClassPlan,
  SecurityAuditBinding,
  SecurityAuditRiskSignal,
  SecurityAuditRuntime,
  SecurityAuditScope,
  SecurityEvidenceRef,
  SecurityFindingEnvelope,
  SecurityFindingRecord,
  SecurityFindingStateEvidence,
  SecuritySourceLocation,
  SecurityThreatModelEnvelope,
  SecurityThreatModelRecord,
  SecurityTrustBoundary,
  SecurityTrustBoundaryInput,
} from "./securityAuditTypes.js";

export type * from "./securityAuditTypes.js";

const MAX_SCOPE_PATHS = 2_000;
const MAX_COMPONENTS = 2_000;
const MAX_BOUNDARIES = 4_000;
const MAX_SOURCE_PATHS = 2_000;
const MAX_EVIDENCE_REFS = 2_000;
const MAX_SOURCE_LOCATIONS = 2_000;
const MAX_TEXT_CHARS = 4_000;
const MAX_PATH_CHARS = 2_048;
const MAX_FINDING_REVISION = 1_000_000;
const REVISION_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}$/;

const RISK_SIGNALS: readonly SecurityAuditRiskSignal[] = [
  "UNTRUSTED_INPUT",
  "NETWORK_ACCESS",
  "FILESYSTEM_ACCESS",
  "PROCESS_EXECUTION",
  "SECRET_MATERIAL",
  "AUTHORITY_BOUNDARY",
  "PERSISTENT_STATE",
  "BROWSER_AUTOMATION",
  "EXTERNAL_DEPENDENCY",
  "SERIALIZATION_BOUNDARY",
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

const COMPONENT_KINDS = [
  "MODULE",
  "PROCESS",
  "DATA_STORE",
  "NETWORK_SERVICE",
  "BROWSER",
  "EXTERNAL_SYSTEM",
  "SECURITY_CONTROL",
] as const;

const ATTACK_CLASS_BY_SIGNAL:
  Readonly<Record<SecurityAuditRiskSignal, SecurityAttackClass>> = {
    UNTRUSTED_INPUT: "INPUT_INJECTION",
    NETWORK_ACCESS: "SSRF_OR_NETWORK_PIVOT",
    FILESYSTEM_ACCESS: "PATH_TRAVERSAL",
    PROCESS_EXECUTION: "COMMAND_EXECUTION_INJECTION",
    SECRET_MATERIAL: "SECRET_EXPOSURE",
    AUTHORITY_BOUNDARY: "AUTHORIZATION_BYPASS",
    PERSISTENT_STATE: "STATE_TAMPERING",
    BROWSER_AUTOMATION: "ORIGIN_OR_BROWSER_BOUNDARY",
    EXTERNAL_DEPENDENCY: "SUPPLY_CHAIN",
    SERIALIZATION_BOUNDARY: "DESERIALIZATION_OR_INTEGRITY",
  };

function exactText(
  value: string,
  label: string,
  maximum = MAX_TEXT_CHARS,
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

function safeRelativePath(value: string, label: string): string {
  const path = exactText(value, label, MAX_PATH_CHARS).replace(/\\/g, "/");
  if (
    path.startsWith("/") ||
    /^[A-Za-z]:\//.test(path)
  ) {
    throw new TypeError(`${label} must be repository-relative`);
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
    throw new TypeError(`${label} contains unsafe path segments`);
  }
  return path;
}

function uniqueSorted(
  values: readonly string[],
  label: string,
  maximum: number,
): readonly string[] {
  if (!Array.isArray(values) || values.length > maximum) {
    throw new RangeError(`${label} exceeds bounded item count`);
  }
  const normalized = values.map((value, index) =>
    safeRelativePath(value, `${label}[${index}]`),
  );
  const unique = [...new Set(normalized)].sort();
  if (unique.length !== normalized.length) {
    throw new Error(`${label} contains duplicates`);
  }
  return Object.freeze(unique);
}

function normalizeScope(scope: SecurityAuditScope): SecurityAuditScope {
  const includePaths = uniqueSorted(
    scope.includePaths,
    "scope.includePaths",
    MAX_SCOPE_PATHS,
  );
  if (includePaths.length < 1) {
    throw new Error("security audit scope requires at least one include path");
  }
  const excludePaths = uniqueSorted(
    scope.excludePaths,
    "scope.excludePaths",
    MAX_SCOPE_PATHS,
  );
  return Object.freeze({ includePaths, excludePaths });
}

function normalizeAttackClass(
  value: SecurityAttackClass,
  label: string,
): SecurityAttackClass {
  if (!ATTACK_CLASSES.includes(value)) {
    throw new TypeError(`${label} is unsupported`);
  }
  return value;
}

function normalizeComponentKind(
  value: SecurityArchitectureComponentInput["kind"],
  label: string,
): SecurityArchitectureComponentInput["kind"] {
  if (!COMPONENT_KINDS.includes(value)) {
    throw new TypeError(`${label} is unsupported`);
  }
  return value;
}

function normalizeRiskSignals(
  values: readonly SecurityAuditRiskSignal[],
  label: string,
): readonly SecurityAuditRiskSignal[] {
  if (!Array.isArray(values) || values.length > RISK_SIGNALS.length) {
    throw new RangeError(`${label} exceeds supported risk signal count`);
  }
  for (const value of values) {
    if (!RISK_SIGNALS.includes(value)) {
      throw new TypeError(`${label} contains unsupported risk signal`);
    }
  }
  const unique = [...new Set(values)].sort();
  if (unique.length !== values.length) {
    throw new Error(`${label} contains duplicate risk signals`);
  }
  return Object.freeze(unique);
}

function normalizeComponent(
  input: SecurityArchitectureComponentInput,
): SecurityArchitectureComponent {
  const sourcePaths = uniqueSorted(
    input.sourcePaths,
    `component.${input.componentId}.sourcePaths`,
    MAX_SOURCE_PATHS,
  );
  return Object.freeze({
    componentId: boundedId(input.componentId, "componentId"),
    kind: normalizeComponentKind(
      input.kind,
      `component.${input.componentId}.kind`,
    ),
    label: exactText(input.label, "component.label"),
    sourcePaths,
    riskSignals: normalizeRiskSignals(
      input.riskSignals,
      `component.${input.componentId}.riskSignals`,
    ),
  });
}

function normalizeBoundary(
  input: SecurityTrustBoundaryInput,
): SecurityTrustBoundary {
  return Object.freeze({
    boundaryId: boundedId(input.boundaryId, "boundaryId"),
    fromComponentId: boundedId(
      input.fromComponentId,
      "fromComponentId",
    ),
    toComponentId: boundedId(
      input.toComponentId,
      "toComponentId",
    ),
    channel: exactText(input.channel, "boundary.channel"),
    riskSignals: normalizeRiskSignals(
      input.riskSignals,
      `boundary.${input.boundaryId}.riskSignals`,
    ),
  });
}

function normalizeArchitecture(
  input: SecurityArchitectureSnapshotInput | SecurityArchitectureSnapshot,
): SecurityArchitectureSnapshot {
  if (
    "schemaVersion" in input &&
    input.schemaVersion !==
      "toadaid.security-architecture-snapshot.v1"
  ) {
    throw new TypeError(
      "unsupported security architecture snapshot schemaVersion",
    );
  }
  if (
    !Array.isArray(input.components) ||
    input.components.length < 1 ||
    input.components.length > MAX_COMPONENTS
  ) {
    throw new RangeError("security architecture component count is invalid");
  }
  if (
    !Array.isArray(input.trustBoundaries) ||
    input.trustBoundaries.length > MAX_BOUNDARIES
  ) {
    throw new RangeError("security architecture boundary count is invalid");
  }

  const components = input.components
    .map(normalizeComponent)
    .sort((a, b) => a.componentId.localeCompare(b.componentId));
  const componentIds = new Set<string>();
  for (const component of components) {
    if (componentIds.has(component.componentId)) {
      throw new Error("security architecture componentId is duplicated");
    }
    componentIds.add(component.componentId);
  }

  const boundaries = input.trustBoundaries
    .map(normalizeBoundary)
    .sort((a, b) => a.boundaryId.localeCompare(b.boundaryId));
  const boundaryIds = new Set<string>();
  for (const boundary of boundaries) {
    if (boundaryIds.has(boundary.boundaryId)) {
      throw new Error("security architecture boundaryId is duplicated");
    }
    boundaryIds.add(boundary.boundaryId);
    if (
      !componentIds.has(boundary.fromComponentId) ||
      !componentIds.has(boundary.toComponentId)
    ) {
      throw new Error(
        "security trust boundary references an unknown component",
      );
    }
    if (boundary.fromComponentId === boundary.toComponentId) {
      throw new Error(
        "security trust boundary must cross distinct components",
      );
    }
  }

  return Object.freeze({
    schemaVersion: "toadaid.security-architecture-snapshot.v1",
    components: Object.freeze(components),
    trustBoundaries: Object.freeze(boundaries),
  });
}

export function deriveSecurityAttackClasses(
  architectureInput:
    | SecurityArchitectureSnapshotInput
    | SecurityArchitectureSnapshot,
): readonly SecurityAttackClassPlan[] {
  const architecture = normalizeArchitecture(architectureInput);
  const accum = new Map<
    SecurityAttackClass,
    {
      signals: Set<SecurityAuditRiskSignal>;
      components: Set<string>;
      boundaries: Set<string>;
    }
  >();

  function add(
    signal: SecurityAuditRiskSignal,
    componentId?: string,
    boundaryId?: string,
  ): void {
    const attackClass = ATTACK_CLASS_BY_SIGNAL[signal];
    const existing =
      accum.get(attackClass) ??
      {
        signals: new Set<SecurityAuditRiskSignal>(),
        components: new Set<string>(),
        boundaries: new Set<string>(),
      };
    existing.signals.add(signal);
    if (componentId) existing.components.add(componentId);
    if (boundaryId) existing.boundaries.add(boundaryId);
    accum.set(attackClass, existing);
  }

  for (const component of architecture.components) {
    for (const signal of component.riskSignals) {
      add(signal, component.componentId);
    }
  }
  for (const boundary of architecture.trustBoundaries) {
    for (const signal of boundary.riskSignals) {
      add(signal, undefined, boundary.boundaryId);
    }
  }

  const plans = [...accum.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([attackClass, evidence]) =>
      Object.freeze({
        attackClass,
        derivedFromSignals: Object.freeze(
          [...evidence.signals].sort(),
        ),
        componentIds: Object.freeze(
          [...evidence.components].sort(),
        ),
        boundaryIds: Object.freeze(
          [...evidence.boundaries].sort(),
        ),
      }),
    );

  if (plans.length < 1) {
    throw new Error(
      "security architecture produced no target-specific attack classes",
    );
  }
  return Object.freeze(plans);
}

function normalizeBinding(
  binding: SecurityAuditBinding,
  scope: SecurityAuditScope,
): SecurityAuditBinding {
  const sourceRevision = exactText(
    binding.sourceRevision,
    "sourceRevision",
    256,
  );
  if (!REVISION_PATTERN.test(sourceRevision)) {
    throw new TypeError("sourceRevision is invalid");
  }
  const scopeSha256 = sha(binding.scopeSha256, "scopeSha256")!;
  const actualScopeSha256 = sha256(scope);
  if (scopeSha256 !== actualScopeSha256) {
    throw new Error("security audit scope hash mismatch");
  }
  return Object.freeze({
    repositoryIdentitySha256: sha(
      binding.repositoryIdentitySha256,
      "repositoryIdentitySha256",
    )!,
    sourceRevision,
    sourceTreeSha256: sha(
      binding.sourceTreeSha256,
      "sourceTreeSha256",
    )!,
    scopeSha256,
    configurationSha256: sha(
      binding.configurationSha256,
      "configurationSha256",
    )!,
    ruleSetSha256: sha(
      binding.ruleSetSha256,
      "ruleSetSha256",
    )!,
    runId: boundedId(binding.runId, "runId"),
  });
}

export function securityThreatModelRecordSha256(
  record: SecurityThreatModelRecord,
): string {
  return sha256(record);
}

export function validateSecurityThreatModelRecord(
  record: SecurityThreatModelRecord,
): SecurityThreatModelRecord {
  if (record.schemaVersion !== "toadaid.security-threat-model.v1") {
    throw new TypeError("unsupported security threat model schemaVersion");
  }
  const scope = normalizeScope(record.scope);
  const binding = normalizeBinding(record.binding, scope);
  const architecture = normalizeArchitecture(record.architecture);
  const architectureSha256 = sha(
    record.architectureSha256,
    "architectureSha256",
  )!;
  if (architectureSha256 !== sha256(architecture)) {
    throw new Error("security architecture snapshot hash mismatch");
  }

  const attackClasses = deriveSecurityAttackClasses(architecture);
  if (sha256(record.attackClasses) !== sha256(attackClasses)) {
    throw new Error(
      "security attack classes do not match target-derived architecture signals",
    );
  }

  return Object.freeze({
    schemaVersion: "toadaid.security-threat-model.v1",
    auditId: boundedId(record.auditId, "auditId"),
    binding,
    scope,
    architecture,
    architectureSha256,
    attackClasses,
    createdAt: canonicalIso(record.createdAt, "createdAt"),
  });
}

export function sealSecurityThreatModelRecord(
  record: SecurityThreatModelRecord,
): SecurityThreatModelEnvelope {
  const normalized = validateSecurityThreatModelRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.security-threat-model-envelope.v1",
    record: normalized,
    recordSha256: securityThreatModelRecordSha256(normalized),
  });
}

export function validateSecurityThreatModelEnvelope(
  envelope: SecurityThreatModelEnvelope,
): SecurityThreatModelEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-threat-model-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security threat model envelope schemaVersion",
    );
  }
  const record = validateSecurityThreatModelRecord(envelope.record);
  const recordSha256 = sha(envelope.recordSha256, "recordSha256")!;
  if (recordSha256 !== securityThreatModelRecordSha256(record)) {
    throw new Error("security threat model integrity mismatch");
  }
  return Object.freeze({
    schemaVersion: "toadaid.security-threat-model-envelope.v1",
    record,
    recordSha256,
  });
}

export function createSecurityThreatModel(
  input: CreateSecurityThreatModelInput,
  runtime: SecurityAuditRuntime = {},
): SecurityThreatModelEnvelope {
  const scope = normalizeScope(input.scope);
  const architecture = normalizeArchitecture(input.architecture);
  const attackClasses = deriveSecurityAttackClasses(architecture);
  const now = runtime.now ?? (() => new Date());
  const randomId = runtime.randomId ?? randomUUID;

  return sealSecurityThreatModelRecord({
    schemaVersion: "toadaid.security-threat-model.v1",
    auditId: boundedId(
      input.auditId ?? `security-audit-${randomId()}`,
      "auditId",
    ),
    binding: {
      repositoryIdentitySha256: sha(
        input.repositoryIdentitySha256,
        "repositoryIdentitySha256",
      )!,
      sourceRevision: exactText(
        input.sourceRevision,
        "sourceRevision",
        256,
      ),
      sourceTreeSha256: sha(
        input.sourceTreeSha256,
        "sourceTreeSha256",
      )!,
      scopeSha256: sha256(scope),
      configurationSha256: sha(
        input.configurationSha256,
        "configurationSha256",
      )!,
      ruleSetSha256: sha(input.ruleSetSha256, "ruleSetSha256")!,
      runId: boundedId(input.runId, "runId"),
    },
    scope,
    architecture,
    architectureSha256: sha256(architecture),
    attackClasses,
    createdAt: canonicalIso(
      input.createdAt ?? now().toISOString(),
      "createdAt",
    ),
  });
}

function normalizeEvidenceRefs(
  refs: readonly SecurityEvidenceRef[],
  label: string,
  requireNonEmpty = true,
): readonly SecurityEvidenceRef[] {
  if (
    !Array.isArray(refs) ||
    refs.length > MAX_EVIDENCE_REFS ||
    (requireNonEmpty && refs.length < 1)
  ) {
    throw new RangeError(`${label} count is invalid`);
  }
  const ids = new Set<string>();
  const normalized = refs.map((ref, index) => {
    const id = boundedId(ref.id, `${label}[${index}].id`);
    if (ids.has(id)) {
      throw new Error(`${label} contains duplicate ids`);
    }
    ids.add(id);
    return Object.freeze({
      id,
      sha256: sha(
        ref.sha256,
        `${label}[${index}].sha256`,
      )!,
    });
  });
  return Object.freeze(normalized.sort((a, b) => a.id.localeCompare(b.id)));
}

function normalizeSourceLocations(
  locations: readonly SecuritySourceLocation[],
): readonly SecuritySourceLocation[] {
  if (
    !Array.isArray(locations) ||
    locations.length < 1 ||
    locations.length > MAX_SOURCE_LOCATIONS
  ) {
    throw new RangeError("security finding source location count is invalid");
  }
  const normalized = locations.map((location, index) => {
    if (
      !Number.isSafeInteger(location.startLine) ||
      location.startLine < 1 ||
      !Number.isSafeInteger(location.endLine) ||
      location.endLine < location.startLine
    ) {
      throw new RangeError(
        `sourceLocations[${index}] line range is invalid`,
      );
    }
    return Object.freeze({
      path: safeRelativePath(
        location.path,
        `sourceLocations[${index}].path`,
      ),
      startLine: location.startLine,
      endLine: location.endLine,
    });
  });
  return Object.freeze(
    normalized.sort(
      (a, b) =>
        a.path.localeCompare(b.path) ||
        a.startLine - b.startLine ||
        a.endLine - b.endLine,
    ),
  );
}

function normalizeFindingStateEvidence(
  evidence: SecurityFindingStateEvidence,
): SecurityFindingStateEvidence {
  switch (evidence.state) {
    case "CANDIDATE":
      return Object.freeze({
        state: "CANDIDATE",
        rationale: exactText(
          evidence.rationale,
          "stateEvidence.rationale",
        ),
      });
    case "NEEDS_VALIDATION":
      return Object.freeze({
        state: "NEEDS_VALIDATION",
        reason: exactText(
          evidence.reason,
          "stateEvidence.reason",
        ),
      });
    case "CONFIRMED":
      return Object.freeze({
        state: "CONFIRMED",
        validatorIdentitySha256: sha(
          evidence.validatorIdentitySha256,
          "stateEvidence.validatorIdentitySha256",
        )!,
        proofEvidenceRefs: normalizeEvidenceRefs(
          evidence.proofEvidenceRefs,
          "stateEvidence.proofEvidenceRefs",
        ),
      });
    case "REJECTED":
      return Object.freeze({
        state: "REJECTED",
        reason: exactText(
          evidence.reason,
          "stateEvidence.reason",
        ),
        disproofEvidenceRefs: normalizeEvidenceRefs(
          evidence.disproofEvidenceRefs,
          "stateEvidence.disproofEvidenceRefs",
        ),
      });
    default:
      throw new TypeError("unsupported security finding state evidence");
  }
}

export function securityFindingRecordSha256(
  record: SecurityFindingRecord,
): string {
  return sha256(record);
}

export function validateSecurityFindingRecord(
  record: SecurityFindingRecord,
): SecurityFindingRecord {
  if (record.schemaVersion !== "toadaid.security-finding.v1") {
    throw new TypeError("unsupported security finding schemaVersion");
  }
  if (
    !Number.isSafeInteger(record.revision) ||
    record.revision < 0 ||
    record.revision > MAX_FINDING_REVISION
  ) {
    throw new RangeError("security finding revision is invalid");
  }

  const previousRecordSha256 =
    record.continuity.previousRecordSha256 === null
      ? null
      : sha(
          record.continuity.previousRecordSha256,
          "continuity.previousRecordSha256",
        )!;

  if (record.revision === 0) {
    if (
      record.state !== "CANDIDATE" ||
      previousRecordSha256 !== null
    ) {
      throw new Error(
        "initial security finding must be a predecessor-free CANDIDATE",
      );
    }
  } else if (previousRecordSha256 === null) {
    throw new Error(
      "non-initial security finding requires predecessor continuity",
    );
  }

  const attackClass = normalizeAttackClass(
    record.attackClass,
    "attackClass",
  );
  const stateEvidence = normalizeFindingStateEvidence(
    record.stateEvidence,
  );
  if (stateEvidence.state !== record.state) {
    throw new Error(
      "security finding state does not match state evidence",
    );
  }

  const createdAt = canonicalIso(record.createdAt, "createdAt");
  const updatedAt = canonicalIso(record.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RangeError(
      "security finding updatedAt is earlier than createdAt",
    );
  }

  return Object.freeze({
    schemaVersion: "toadaid.security-finding.v1",
    findingId: boundedId(record.findingId, "findingId"),
    revision: record.revision,
    threatModelRecordSha256: sha(
      record.threatModelRecordSha256,
      "threatModelRecordSha256",
    )!,
    attackClass,
    title: exactText(record.title, "title"),
    evidenceRefs: normalizeEvidenceRefs(
      record.evidenceRefs,
      "evidenceRefs",
    ),
    sourceLocations: normalizeSourceLocations(
      record.sourceLocations,
    ),
    state: record.state,
    stateEvidence,
    createdAt,
    updatedAt,
    continuity: Object.freeze({ previousRecordSha256 }),
  });
}

export function sealSecurityFindingRecord(
  record: SecurityFindingRecord,
): SecurityFindingEnvelope {
  const normalized = validateSecurityFindingRecord(record);
  return Object.freeze({
    schemaVersion: "toadaid.security-finding-envelope.v1",
    record: normalized,
    recordSha256: securityFindingRecordSha256(normalized),
  });
}

export function validateSecurityFindingEnvelope(
  envelope: SecurityFindingEnvelope,
): SecurityFindingEnvelope {
  if (
    envelope.schemaVersion !== "toadaid.security-finding-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security finding envelope schemaVersion",
    );
  }
  const record = validateSecurityFindingRecord(envelope.record);
  const recordSha256 = sha(envelope.recordSha256, "recordSha256")!;
  if (recordSha256 !== securityFindingRecordSha256(record)) {
    throw new Error("security finding integrity mismatch");
  }
  return Object.freeze({
    schemaVersion: "toadaid.security-finding-envelope.v1",
    record,
    recordSha256,
  });
}

export function validateSecurityFindingAgainstThreatModel(
  findingInput: SecurityFindingEnvelope,
  modelInput: SecurityThreatModelEnvelope,
): SecurityFindingEnvelope {
  const finding = validateSecurityFindingEnvelope(findingInput);
  const model = validateSecurityThreatModelEnvelope(modelInput);
  if (
    finding.record.threatModelRecordSha256 !== model.recordSha256
  ) {
    throw new Error(
      "security finding is bound to a different threat model",
    );
  }
  if (
    !model.record.attackClasses.some(
      (entry) =>
        entry.attackClass === finding.record.attackClass,
    )
  ) {
    throw new Error(
      "security finding attack class is not derived by this threat model",
    );
  }
  return finding;
}

export function createSecurityFindingCandidate(
  modelInput: SecurityThreatModelEnvelope,
  input: CreateSecurityFindingCandidateInput,
  runtime: SecurityAuditRuntime = {},
): SecurityFindingEnvelope {
  const model = validateSecurityThreatModelEnvelope(modelInput);
  if (
    !model.record.attackClasses.some(
      (entry) => entry.attackClass === input.attackClass,
    )
  ) {
    throw new Error(
      "candidate attack class is not derived by this threat model",
    );
  }
  const now = runtime.now ?? (() => new Date());
  const randomId = runtime.randomId ?? randomUUID;
  const createdAt = canonicalIso(
    input.createdAt ?? now().toISOString(),
    "createdAt",
  );

  return sealSecurityFindingRecord({
    schemaVersion: "toadaid.security-finding.v1",
    findingId: boundedId(
      input.findingId ?? `security-finding-${randomId()}`,
      "findingId",
    ),
    revision: 0,
    threatModelRecordSha256: model.recordSha256,
    attackClass: input.attackClass,
    title: exactText(input.title, "title"),
    evidenceRefs: input.evidenceRefs,
    sourceLocations: input.sourceLocations,
    state: "CANDIDATE",
    stateEvidence: {
      state: "CANDIDATE",
      rationale: exactText(input.rationale, "rationale"),
    },
    createdAt,
    updatedAt: createdAt,
    continuity: Object.freeze({
      previousRecordSha256: null,
    }),
  });
}

export function serializeSecurityThreatModel(
  envelope: SecurityThreatModelEnvelope,
): string {
  return JSON.stringify(validateSecurityThreatModelEnvelope(envelope));
}

export function parseSecurityThreatModel(
  serialized: string,
): SecurityThreatModelEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("security threat model serialization is invalid JSON");
  }
  return validateSecurityThreatModelEnvelope(
    parsed as SecurityThreatModelEnvelope,
  );
}

export function serializeSecurityFinding(
  envelope: SecurityFindingEnvelope,
): string {
  return JSON.stringify(validateSecurityFindingEnvelope(envelope));
}

export function parseSecurityFinding(
  serialized: string,
): SecurityFindingEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError("security finding serialization is invalid JSON");
  }
  return validateSecurityFindingEnvelope(
    parsed as SecurityFindingEnvelope,
  );
}
