import type {
  CompileGovernedRecipeOptions,
  GovernedRecipeDefinition,
  GovernedRecipePlan,
  RecipeParameterDefinition,
} from "./recipeTypes.js";
import {
  compileGovernedRecipe,
  governedRecipeSha256,
  normalizeGovernedRecipeDefinition,
  validateGovernedRecipePlanIntegrity,
} from "./recipeCompiler.js";
import {
  boundedId,
  canonicalIso,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  SecurityEvidenceRef,
} from "./securityAuditTypes.js";
import {
  validateCanonicalSecurityFindings,
} from "./securityReport.js";
import type {
  SecurityCanonicalFinding,
} from "./securityReportTypes.js";
import {
  workspaceSnapshotSha256,
} from "./workspaceTimeTravel.js";
import type {
  WorkspaceDiffReceipt,
  WorkspaceSnapshot,
} from "./workspaceHistoryTypes.js";
import type {
  BindSecurityRepairPreMutationSnapshotInput,
  CreateSecurityRepairProposalInput,
  CreateSecurityRepairVerificationPackageInput,
  SecurityRepairMergeSeparationReceipt,
  SecurityRepairPreMutationBindingEnvelope,
  SecurityRepairPreMutationBindingRecord,
  SecurityRepairProposalEnvelope,
  SecurityRepairProposalRecord,
  SecurityRepairVerificationEnvelope,
  SecurityRepairVerificationRecord,
  SecuritySpecialistCompiledPlan,
  SecuritySpecialistMode,
} from "./securitySpecialistTypes.js";

export type * from "./securitySpecialistTypes.js";

export const SECURITY_SPECIALIST_MODES =
  Object.freeze([
    "REPOSITORY_PREFLIGHT",
    "TARGETED_AUDIT",
    "GAP_FILL_AUDIT",
    "VALIDATION_ONLY",
    "REVERIFICATION",
  ] as const);

export const SECURITY_SPECIALIST_INSPECTION_CAPABILITIES =
  Object.freeze([
    "host:file-read",
    "host:session",
    "security:sandbox-exec",
  ] as const);

export const SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES =
  Object.freeze([
    "host:command-exec",
    "host:file-write",
    "review:fix",
    "workspace:diff",
    "workspace:restore",
    "workspace:snapshot",
  ] as const);

const REQUIRED_INSPECTION_CAPABILITIES =
  Object.freeze([
    "host:file-read",
    "host:session",
  ] as const);

const REQUIRED_REPAIR_CAPABILITIES =
  Object.freeze([
    "review:fix",
    "workspace:snapshot",
    "workspace:diff",
  ] as const);

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const MAX_TEXT = 4_000;
const MAX_EVIDENCE_REFS = 2_000;
const MAX_DIFF_ENTRIES = 100_000;

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
    2_048,
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

function sha256TextParameter(
  required = true,
): RecipeParameterDefinition {
  return Object.freeze({
    schema: Object.freeze({
      type: "STRING" as const,
      minLength: 64,
      maxLength: 64,
    }),
    required,
  });
}

function boundedTextParameter(
  maxLength: number,
): RecipeParameterDefinition {
  return Object.freeze({
    schema: Object.freeze({
      type: "STRING" as const,
      minLength: 1,
      maxLength,
    }),
    required: true,
  });
}

function commonParameters():
  Readonly<Record<string, RecipeParameterDefinition>> {
  return Object.freeze({
    repositoryIdentitySha256:
      sha256TextParameter(),
    sourceRevision:
      boundedTextParameter(256),
    sourceTreeSha256:
      sha256TextParameter(),
  });
}

function responseSchema() {
  return Object.freeze({
    type: "OBJECT" as const,
    properties: Object.freeze({
      status: Object.freeze({
        type: "STRING" as const,
        minLength: 7,
        maxLength: 8,
        enum: Object.freeze([
          "BLOCKED",
          "COMPLETE",
        ]),
      }),
      artifactSha256: Object.freeze({
        type: "STRING" as const,
        minLength: 64,
        maxLength: 64,
      }),
    }),
    required: Object.freeze(["status"]),
  });
}

function recipeDefinition(
  mode: SecuritySpecialistMode,
): GovernedRecipeDefinition {
  const common = commonParameters();
  const forbidden =
    SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES;

  switch (mode) {
    case "REPOSITORY_PREFLIGHT":
      return {
        schemaVersion:
          "toadaid.governed-recipe.v1",
        recipeId:
          "security-repository-preflight",
        version: "1",
        description:
          "Bound repository/source preflight for the Agent0 security specialist. Read-only inspection only.",
        parameters: common,
        responseSchema: responseSchema(),
        maxTurns: 8,
        maxRetries: 0,
        capabilities: {
          required:
            REQUIRED_INSPECTION_CAPABILITIES,
          forbidden,
        },
        steps: [
          {
            id: "bind-session",
            summary:
              "Bind the exact current host session for repository inspection.",
            capabilityId: "host:session",
            onUnavailable: "FAIL",
          },
          {
            id: "inspect-repository",
            summary:
              "Read bounded repository evidence needed for security preflight.",
            capabilityId: "host:file-read",
            onUnavailable: "FAIL",
          },
        ],
      };

    case "TARGETED_AUDIT":
      return {
        schemaVersion:
          "toadaid.governed-recipe.v1",
        recipeId:
          "security-targeted-audit",
        version: "1",
        description:
          "Bound targeted security audit over one declared repository-relative target scope.",
        parameters: Object.freeze({
          ...common,
          targetScope:
            boundedTextParameter(2_048),
        }),
        responseSchema: responseSchema(),
        maxTurns: 24,
        maxRetries: 0,
        capabilities: {
          required:
            REQUIRED_INSPECTION_CAPABILITIES,
          forbidden,
        },
        steps: [
          {
            id: "bind-session",
            summary:
              "Bind the exact current host session for targeted audit.",
            capabilityId: "host:session",
            onUnavailable: "FAIL",
          },
          {
            id: "inspect-target",
            summary:
              "Inspect only the declared target scope using read-only source evidence.",
            capabilityId: "host:file-read",
            onUnavailable: "FAIL",
          },
        ],
      };

    case "GAP_FILL_AUDIT":
      return {
        schemaVersion:
          "toadaid.governed-recipe.v1",
        recipeId:
          "security-gap-fill-audit",
        version: "1",
        description:
          "Bound SEC2 gap-fill audit driven by one exact coverage-ledger revision.",
        parameters: Object.freeze({
          ...common,
          coverageLedgerRecordSha256:
            sha256TextParameter(),
        }),
        responseSchema: responseSchema(),
        maxTurns: 24,
        maxRetries: 0,
        capabilities: {
          required:
            REQUIRED_INSPECTION_CAPABILITIES,
          forbidden,
        },
        steps: [
          {
            id: "bind-session",
            summary:
              "Bind the exact current host session for coverage gap fill.",
            capabilityId: "host:session",
            onUnavailable: "FAIL",
          },
          {
            id: "inspect-gap",
            summary:
              "Inspect only the deterministic SEC2 coverage gap with read-only source authority.",
            capabilityId: "host:file-read",
            onUnavailable: "FAIL",
          },
        ],
      };

    case "VALIDATION_ONLY":
      return {
        schemaVersion:
          "toadaid.governed-recipe.v1",
        recipeId:
          "security-validation-only",
        version: "1",
        description:
          "Fresh SEC4 validation-only pass for one exact finding. Sandbox execution is optional and separately governed.",
        parameters: Object.freeze({
          ...common,
          findingId:
            boundedTextParameter(256),
          findingRecordSha256:
            sha256TextParameter(),
        }),
        responseSchema: responseSchema(),
        maxTurns: 16,
        maxRetries: 0,
        capabilities: {
          required:
            REQUIRED_INSPECTION_CAPABILITIES,
          optional:
            Object.freeze([
              "security:sandbox-exec",
            ]),
          forbidden,
        },
        steps: [
          {
            id: "bind-session",
            summary:
              "Bind the exact current host session for validation.",
            capabilityId: "host:session",
            onUnavailable: "FAIL",
          },
          {
            id: "validate-source",
            summary:
              "Re-read exact candidate source locations before validation.",
            capabilityId: "host:file-read",
            onUnavailable: "FAIL",
          },
          {
            id: "optional-sandbox-proof",
            summary:
              "Attempt a bounded SEC5 proof step only when dedicated sandbox authority is currently available.",
            capabilityId:
              "security:sandbox-exec",
            onUnavailable: "SKIP",
          },
        ],
      };

    case "REVERIFICATION":
      return {
        schemaVersion:
          "toadaid.governed-recipe.v1",
        recipeId:
          "security-reverification",
        version: "1",
        description:
          "Independent SEC4 re-verification for one exact confirmed finding. No repair or merge authority.",
        parameters: Object.freeze({
          ...common,
          findingId:
            boundedTextParameter(256),
          findingRecordSha256:
            sha256TextParameter(),
          priorValidatorIdentitySha256:
            sha256TextParameter(),
        }),
        responseSchema: responseSchema(),
        maxTurns: 16,
        maxRetries: 0,
        capabilities: {
          required:
            REQUIRED_INSPECTION_CAPABILITIES,
          optional:
            Object.freeze([
              "security:sandbox-exec",
            ]),
          forbidden,
        },
        steps: [
          {
            id: "bind-session",
            summary:
              "Bind the exact current host session for independent re-verification.",
            capabilityId: "host:session",
            onUnavailable: "FAIL",
          },
          {
            id: "reverify-source",
            summary:
              "Re-read exact confirmed-finding source and evidence bindings.",
            capabilityId: "host:file-read",
            onUnavailable: "FAIL",
          },
          {
            id: "optional-sandbox-reproof",
            summary:
              "Run an optional bounded SEC5 proof step only with separate current sandbox authority.",
            capabilityId:
              "security:sandbox-exec",
            onUnavailable: "SKIP",
          },
        ],
      };
  }
}

function assertMode(
  mode: string,
): asserts mode is SecuritySpecialistMode {
  if (
    !SECURITY_SPECIALIST_MODES.includes(
      mode as SecuritySpecialistMode,
    )
  ) {
    throw new TypeError(
      "unsupported security specialist mode",
    );
  }
}

export function securitySpecialistRecipe(
  modeInput: SecuritySpecialistMode,
): GovernedRecipeDefinition {
  assertMode(modeInput);
  return normalizeGovernedRecipeDefinition(
    recipeDefinition(modeInput),
  );
}

export function securitySpecialistRecipeSha256(
  mode: SecuritySpecialistMode,
): string {
  return governedRecipeSha256(
    securitySpecialistRecipe(mode),
  );
}

export function assertSecuritySpecialistPlanInspectionOnly(
  planInput: GovernedRecipePlan,
): GovernedRecipePlan {
  const plan =
    validateGovernedRecipePlanIntegrity(
      planInput,
    );
  const allowed = new Set<string>(
    SECURITY_SPECIALIST_INSPECTION_CAPABILITIES,
  );
  for (
    const capabilityId of
    plan.effectiveCapabilities
  ) {
    if (!allowed.has(capabilityId)) {
      throw new Error(
        `security specialist plan contains non-inspection capability: ${capabilityId}`,
      );
    }
  }
  for (
    const forbidden of
    SECURITY_SPECIALIST_FORBIDDEN_MUTATION_CAPABILITIES
  ) {
    if (
      plan.effectiveCapabilities.includes(
        forbidden,
      )
    ) {
      throw new Error(
        `security specialist plan illegally includes mutation authority: ${forbidden}`,
      );
    }
  }
  return plan;
}

export function compileSecuritySpecialistRecipe(
  mode: SecuritySpecialistMode,
  rawInputs: Readonly<Record<string, unknown>>,
  options: CompileGovernedRecipeOptions,
): SecuritySpecialistCompiledPlan {
  const recipe =
    securitySpecialistRecipe(mode);
  const recipePlan =
    assertSecuritySpecialistPlanInspectionOnly(
      compileGovernedRecipe(
        recipe,
        rawInputs,
        options,
      ),
    );

  return Object.freeze({
    schemaVersion:
      "toadaid.security-specialist-plan.v1",
    mode,
    recipe,
    recipePlan,
    inspectionOnly: true,
    repairAuthorityIncluded: false,
    fileMutationAuthorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

function normalizeEvidenceRefs(
  refs: readonly SecurityEvidenceRef[],
  label: string,
  requireNonEmpty: boolean,
): readonly SecurityEvidenceRef[] {
  if (
    !Array.isArray(refs) ||
    refs.length > MAX_EVIDENCE_REFS ||
    (requireNonEmpty && refs.length < 1)
  ) {
    throw new RangeError(
      `${label} count is invalid`,
    );
  }
  const seen = new Set<string>();
  const normalized = refs.map(
    (ref, index) => {
      const id = boundedId(
        ref.id,
        `${label}[${index}].id`,
      );
      if (seen.has(id)) {
        throw new Error(
          `${label} contains duplicate evidence id`,
        );
      }
      seen.add(id);
      return Object.freeze({
        id,
        sha256: sha(
          ref.sha256,
          `${label}[${index}].sha256`,
        )!,
      });
    },
  );
  return Object.freeze(
    normalized.sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
  );
}

function proposalRecordSha256(
  record: SecurityRepairProposalRecord,
): string {
  return sha256(record);
}

function normalizeProposalRecord(
  record: SecurityRepairProposalRecord,
): SecurityRepairProposalRecord {
  if (
    record.schemaVersion !==
    "toadaid.security-repair-proposal.v1"
  ) {
    throw new TypeError(
      "unsupported security repair proposal schemaVersion",
    );
  }
  const finderIdentitySha256 = sha(
    record.finderIdentitySha256,
    "finderIdentitySha256",
  )!;
  const validatorIdentitySha256 = sha(
    record.validatorIdentitySha256,
    "validatorIdentitySha256",
  )!;
  if (
    finderIdentitySha256 ===
    validatorIdentitySha256
  ) {
    throw new Error(
      "security repair proposal requires finder and validator identity separation",
    );
  }
  if (
    JSON.stringify(
      record.requiredIndependentCapabilities,
    ) !==
    JSON.stringify(
      REQUIRED_REPAIR_CAPABILITIES,
    )
  ) {
    throw new Error(
      "security repair proposal independent capability set mismatch",
    );
  }
  if (
    record.authorityIncluded !== false ||
    record.fileMutationAuthorityIncluded !==
      false ||
    record.gitAuthorityIncluded !== false ||
    record.prAuthorityIncluded !== false ||
    record.mergeAuthorityIncluded !== false
  ) {
    throw new Error(
      "security repair proposal cannot carry authority",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-proposal.v1",
    proposalId: boundedId(
      record.proposalId,
      "proposalId",
    ),
    canonicalFindingsRecordSha256: sha(
      record.canonicalFindingsRecordSha256,
      "canonicalFindingsRecordSha256",
    )!,
    auditId: boundedId(
      record.auditId,
      "auditId",
    ),
    findingId: boundedId(
      record.findingId,
      "findingId",
    ),
    findingRecordSha256: sha(
      record.findingRecordSha256,
      "findingRecordSha256",
    )!,
    affectedRevision: exactText(
      record.affectedRevision,
      "affectedRevision",
      256,
    ),
    affectedSourceTreeSha256: sha(
      record.affectedSourceTreeSha256,
      "affectedSourceTreeSha256",
    )!,
    proofEvidenceRefs:
      normalizeEvidenceRefs(
        record.proofEvidenceRefs,
        "proofEvidenceRefs",
        true,
      ),
    finderIdentitySha256,
    validatorIdentitySha256,
    createdAt: canonicalIso(
      record.createdAt,
      "createdAt",
    ),
    requiredIndependentCapabilities:
      REQUIRED_REPAIR_CAPABILITIES,
    authorityIncluded: false,
    fileMutationAuthorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

export function sealSecurityRepairProposalRecord(
  record: SecurityRepairProposalRecord,
): SecurityRepairProposalEnvelope {
  const normalized =
    normalizeProposalRecord(record);
  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-proposal-envelope.v1",
    record: normalized,
    recordSha256:
      proposalRecordSha256(normalized),
  });
}

export function validateSecurityRepairProposal(
  envelope: SecurityRepairProposalEnvelope,
): SecurityRepairProposalEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-repair-proposal-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security repair proposal envelope schemaVersion",
    );
  }
  const record =
    normalizeProposalRecord(envelope.record);
  const recordSha256 = sha(
    envelope.recordSha256,
    "recordSha256",
  )!;
  if (
    recordSha256 !==
    proposalRecordSha256(record)
  ) {
    throw new Error(
      "security repair proposal integrity mismatch",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-proposal-envelope.v1",
    record,
    recordSha256,
  });
}

function confirmedCurrentFinding(
  canonicalInput:
    Parameters<typeof validateCanonicalSecurityFindings>[0],
  findingIdInput: string,
): {
  readonly canonicalRecordSha256: string;
  readonly auditId: string;
  readonly finding: SecurityCanonicalFinding;
} {
  const canonical =
    validateCanonicalSecurityFindings(
      canonicalInput,
    );
  const findingId = boundedId(
    findingIdInput,
    "findingId",
  );
  const finding =
    canonical.record.findings.find(
      (entry) =>
        entry.findingId === findingId,
    );
  if (!finding) {
    throw new Error(
      "security repair proposal references unknown canonical finding",
    );
  }
  if (
    finding.proofStatus !== "CONFIRMED"
  ) {
    throw new Error(
      "security repair proposal requires a CONFIRMED finding",
    );
  }
  if (
    finding.sourceDisposition ===
    "INVALIDATED_SOURCE_CHANGE"
  ) {
    throw new Error(
      "security repair proposal refuses source-invalidated finding",
    );
  }
  if (
    finding.validatorProvenance.level !==
      "IDENTITY_ONLY" ||
    finding.validatorProvenance
      .validatorIdentitySha256 === null
  ) {
    throw new Error(
      "confirmed repair proposal requires validator identity provenance",
    );
  }
  if (
    finding.proofEvidenceRefs.length < 1
  ) {
    throw new Error(
      "confirmed repair proposal requires proof evidence",
    );
  }

  return Object.freeze({
    canonicalRecordSha256:
      canonical.recordSha256,
    auditId: canonical.record.auditId,
    finding,
  });
}

export function validateSecurityRepairProposalAgainstCanonical(
  canonicalFindings:
    Parameters<typeof validateCanonicalSecurityFindings>[0],
  proposalInput: SecurityRepairProposalEnvelope,
): SecurityRepairProposalEnvelope {
  const proposal =
    validateSecurityRepairProposal(
      proposalInput,
    );
  const source = confirmedCurrentFinding(
    canonicalFindings,
    proposal.record.findingId,
  );
  const finding = source.finding;

  if (
    proposal.record
      .canonicalFindingsRecordSha256 !==
      source.canonicalRecordSha256 ||
    proposal.record.auditId !==
      source.auditId ||
    proposal.record.findingRecordSha256 !==
      finding.findingRecordSha256 ||
    proposal.record.affectedRevision !==
      finding.affectedRevision ||
    proposal.record.affectedSourceTreeSha256 !==
      finding.affectedSourceTreeSha256 ||
    proposal.record.validatorIdentitySha256 !==
      finding.validatorProvenance
        .validatorIdentitySha256 ||
    JSON.stringify(
      proposal.record.proofEvidenceRefs,
    ) !==
      JSON.stringify(
        finding.proofEvidenceRefs,
      )
  ) {
    throw new Error(
      "security repair proposal does not match authoritative canonical finding truth",
    );
  }

  return proposal;
}

export function createSecurityRepairProposal(
  canonicalFindings:
    Parameters<typeof validateCanonicalSecurityFindings>[0],
  input: CreateSecurityRepairProposalInput,
): SecurityRepairProposalEnvelope {
  const source = confirmedCurrentFinding(
    canonicalFindings,
    input.findingId,
  );
  const finderIdentitySha256 = sha(
    input.finderIdentitySha256,
    "finderIdentitySha256",
  )!;
  const validatorIdentitySha256 =
    source.finding.validatorProvenance
      .validatorIdentitySha256!;

  return sealSecurityRepairProposalRecord({
    schemaVersion:
      "toadaid.security-repair-proposal.v1",
    proposalId: boundedId(
      input.proposalId,
      "proposalId",
    ),
    canonicalFindingsRecordSha256:
      source.canonicalRecordSha256,
    auditId: source.auditId,
    findingId:
      source.finding.findingId,
    findingRecordSha256:
      source.finding.findingRecordSha256,
    affectedRevision:
      source.finding.affectedRevision,
    affectedSourceTreeSha256:
      source.finding.affectedSourceTreeSha256,
    proofEvidenceRefs:
      source.finding.proofEvidenceRefs,
    finderIdentitySha256,
    validatorIdentitySha256,
    createdAt: canonicalIso(
      input.createdAt,
      "createdAt",
    ),
    requiredIndependentCapabilities:
      REQUIRED_REPAIR_CAPABILITIES,
    authorityIncluded: false,
    fileMutationAuthorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

function normalizeWorkspaceSnapshotEvidence(
  snapshot: WorkspaceSnapshot,
  label: string,
): WorkspaceSnapshot {
  if (
    snapshot.schemaVersion !==
    "toadaid.workspace-snapshot.v1"
  ) {
    throw new TypeError(
      `${label} schemaVersion is invalid`,
    );
  }
  boundedId(
    snapshot.snapshotId,
    `${label}.snapshotId`,
  );
  boundedId(
    snapshot.workspaceId,
    `${label}.workspaceId`,
  );
  canonicalIso(
    snapshot.createdAt,
    `${label}.createdAt`,
  );
  if (
    !Array.isArray(snapshot.files) ||
    !Number.isSafeInteger(
      snapshot.totalBytes,
    ) ||
    snapshot.totalBytes < 0
  ) {
    throw new TypeError(
      `${label} shape is invalid`,
    );
  }
  return snapshot;
}

function preMutationRecordSha256(
  record:
    SecurityRepairPreMutationBindingRecord,
): string {
  return sha256(record);
}

function normalizePreMutationRecord(
  record:
    SecurityRepairPreMutationBindingRecord,
): SecurityRepairPreMutationBindingRecord {
  if (
    record.schemaVersion !==
    "toadaid.security-repair-pre-mutation-binding.v1"
  ) {
    throw new TypeError(
      "unsupported security repair pre-mutation binding schemaVersion",
    );
  }
  if (record.authorityIncluded !== false) {
    throw new Error(
      "security repair pre-mutation binding cannot carry authority",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-pre-mutation-binding.v1",
    proposalRecordSha256: sha(
      record.proposalRecordSha256,
      "proposalRecordSha256",
    )!,
    findingRecordSha256: sha(
      record.findingRecordSha256,
      "findingRecordSha256",
    )!,
    workspaceId: boundedId(
      record.workspaceId,
      "workspaceId",
    ),
    beforeSnapshotId: boundedId(
      record.beforeSnapshotId,
      "beforeSnapshotId",
    ),
    beforeSnapshotSha256: sha(
      record.beforeSnapshotSha256,
      "beforeSnapshotSha256",
    )!,
    snapshotCreatedAt: canonicalIso(
      record.snapshotCreatedAt,
      "snapshotCreatedAt",
    ),
    boundAt: canonicalIso(
      record.boundAt,
      "boundAt",
    ),
    authorityIncluded: false,
  });
}

export function validateSecurityRepairPreMutationBinding(
  envelope:
    SecurityRepairPreMutationBindingEnvelope,
): SecurityRepairPreMutationBindingEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-repair-pre-mutation-binding-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security repair pre-mutation binding envelope schemaVersion",
    );
  }
  const record =
    normalizePreMutationRecord(
      envelope.record,
    );
  const recordSha256 = sha(
    envelope.recordSha256,
    "recordSha256",
  )!;
  if (
    recordSha256 !==
    preMutationRecordSha256(record)
  ) {
    throw new Error(
      "security repair pre-mutation binding integrity mismatch",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-pre-mutation-binding-envelope.v1",
    record,
    recordSha256,
  });
}

export function bindSecurityRepairPreMutationSnapshot(
  input:
    BindSecurityRepairPreMutationSnapshotInput,
): SecurityRepairPreMutationBindingEnvelope {
  const proposal =
    validateSecurityRepairProposalAgainstCanonical(
      input.canonicalFindings,
      input.proposal,
    );
  const snapshot =
    normalizeWorkspaceSnapshotEvidence(
      input.snapshot,
      "snapshot",
    );
  const boundAt = canonicalIso(
    input.boundAt,
    "boundAt",
  );
  if (
    Date.parse(snapshot.createdAt) <
    Date.parse(proposal.record.createdAt)
  ) {
    throw new RangeError(
      "security repair before snapshot predates repair proposal",
    );
  }
  if (
    Date.parse(boundAt) <
    Date.parse(snapshot.createdAt)
  ) {
    throw new RangeError(
      "security repair pre-mutation binding predates snapshot",
    );
  }

  const record =
    normalizePreMutationRecord({
      schemaVersion:
        "toadaid.security-repair-pre-mutation-binding.v1",
      proposalRecordSha256:
        proposal.recordSha256,
      findingRecordSha256:
        proposal.record.findingRecordSha256,
      workspaceId:
        snapshot.workspaceId,
      beforeSnapshotId:
        snapshot.snapshotId,
      beforeSnapshotSha256:
        workspaceSnapshotSha256(snapshot),
      snapshotCreatedAt:
        snapshot.createdAt,
      boundAt,
      authorityIncluded: false,
    });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-pre-mutation-binding-envelope.v1",
    record,
    recordSha256:
      preMutationRecordSha256(record),
  });
}

function normalizeWorkspaceDiff(
  diff: WorkspaceDiffReceipt,
): WorkspaceDiffReceipt {
  if (
    diff.schemaVersion !==
    "toadaid.workspace-diff.v1"
  ) {
    throw new TypeError(
      "security repair diff schemaVersion is invalid",
    );
  }
  boundedId(
    diff.fromSnapshotId,
    "diff.fromSnapshotId",
  );
  boundedId(
    diff.toSnapshotId,
    "diff.toSnapshotId",
  );
  if (
    !Array.isArray(diff.entries) ||
    diff.entries.length < 1 ||
    diff.entries.length > MAX_DIFF_ENTRIES
  ) {
    throw new RangeError(
      "security repair diff must contain bounded changed entries",
    );
  }
  const paths = new Set<string>();
  const entries = diff.entries.map(
    (entry, index) => {
      const path = safeRelativePath(
        entry.path,
        `diff.entries[${index}].path`,
      );
      if (paths.has(path)) {
        throw new Error(
          "security repair diff contains duplicate path",
        );
      }
      paths.add(path);
      if (
        entry.kind !== "ADDED" &&
        entry.kind !== "MODIFIED" &&
        entry.kind !== "DELETED"
      ) {
        throw new TypeError(
          "security repair diff kind is invalid",
        );
      }
      const fromSha256 =
        entry.fromSha256 === null
          ? null
          : sha(
              entry.fromSha256,
              `diff.entries[${index}].fromSha256`,
            )!;
      const toSha256 =
        entry.toSha256 === null
          ? null
          : sha(
              entry.toSha256,
              `diff.entries[${index}].toSha256`,
            )!;
      if (
        entry.kind === "ADDED" &&
        (fromSha256 !== null ||
          toSha256 === null)
      ) {
        throw new Error(
          "ADDED repair diff entry has impossible before/after hashes",
        );
      }
      if (
        entry.kind === "DELETED" &&
        (fromSha256 === null ||
          toSha256 !== null)
      ) {
        throw new Error(
          "DELETED repair diff entry has impossible before/after hashes",
        );
      }
      if (
        entry.kind === "MODIFIED" &&
        (fromSha256 === null ||
          toSha256 === null)
      ) {
        throw new Error(
          "MODIFIED repair diff entry requires before/after hashes",
        );
      }
      return Object.freeze({
        path,
        kind: entry.kind,
        fromSha256,
        toSha256,
      });
    },
  );
  return Object.freeze({
    schemaVersion:
      "toadaid.workspace-diff.v1",
    fromSnapshotId:
      diff.fromSnapshotId,
    toSnapshotId:
      diff.toSnapshotId,
    entries: Object.freeze(entries),
  });
}

function deriveWorkspaceDiffFromSnapshots(
  beforeInput: WorkspaceSnapshot,
  afterInput: WorkspaceSnapshot,
): WorkspaceDiffReceipt {
  const before =
    normalizeWorkspaceSnapshotEvidence(
      beforeInput,
      "beforeSnapshot",
    );
  const after =
    normalizeWorkspaceSnapshotEvidence(
      afterInput,
      "afterSnapshot",
    );

  if (
    before.workspaceId !==
    after.workspaceId
  ) {
    throw new Error(
      "security repair before/after snapshots must share workspaceId",
    );
  }

  const beforeByPath = new Map(
    before.files.map((file) => [
      file.path,
      file,
    ]),
  );
  const afterByPath = new Map(
    after.files.map((file) => [
      file.path,
      file,
    ]),
  );
  const paths = [
    ...new Set([
      ...beforeByPath.keys(),
      ...afterByPath.keys(),
    ]),
  ].sort();

  const entries:
    WorkspaceDiffReceipt["entries"][number][] =
      [];

  for (const path of paths) {
    const prior = beforeByPath.get(path);
    const current = afterByPath.get(path);

    if (!prior && current) {
      entries.push({
        path,
        kind: "ADDED",
        fromSha256: null,
        toSha256: current.sha256,
      });
      continue;
    }
    if (prior && !current) {
      entries.push({
        path,
        kind: "DELETED",
        fromSha256: prior.sha256,
        toSha256: null,
      });
      continue;
    }
    if (
      prior &&
      current &&
      (
        prior.sha256 !==
          current.sha256 ||
        prior.mode !== current.mode
      )
    ) {
      entries.push({
        path,
        kind: "MODIFIED",
        fromSha256: prior.sha256,
        toSha256: current.sha256,
      });
    }
  }

  return normalizeWorkspaceDiff({
    schemaVersion:
      "toadaid.workspace-diff.v1",
    fromSnapshotId:
      before.snapshotId,
    toSnapshotId:
      after.snapshotId,
    entries: Object.freeze(entries),
  });
}

function verificationRecordSha256(
  record: SecurityRepairVerificationRecord,
): string {
  return sha256(record);
}

function normalizeVerificationRecord(
  record: SecurityRepairVerificationRecord,
): SecurityRepairVerificationRecord {
  if (
    record.schemaVersion !==
    "toadaid.security-repair-verification.v1"
  ) {
    throw new TypeError(
      "unsupported security repair verification schemaVersion",
    );
  }
  if (
    record.findingStatusMutationIncluded !==
      false ||
    record.authorityIncluded !== false ||
    record.gitAuthorityIncluded !== false ||
    record.prAuthorityIncluded !== false ||
    record.mergeAuthorityIncluded !== false
  ) {
    throw new Error(
      "security repair verification cannot carry authority or mutate finding truth",
    );
  }
  if (
    !Array.isArray(record.changedPaths) ||
    record.changedPaths.length < 1
  ) {
    throw new RangeError(
      "security repair verification changedPaths is empty",
    );
  }
  const changedPaths = record.changedPaths.map(
    (path, index) =>
      safeRelativePath(
        path,
        `changedPaths[${index}]`,
      ),
  );
  const sortedPaths =
    [...new Set(changedPaths)].sort();
  if (
    sortedPaths.length !==
      changedPaths.length ||
    JSON.stringify(sortedPaths) !==
      JSON.stringify(changedPaths)
  ) {
    throw new Error(
      "security repair verification changedPaths must be unique and sorted",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-verification.v1",
    proposalRecordSha256: sha(
      record.proposalRecordSha256,
      "proposalRecordSha256",
    )!,
    findingId: boundedId(
      record.findingId,
      "findingId",
    ),
    findingRecordSha256: sha(
      record.findingRecordSha256,
      "findingRecordSha256",
    )!,
    beforeSnapshotId: boundedId(
      record.beforeSnapshotId,
      "beforeSnapshotId",
    ),
    beforeSnapshotSha256: sha(
      record.beforeSnapshotSha256,
      "beforeSnapshotSha256",
    )!,
    afterSnapshotId: boundedId(
      record.afterSnapshotId,
      "afterSnapshotId",
    ),
    afterSnapshotSha256: sha(
      record.afterSnapshotSha256,
      "afterSnapshotSha256",
    )!,
    diffSha256: sha(
      record.diffSha256,
      "diffSha256",
    )!,
    changedPaths:
      Object.freeze(sortedPaths),
    testEvidenceRefs:
      normalizeEvidenceRefs(
        record.testEvidenceRefs,
        "testEvidenceRefs",
        true,
      ),
    verifiedAt: canonicalIso(
      record.verifiedAt,
      "verifiedAt",
    ),
    findingStatusMutationIncluded: false,
    authorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

export function validateSecurityRepairVerification(
  envelope: SecurityRepairVerificationEnvelope,
): SecurityRepairVerificationEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-repair-verification-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security repair verification envelope schemaVersion",
    );
  }
  const record =
    normalizeVerificationRecord(
      envelope.record,
    );
  const recordSha256 = sha(
    envelope.recordSha256,
    "recordSha256",
  )!;
  if (
    recordSha256 !==
    verificationRecordSha256(record)
  ) {
    throw new Error(
      "security repair verification integrity mismatch",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-verification-envelope.v1",
    record,
    recordSha256,
  });
}

export function createSecurityRepairVerificationPackage(
  input:
    CreateSecurityRepairVerificationPackageInput,
): SecurityRepairVerificationEnvelope {
  const proposal =
    validateSecurityRepairProposalAgainstCanonical(
      input.canonicalFindings,
      input.proposal,
    );
  const preMutation =
    validateSecurityRepairPreMutationBinding(
      input.preMutation,
    );
  if (
    preMutation.record
      .proposalRecordSha256 !==
      proposal.recordSha256 ||
    preMutation.record
      .findingRecordSha256 !==
      proposal.record.findingRecordSha256
  ) {
    throw new Error(
      "security repair pre-mutation binding does not match proposal",
    );
  }

  const before =
    normalizeWorkspaceSnapshotEvidence(
      input.beforeSnapshot,
      "beforeSnapshot",
    );
  if (
    before.workspaceId !==
      preMutation.record.workspaceId ||
    before.snapshotId !==
      preMutation.record.beforeSnapshotId ||
    workspaceSnapshotSha256(before) !==
      preMutation.record.beforeSnapshotSha256
  ) {
    throw new Error(
      "security repair before snapshot does not match pre-mutation binding",
    );
  }

  const after =
    normalizeWorkspaceSnapshotEvidence(
      input.afterSnapshot,
      "afterSnapshot",
    );
  if (
    after.workspaceId !==
    preMutation.record.workspaceId
  ) {
    throw new Error(
      "security repair before/after snapshots must share workspaceId",
    );
  }
  if (
    Date.parse(after.createdAt) <
    Date.parse(
      preMutation.record.snapshotCreatedAt,
    )
  ) {
    throw new RangeError(
      "security repair after snapshot predates before snapshot",
    );
  }

  const diff =
    normalizeWorkspaceDiff(input.diff);
  const expectedDiff =
    deriveWorkspaceDiffFromSnapshots(
      before,
      after,
    );
  if (
    JSON.stringify(diff) !==
    JSON.stringify(expectedDiff)
  ) {
    throw new Error(
      "security repair diff does not match exact before/after snapshot manifests",
    );
  }

  const verifiedAt = canonicalIso(
    input.verifiedAt,
    "verifiedAt",
  );
  if (
    Date.parse(verifiedAt) <
    Date.parse(after.createdAt)
  ) {
    throw new RangeError(
      "security repair verification predates after snapshot",
    );
  }

  const record =
    normalizeVerificationRecord({
      schemaVersion:
        "toadaid.security-repair-verification.v1",
      proposalRecordSha256:
        proposal.recordSha256,
      findingId:
        proposal.record.findingId,
      findingRecordSha256:
        proposal.record.findingRecordSha256,
      beforeSnapshotId:
        preMutation.record.beforeSnapshotId,
      beforeSnapshotSha256:
        preMutation.record.beforeSnapshotSha256,
      afterSnapshotId:
        after.snapshotId,
      afterSnapshotSha256:
        workspaceSnapshotSha256(after),
      diffSha256: sha256(diff),
      changedPaths:
        Object.freeze(
          diff.entries
            .map((entry) => entry.path)
            .sort(),
        ),
      testEvidenceRefs:
        input.testEvidenceRefs,
      verifiedAt,
      findingStatusMutationIncluded: false,
      authorityIncluded: false,
      gitAuthorityIncluded: false,
      prAuthorityIncluded: false,
      mergeAuthorityIncluded: false,
    });

  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-verification-envelope.v1",
    record,
    recordSha256:
      verificationRecordSha256(record),
  });
}

export function assertSecurityRepairMergeActorSeparated(
  proposalInput:
    SecurityRepairProposalEnvelope,
  mergeActorIdentitySha256Input: string,
): SecurityRepairMergeSeparationReceipt {
  const proposal =
    validateSecurityRepairProposal(
      proposalInput,
    );
  const mergeActorIdentitySha256 = sha(
    mergeActorIdentitySha256Input,
    "mergeActorIdentitySha256",
  )!;
  if (
    mergeActorIdentitySha256 ===
    proposal.record.finderIdentitySha256
  ) {
    throw new Error(
      "security repair finder cannot merge its own fix",
    );
  }
  if (
    mergeActorIdentitySha256 ===
    proposal.record.validatorIdentitySha256
  ) {
    throw new Error(
      "security repair validator cannot merge its own fix",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-repair-merge-separation.v1",
    proposalRecordSha256:
      proposal.recordSha256,
    mergeActorIdentitySha256,
    separatedFromFinder: true,
    separatedFromValidator: true,
    mergeAuthorityGranted: false,
  });
}
