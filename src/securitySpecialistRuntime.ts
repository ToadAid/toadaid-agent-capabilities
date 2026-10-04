import {
  assertCapabilityInvocationContractReady,
  assertContractBoundRecipePlanCurrent,
  capabilityContractRequirementSha256,
  compileGovernedRecipeWithContracts,
  normalizeCapabilityContractRequirement,
  validateContractBoundRecipePlan,
} from "./capabilityContract.js";
import type {
  CompileGovernedRecipeWithContractsOptions,
} from "./capabilityContractTypes.js";
import {
  resolveCapabilityAuthority,
} from "./capabilityPolicy.js";
import {
  validateCapabilityInvocationEnvelope,
} from "./capabilityInvocation.js";
import {
  assertCurrentCapabilityInvocationHead,
} from "./invocationReconciliation.js";
import {
  canonicalIso,
  sha256,
} from "./invocationSchema.js";
import {
  assertChildRunBudgetBinding,
  evaluateRunBudgetAvailability,
  normalizeRunBudgetVector,
  validateRunBudgetLedgerEnvelope,
} from "./runBudgetLedger.js";
import {
  resolveResumeCapabilityAuthority,
  runStateCapsuleSha256,
  validateRunStateCapsule,
} from "./runStateCapsule.js";
import {
  childTaskSha256,
  resolveChildTaskCapabilityAuthority,
  sealChildTask,
} from "./childTaskLifecycle.js";
import {
  assertSecuritySpecialistPlanInspectionOnly,
  securitySpecialistRecipe,
} from "./securitySpecialist.js";
import type {
  SecuritySpecialistMode,
} from "./securitySpecialistTypes.js";
import type {
  BindSecuritySpecialistStepRuntimeInput,
  SecuritySpecialistContractPlan,
  SecuritySpecialistStepRuntimeEnvelope,
  SecuritySpecialistStepRuntimeRecord,
} from "./securitySpecialistRuntimeTypes.js";

export type * from "./securitySpecialistRuntimeTypes.js";

function sameStringSet(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return JSON.stringify([...left].sort()) ===
    JSON.stringify([...right].sort());
}

function budgetIsZero(
  value: ReturnType<
    typeof normalizeRunBudgetVector
  >,
): boolean {
  return (
    value.modelRequests === 0 &&
    value.inputTokens === 0 &&
    value.outputTokens === 0 &&
    value.toolCalls === 0 &&
    value.networkRequests === 0 &&
    value.retries === 0 &&
    value.wallClockMs === 0 &&
    value.childTasks === 0
  );
}

export function compileSecuritySpecialistRecipeWithContracts(
  mode: SecuritySpecialistMode,
  rawInputs: Readonly<Record<string, unknown>>,
  options: CompileGovernedRecipeWithContractsOptions,
): SecuritySpecialistContractPlan {
  const recipe =
    securitySpecialistRecipe(mode);
  const contractPlan =
    compileGovernedRecipeWithContracts(
      recipe,
      rawInputs,
      options,
    );

  assertSecuritySpecialistPlanInspectionOnly(
    contractPlan.basePlan,
  );

  return Object.freeze({
    schemaVersion:
      "toadaid.security-specialist-contract-plan.v1",
    mode,
    recipe,
    contractPlan,
    inspectionOnly: true,
    repairAuthorityIncluded: false,
    fileMutationAuthorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

function validateCompiled(
  input: SecuritySpecialistContractPlan,
): SecuritySpecialistContractPlan {
  if (
    input.schemaVersion !==
    "toadaid.security-specialist-contract-plan.v1"
  ) {
    throw new TypeError(
      "unsupported security specialist contract plan schemaVersion",
    );
  }
  const recipe =
    securitySpecialistRecipe(input.mode);
  const contractPlan =
    validateContractBoundRecipePlan(
      input.contractPlan,
    );
  assertSecuritySpecialistPlanInspectionOnly(
    contractPlan.basePlan,
  );
  if (
    recipe.recipeId !== input.recipe.recipeId ||
    recipe.version !== input.recipe.version ||
    sha256(recipe) !== sha256(input.recipe)
  ) {
    throw new Error(
      "security specialist contract plan recipe drift",
    );
  }
  if (
    input.inspectionOnly !== true ||
    input.repairAuthorityIncluded !== false ||
    input.fileMutationAuthorityIncluded !== false ||
    input.gitAuthorityIncluded !== false ||
    input.prAuthorityIncluded !== false ||
    input.mergeAuthorityIncluded !== false
  ) {
    throw new Error(
      "security specialist contract plan carries forbidden authority truth",
    );
  }

  return Object.freeze({
    ...input,
    recipe,
    contractPlan,
  });
}

export function securitySpecialistStepIntentSha256(
  compiledInput:
    SecuritySpecialistContractPlan,
  stepIdInput: string,
): string {
  const compiled =
    validateCompiled(compiledInput);
  const step =
    compiled.contractPlan.basePlan.steps.find(
      (candidate) =>
        candidate.id === stepIdInput,
    );
  if (!step) {
    throw new Error(
      "security specialist runtime references unknown recipe step",
    );
  }
  if (step.status !== "ENABLED") {
    throw new Error(
      "security specialist runtime cannot bind a skipped optional step",
    );
  }

  return sha256({
    schemaVersion:
      "toadaid.security-specialist-step-intent.v1",
    mode: compiled.mode,
    recipeId:
      compiled.contractPlan.basePlan.recipeId,
    contractPlanSha256:
      compiled.contractPlan.planSha256,
    stepId: step.id,
    capabilityId: step.capabilityId,
  });
}

function runtimeRecordSha256(
  record:
    SecuritySpecialistStepRuntimeRecord,
): string {
  return sha256(record);
}

function assertRequestedBudgetLaw(
  requestedInput:
    BindSecuritySpecialistStepRuntimeInput[
      "requestedBudget"
    ],
) {
  const requested =
    normalizeRunBudgetVector(
      requestedInput,
      "requestedBudget",
    );
  if (budgetIsZero(requested)) {
    throw new Error(
      "security specialist step budget must consume at least one metric",
    );
  }
  if (
    requested.networkRequests !== 0 ||
    requested.retries !== 0 ||
    requested.childTasks !== 0
  ) {
    throw new Error(
      "security specialist inspection step budget cannot request network, retry, or child-task fuel",
    );
  }
  return requested;
}

function assertCurrentP5ChildTaskHead(
  input: BindSecuritySpecialistStepRuntimeInput,
) {
  const supplied =
    sealChildTask(input.childTask).task;
  const current =
    input.childTaskHeadRuntime
      .resolveCurrentChildTaskHead({
        parentRunId: supplied.parentRunId,
        childTaskId: supplied.childTaskId,
      });
  if (current === null) {
    throw new Error(
      "current P5 child-task head is unavailable",
    );
  }
  const canonicalCurrent =
    sealChildTask(current).task;
  if (
    canonicalCurrent.parentRunId !==
      supplied.parentRunId ||
    canonicalCurrent.childTaskId !==
      supplied.childTaskId
  ) {
    throw new Error(
      "current P5 child-task head identity mismatch",
    );
  }
  if (
    childTaskSha256(canonicalCurrent) !==
    childTaskSha256(supplied)
  ) {
    throw new Error(
      "security specialist P5 child is stale relative to current P5 head",
    );
  }
  return canonicalCurrent;
}

function assertCurrentQ1ChildBudgetHead(
  input: BindSecuritySpecialistStepRuntimeInput,
) {
  const supplied =
    validateRunBudgetLedgerEnvelope(
      input.childBudget,
    );
  if (
    supplied.record.childTaskId === undefined
  ) {
    throw new Error(
      "security specialist child Q1 budget requires childTaskId",
    );
  }
  const current =
    input.childBudgetHeadRuntime
      .resolveCurrentRunBudgetHead({
        runId: supplied.record.runId,
        budgetId: supplied.record.budgetId,
        childTaskId:
          supplied.record.childTaskId,
      });
  if (current === null) {
    throw new Error(
      "current Q1 child budget head is unavailable",
    );
  }
  const canonicalCurrent =
    validateRunBudgetLedgerEnvelope(
      current,
    );
  if (
    canonicalCurrent.record.runId !==
      supplied.record.runId ||
    canonicalCurrent.record.budgetId !==
      supplied.record.budgetId ||
    canonicalCurrent.record.childTaskId !==
      supplied.record.childTaskId
  ) {
    throw new Error(
      "current Q1 child budget head identity mismatch",
    );
  }
  if (
    canonicalCurrent.recordSha256 !==
    supplied.recordSha256
  ) {
    throw new Error(
      "security specialist child Q1 budget is stale relative to current Q1 head",
    );
  }
  return canonicalCurrent;
}

function buildRuntimeRecord(
  input: BindSecuritySpecialistStepRuntimeInput,
): SecuritySpecialistStepRuntimeRecord {
  const compiled =
    validateCompiled(input.compiled);
  const currentPlan =
    assertContractBoundRecipePlanCurrent(
      compiled.contractPlan,
      compiled.recipe,
      input.compileOptions,
    );
  const basePlan =
    compiled.contractPlan.basePlan;
  const step =
    basePlan.steps.find(
      (candidate) =>
        candidate.id === input.stepId,
    );
  if (!step) {
    throw new Error(
      "security specialist runtime references unknown recipe step",
    );
  }
  if (step.status !== "ENABLED") {
    throw new Error(
      "security specialist runtime cannot bind a skipped optional step",
    );
  }
  if (
    !basePlan.effectiveCapabilities.includes(
      step.capabilityId,
    )
  ) {
    throw new Error(
      "security specialist enabled step capability is absent from effective plan",
    );
  }

  const parentRunState =
    validateRunStateCapsule(
      input.parentRunState,
    );
  const childTask =
    assertCurrentP5ChildTaskHead(input);
  if (childTask.status !== "RUNNING") {
    throw new Error(
      "security specialist runtime requires a RUNNING P5 child",
    );
  }
  if (
    childTask.parentRunId !==
    parentRunState.runId
  ) {
    throw new Error(
      "security specialist P5 child is not bound to parent run",
    );
  }
  if (
    !sameStringSet(
      childTask.delegatedCapabilities,
      basePlan.effectiveCapabilities,
    )
  ) {
    throw new Error(
      "security specialist P5 delegated capabilities must equal effective W1 plan",
    );
  }

  const parentDecision =
    resolveCapabilityAuthority(
      step.capabilityId,
      input.compileOptions.manifest,
      input.parentPolicyLayers,
    );
  const parentResume =
    resolveResumeCapabilityAuthority(
      step.capabilityId,
      parentRunState,
      [parentDecision],
    );
  const childDecision =
    resolveCapabilityAuthority(
      step.capabilityId,
      input.compileOptions.manifest,
      input.compileOptions.policyLayers,
    );
  const childAuthority =
    resolveChildTaskCapabilityAuthority(
      step.capabilityId,
      childTask,
      [parentResume],
      [childDecision],
    );
  if (
    parentResume.decision !== "ALLOW" ||
    childAuthority.decision !== "ALLOW"
  ) {
    throw new Error(
      "security specialist step is not currently authorized through P3/P5",
    );
  }

  const parentBudget =
    validateRunBudgetLedgerEnvelope(
      input.parentBudget,
    );
  const childBudget =
    assertCurrentQ1ChildBudgetHead(
      input,
    );
  if (
    parentBudget.record.runId !==
      parentRunState.runId
  ) {
    throw new Error(
      "security specialist parent Q1 budget run mismatch",
    );
  }
  if (
    childBudget.record.runId !==
      childTask.childTaskId ||
    childBudget.record.childTaskId !==
      childTask.childTaskId
  ) {
    throw new Error(
      "security specialist child Q1 budget is not bound to P5 child",
    );
  }
  const allocation =
    assertChildRunBudgetBinding(
      parentBudget,
      childBudget,
    );
  if (
    allocation.childTaskId !==
    childTask.childTaskId
  ) {
    throw new Error(
      "security specialist Q1 allocation childTaskId mismatch",
    );
  }

  const requestedBudget =
    assertRequestedBudgetLaw(
      input.requestedBudget,
    );
  const budgetAvailability =
    evaluateRunBudgetAvailability(
      childBudget,
      requestedBudget,
    );
  if (!budgetAvailability.allowed) {
    throw new Error(
      `security specialist step exceeds current Q1 budget: ${budgetAvailability.exceededMetrics.join(",")}`,
    );
  }

  const invocation =
    assertCurrentCapabilityInvocationHead(
      input.invocationHeadRuntime,
      validateCapabilityInvocationEnvelope(
        input.invocation,
      ),
    );
  if (
    invocation.record.status !==
    "AUTHORIZED"
  ) {
    throw new Error(
      "security specialist H1 invocation must be current AUTHORIZED head",
    );
  }
  if (
    invocation.record.runId !==
      childTask.runState.runId ||
    invocation.record.childTaskId !==
      childTask.childTaskId ||
    invocation.record.capabilityId !==
      step.capabilityId
  ) {
    throw new Error(
      "security specialist H1 invocation is not bound to exact P5 child/capability",
    );
  }

  const stepIntentSha256 =
    securitySpecialistStepIntentSha256(
      compiled,
      step.id,
    );
  if (
    invocation.record.request.intentSha256 !==
    stepIntentSha256
  ) {
    throw new Error(
      "security specialist H1 invocation intent does not match W1 step",
    );
  }

  const requirement =
    input.compileOptions.contractProfile
      .requirements.find(
        (candidate) =>
          candidate.capabilityId ===
          step.capabilityId,
      );
  if (!requirement) {
    throw new Error(
      "security specialist C1 profile is missing enabled step capability",
    );
  }
  const normalizedRequirement =
    normalizeCapabilityContractRequirement(
      requirement,
    );
  const ready =
    assertCapabilityInvocationContractReady(
      input.invocationContractBinding,
      invocation,
      normalizedRequirement,
      input.compileOptions.contractRegistry,
      input.provider,
    );
  const compiledContract =
    currentPlan.contractBindings.find(
      (candidate) =>
        candidate.capabilityId ===
        step.capabilityId,
    );
  if (!compiledContract) {
    throw new Error(
      "security specialist current C1 plan is missing enabled step binding",
    );
  }
  if (
    ready.compatibility.requirementSha256 !==
      compiledContract.requirementSha256 ||
    ready.compatibility.descriptorSha256 !==
      compiledContract.descriptorSha256 ||
    ready.compatibility.registrySha256 !==
      compiledContract.registrySha256
  ) {
    throw new Error(
      "security specialist H1 C1 binding does not match current W1 contract plan",
    );
  }
  if (
    ready.compatibility.requirementSha256 !==
    capabilityContractRequirementSha256(
      normalizedRequirement,
    )
  ) {
    throw new Error(
      "security specialist C1 requirement identity mismatch",
    );
  }

  const boundAt = canonicalIso(
    input.boundAt,
    "boundAt",
  );
  if (
    Date.parse(boundAt) <
    Date.parse(invocation.record.updatedAt)
  ) {
    throw new RangeError(
      "security specialist runtime binding predates current H1 head",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.security-specialist-step-runtime.v1",
    mode: compiled.mode,
    recipeId: basePlan.recipeId,
    contractPlanSha256:
      compiled.contractPlan.planSha256,
    basePlanSha256:
      basePlan.planSha256,
    stepId: step.id,
    capabilityId: step.capabilityId,
    stepIntentSha256,
    contractRequirementSha256:
      ready.compatibility.requirementSha256,
    contractDescriptorSha256:
      ready.compatibility.descriptorSha256,
    contractRegistrySha256:
      ready.compatibility.registrySha256,
    providerDescriptorSha256:
      ready.provider.providerDescriptorSha256,
    adapterRegistrationSha256:
      ready.provider.adapterRegistrationSha256,
    implementationFingerprintSha256:
      ready.provider
        .implementationFingerprintSha256,
    invocationId:
      invocation.record.invocationId,
    invocationRecordSha256:
      invocation.recordSha256,
    invocationContractBindingSha256:
      ready.bindingSha256,
    parentRunId:
      parentRunState.runId,
    parentRunStateSha256:
      runStateCapsuleSha256(
        parentRunState,
      ),
    childTaskId:
      childTask.childTaskId,
    childTaskSha256:
      childTaskSha256(childTask),
    childRunStateSha256:
      runStateCapsuleSha256(
        childTask.runState,
      ),
    parentBudgetId:
      parentBudget.record.budgetId,
    parentBudgetSha256:
      parentBudget.recordSha256,
    childBudgetId:
      childBudget.record.budgetId,
    childBudgetSha256:
      childBudget.recordSha256,
    childBudgetAllocationSha256:
      allocation.allocationSha256,
    requestedBudget,
    remainingBudgetBefore:
      budgetAvailability.remainingBefore,
    remainingBudgetAfter:
      budgetAvailability.remainingAfter,
    parentAuthorityDecision: "ALLOW",
    childAuthorityDecision: "ALLOW",
    boundAt,
    currentH1HeadVerified: true,
    currentC1ContractVerified: true,
    currentP3AuthorityVerified: true,
    currentQ1BudgetVerified: true,
    currentP5DelegationVerified: true,
    authorityIncluded: false,
    repairAuthorityIncluded: false,
    mutationAuthorityIncluded: false,
    gitAuthorityIncluded: false,
    prAuthorityIncluded: false,
    mergeAuthorityIncluded: false,
  });
}

export function bindSecuritySpecialistStepRuntime(
  input: BindSecuritySpecialistStepRuntimeInput,
): SecuritySpecialistStepRuntimeEnvelope {
  const record =
    buildRuntimeRecord(input);
  return Object.freeze({
    schemaVersion:
      "toadaid.security-specialist-step-runtime-envelope.v1",
    record,
    recordSha256:
      runtimeRecordSha256(record),
  });
}

export function assertSecuritySpecialistStepRuntimeCurrent(
  envelope:
    SecuritySpecialistStepRuntimeEnvelope,
  input: BindSecuritySpecialistStepRuntimeInput,
): SecuritySpecialistStepRuntimeEnvelope {
  if (
    envelope.schemaVersion !==
    "toadaid.security-specialist-step-runtime-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported security specialist runtime envelope schemaVersion",
    );
  }
  if (
    envelope.record.schemaVersion !==
    "toadaid.security-specialist-step-runtime.v1" ||
    envelope.recordSha256 !==
      runtimeRecordSha256(envelope.record)
  ) {
    throw new Error(
      "security specialist runtime binding integrity mismatch",
    );
  }

  const current =
    bindSecuritySpecialistStepRuntime(
      input,
    );
  if (
    current.recordSha256 !==
    envelope.recordSha256
  ) {
    throw new Error(
      "security specialist runtime binding is stale relative to current authoritative runtime evidence",
    );
  }
  return current;
}
