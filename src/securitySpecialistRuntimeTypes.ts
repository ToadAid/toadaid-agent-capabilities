import type {
  CapabilityAuthorityDecision,
  CapabilityPolicyLayer,
} from "./capabilityPolicy.js";
import type {
  CapabilityInvocationContractBinding,
  CapabilityInvocationProviderBinding,
  CompileGovernedRecipeWithContractsOptions,
  ContractBoundRecipePlan,
} from "./capabilityContractTypes.js";
import type {
  CapabilityInvocationEnvelope,
  CapabilityInvocationHeadRuntime,
} from "./invocationTypes.js";
import type {
  RunBudgetLedgerEnvelope,
  RunBudgetVector,
} from "./runBudgetTypes.js";
import type {
  RunStateCapsule,
} from "./runStateCapsule.js";
import type {
  ChildTaskRecord,
} from "./childTaskLifecycle.js";
import type {
  GovernedRecipeDefinition,
} from "./recipeTypes.js";
import type {
  SecuritySpecialistMode,
} from "./securitySpecialistTypes.js";

export interface SecuritySpecialistChildTaskHeadIdentity {
  readonly parentRunId: string;
  readonly childTaskId: string;
}

export interface SecuritySpecialistChildTaskHeadRuntime {
  resolveCurrentChildTaskHead(
    identity: SecuritySpecialistChildTaskHeadIdentity,
  ): ChildTaskRecord | null;
}

export interface SecuritySpecialistRunBudgetHeadIdentity {
  readonly runId: string;
  readonly budgetId: string;
  readonly childTaskId: string;
}

export interface SecuritySpecialistRunBudgetHeadRuntime {
  resolveCurrentRunBudgetHead(
    identity: SecuritySpecialistRunBudgetHeadIdentity,
  ): RunBudgetLedgerEnvelope | null;
}

export interface SecuritySpecialistContractPlan {
  readonly schemaVersion:
    "toadaid.security-specialist-contract-plan.v1";
  readonly mode: SecuritySpecialistMode;
  readonly recipe: GovernedRecipeDefinition;
  readonly contractPlan: ContractBoundRecipePlan;
  readonly inspectionOnly: true;
  readonly repairAuthorityIncluded: false;
  readonly fileMutationAuthorityIncluded: false;
  readonly gitAuthorityIncluded: false;
  readonly prAuthorityIncluded: false;
  readonly mergeAuthorityIncluded: false;
}

export interface BindSecuritySpecialistStepRuntimeInput {
  readonly compiled: SecuritySpecialistContractPlan;
  readonly compileOptions:
    CompileGovernedRecipeWithContractsOptions;
  readonly parentRunState: RunStateCapsule;
  readonly childTask: ChildTaskRecord;
  readonly childTaskHeadRuntime:
    SecuritySpecialistChildTaskHeadRuntime;
  readonly parentBudget: RunBudgetLedgerEnvelope;
  readonly childBudget: RunBudgetLedgerEnvelope;
  readonly childBudgetHeadRuntime:
    SecuritySpecialistRunBudgetHeadRuntime;
  readonly parentPolicyLayers:
    readonly CapabilityPolicyLayer[];
  readonly invocation: CapabilityInvocationEnvelope;
  readonly invocationHeadRuntime:
    CapabilityInvocationHeadRuntime;
  readonly invocationContractBinding:
    CapabilityInvocationContractBinding;
  readonly provider:
    CapabilityInvocationProviderBinding;
  readonly stepId: string;
  readonly requestedBudget: RunBudgetVector;
  readonly boundAt: string;
}

export interface SecuritySpecialistStepRuntimeRecord {
  readonly schemaVersion:
    "toadaid.security-specialist-step-runtime.v1";
  readonly mode: SecuritySpecialistMode;
  readonly recipeId: string;
  readonly contractPlanSha256: string;
  readonly basePlanSha256: string;
  readonly stepId: string;
  readonly capabilityId: string;
  readonly stepIntentSha256: string;
  readonly contractRequirementSha256: string;
  readonly contractDescriptorSha256: string;
  readonly contractRegistrySha256: string;
  readonly providerDescriptorSha256: string;
  readonly adapterRegistrationSha256: string;
  readonly implementationFingerprintSha256: string;
  readonly invocationId: string;
  readonly invocationRecordSha256: string;
  readonly invocationContractBindingSha256: string;
  readonly parentRunId: string;
  readonly parentRunStateSha256: string;
  readonly childTaskId: string;
  readonly childTaskSha256: string;
  readonly childRunStateSha256: string;
  readonly parentBudgetId: string;
  readonly parentBudgetSha256: string;
  readonly childBudgetId: string;
  readonly childBudgetSha256: string;
  readonly childBudgetAllocationSha256: string;
  readonly requestedBudget: RunBudgetVector;
  readonly remainingBudgetBefore: RunBudgetVector;
  readonly remainingBudgetAfter: RunBudgetVector;
  readonly parentAuthorityDecision: "ALLOW";
  readonly childAuthorityDecision: "ALLOW";
  readonly boundAt: string;
  readonly currentH1HeadVerified: true;
  readonly currentC1ContractVerified: true;
  readonly currentP3AuthorityVerified: true;
  readonly currentQ1BudgetVerified: true;
  readonly currentP5DelegationVerified: true;
  readonly authorityIncluded: false;
  readonly repairAuthorityIncluded: false;
  readonly mutationAuthorityIncluded: false;
  readonly gitAuthorityIncluded: false;
  readonly prAuthorityIncluded: false;
  readonly mergeAuthorityIncluded: false;
}

export interface SecuritySpecialistStepRuntimeEnvelope {
  readonly schemaVersion:
    "toadaid.security-specialist-step-runtime-envelope.v1";
  readonly record:
    SecuritySpecialistStepRuntimeRecord;
  readonly recordSha256: string;
}

export interface SecuritySpecialistRuntimePolicyEvidence {
  readonly parent:
    readonly CapabilityAuthorityDecision[];
  readonly child:
    readonly CapabilityAuthorityDecision[];
}
