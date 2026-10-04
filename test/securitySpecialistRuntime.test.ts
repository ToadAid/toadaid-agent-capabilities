import assert from "node:assert/strict";
import test from "node:test";

import {
  createCapabilityContractRegistry,
  createCapabilityInvocationContractBinding,
} from "../src/capabilityContract.js";
import {
  authorizeCapabilityInvocation,
  createCapabilityInvocation,
} from "../src/capabilityInvocation.js";
import {
  CORE_CAPABILITY_MANIFEST,
  resolveCapabilityAuthority,
} from "../src/capabilityPolicy.js";
import type {
  CapabilityPolicyLayer,
} from "../src/capabilityPolicy.js";
import {
  createChildTask,
  transitionChildTask,
} from "../src/childTaskLifecycle.js";
import {
  allocateChildRunBudget,
  createRunBudgetLedger,
  recordRunBudgetUsage,
} from "../src/runBudgetLedger.js";
import {
  checkpointRunStateCapsule,
  createRunStateCapsule,
  resolveResumeCapabilityAuthority,
} from "../src/runStateCapsule.js";
import {
  bindSecuritySpecialistStepRuntime,
  assertSecuritySpecialistStepRuntimeCurrent,
  compileSecuritySpecialistRecipeWithContracts,
  securitySpecialistStepIntentSha256,
} from "../src/securitySpecialistRuntime.js";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const H3 = "3".repeat(64);
const H4 = "4".repeat(64);
const H5 = "5".repeat(64);
const H6 = "6".repeat(64);
const H7 = "7".repeat(64);
const H8 = "8".repeat(64);
const H9 = "9".repeat(64);
const HA = "a".repeat(64);

const policyLayers: readonly CapabilityPolicyLayer[] = [{
  scope: "agent",
  subject: "sec8-runtime-child",
  decisions: {
    "host:file-read": "ALLOW",
    "host:session": "ALLOW",
  },
}];

const parentPolicyLayers:
  readonly CapabilityPolicyLayer[] = [{
    scope: "agent",
    subject: "sec8-runtime-parent",
    decisions: {
      "host:file-read": "ALLOW",
      "host:session": "ALLOW",
    },
  }];

function descriptor(
  capabilityId: "host:file-read" | "host:session",
  contractId: string,
  seed: string,
) {
  return {
    schemaVersion:
      "toadaid.capability-contract.v2" as const,
    capabilityId,
    contractId,
    version: {
      major: 1,
      minor: 0,
    },
    features: [] as readonly string[],
    requestSchema: {
      schemaId:
        `${contractId}.request.v1`,
      schemaSha256: seed,
    },
    resultSchema: {
      schemaId:
        `${contractId}.result.v1`,
      schemaSha256:
        capabilityId ===
        "host:file-read"
          ? H4
          : H5,
    },
    receiptSchema: {
      schemaId:
        `${contractId}.receipt.v1`,
      schemaSha256:
        capabilityId ===
        "host:file-read"
          ? H6
          : H7,
    },
  };
}

function contractContext(
  registry = createCapabilityContractRegistry([
    descriptor(
      "host:file-read",
      "toadaid.host.file-read",
      H2,
    ),
    descriptor(
      "host:session",
      "toadaid.host.session",
      H3,
    ),
  ]),
) {
  return {
    manifest:
      CORE_CAPABILITY_MANIFEST,
    policyLayers,
    compiledAt:
      "2026-10-04T05:00:00.000Z",
    contractRegistry: registry,
    contractProfile: {
      schemaVersion:
        "toadaid.recipe-contract-profile.v1" as const,
      recipeId:
        "security-targeted-audit",
      recipeVersion: "1",
      requirements: [
        {
          capabilityId:
            "host:file-read",
          contractId:
            "toadaid.host.file-read",
          major: 1,
          minMinor: 0,
          requiredFeatures: [],
        },
        {
          capabilityId:
            "host:session",
          contractId:
            "toadaid.host.session",
          major: 1,
          minMinor: 0,
          requiredFeatures: [],
        },
      ],
    },
  };
}

function authority(
  capabilityId:
    | "host:file-read"
    | "host:session",
  layers:
    readonly CapabilityPolicyLayer[] =
      policyLayers,
) {
  return resolveCapabilityAuthority(
    capabilityId,
    CORE_CAPABILITY_MANIFEST,
    layers,
  );
}

function parentRun() {
  return createRunStateCapsule({
    runId: "sec8-parent",
    createdAt:
      "2026-10-04T05:01:00.000Z",
    objective: {
      summary:
        "Run bounded security specialist",
      status: "ACTIVE",
    },
    phase: "security-specialist",
    authoritySnapshot: {
      capturedAt:
        "2026-10-04T05:01:00.000Z",
      decisions: [
        authority(
          "host:file-read",
          parentPolicyLayers,
        ),
        authority(
          "host:session",
          parentPolicyLayers,
        ),
      ],
    },
  });
}

function runningChild(parent = parentRun()) {
  const childCreatedAt =
    "2026-10-04T05:02:00.000Z";
  const childState =
    createRunStateCapsule({
      runId: "sec8-child",
      createdAt: childCreatedAt,
      objective: {
        summary:
          "Inspect targeted security scope",
        status: "ACTIVE",
      },
      phase: "targeted-audit",
      authoritySnapshot: {
        capturedAt: childCreatedAt,
        decisions: [
          authority("host:file-read"),
          authority("host:session"),
        ],
      },
    });

  const parentAuthority = [
    resolveResumeCapabilityAuthority(
      "host:file-read",
      parent,
      [
        authority(
          "host:file-read",
          parentPolicyLayers,
        ),
      ],
    ),
    resolveResumeCapabilityAuthority(
      "host:session",
      parent,
      [
        authority(
          "host:session",
          parentPolicyLayers,
        ),
      ],
    ),
  ];

  const created = createChildTask({
    childTaskId: "sec8-child",
    parentRunId: parent.runId,
    createdAt: childCreatedAt,
    delegatedCapabilities: [
      "host:file-read",
      "host:session",
    ],
    parentAuthority,
    runState: childState,
  });

  return transitionChildTask(
    created,
    {
      kind: "START",
      updatedAt:
        "2026-10-04T05:03:00.000Z",
      runState:
        checkpointRunStateCapsule(
          childState,
          {
            updatedAt:
              "2026-10-04T05:03:00.000Z",
            reason: "CHECKPOINT",
          },
        ),
    },
  );
}

function budgets() {
  const zero = {
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 0,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 0,
    childTasks: 0,
  };
  const parent =
    createRunBudgetLedger({
      budgetId: "budget-parent",
      runId: "sec8-parent",
      createdAt:
        "2026-10-04T05:01:00.000Z",
      limits: {
        ...zero,
        toolCalls: 20,
        wallClockMs: 20_000,
        childTasks: 2,
      },
    });
  return allocateChildRunBudget(
    parent,
    {
      allocationId:
        "alloc-sec8-child",
      childBudgetId:
        "budget-sec8-child",
      childRunId:
        "sec8-child",
      childTaskId:
        "sec8-child",
      allocatedAt:
        "2026-10-04T05:02:00.000Z",
      limits: {
        ...zero,
        toolCalls: 10,
        wallClockMs: 10_000,
      },
    },
  );
}

function provider() {
  return {
    providerDescriptorSha256: H7,
    adapterRegistrationSha256: H8,
    implementationFingerprintSha256:
      H9,
  };
}

function compiled(
  context = contractContext(),
) {
  return compileSecuritySpecialistRecipeWithContracts(
    "TARGETED_AUDIT",
    {
      repositoryIdentitySha256: H1,
      sourceRevision: "rev-a",
      sourceTreeSha256: HA,
      targetScope: "src/security",
    },
    context,
  );
}

function fixture() {
  const context = contractContext();
  const plan = compiled(context);
  const parent = parentRun();
  const child = runningChild(parent);
  const budget = budgets();
  const intent =
    securitySpecialistStepIntentSha256(
      plan,
      "inspect-target",
    );
  const requested =
    createCapabilityInvocation({
      invocationId:
        "inv-sec8-file-read",
      runId: "sec8-child",
      childTaskId: "sec8-child",
      capabilityId:
        "host:file-read",
      toolName: "host.file-read",
      intentSha256: intent,
      argumentsSha256: H6,
      createdAt:
        "2026-10-04T05:04:00.000Z",
    });
  const invocation =
    authorizeCapabilityInvocation(
      requested,
      {
        manifest:
          CORE_CAPABILITY_MANIFEST,
        policyLayers,
      },
      {
        now: () =>
          new Date(
            "2026-10-04T05:04:01.000Z",
          ),
      },
    );
  let currentHead = invocation;
  const headRuntime = {
    resolveCurrentInvocationHead() {
      return currentHead;
    },
    claimCurrentInvocationHead(
      expected:
        typeof currentHead,
      next:
        typeof currentHead,
    ) {
      if (
        currentHead.recordSha256 !==
        expected.recordSha256
      ) {
        return false;
      }
      currentHead = next;
      return true;
    },
  };
  const requirement =
    context.contractProfile
      .requirements[0]!;
  const contractBinding =
    createCapabilityInvocationContractBinding(
      invocation,
      requirement,
      context.contractRegistry,
      provider(),
    );

  const childTaskHeadRuntime = {
    resolveCurrentChildTaskHead() {
      return child;
    },
  };
  const childBudgetHeadRuntime = {
    resolveCurrentRunBudgetHead() {
      return budget.child;
    },
  };

  return {
    context,
    plan,
    parent,
    child,
    budget,
    invocation,
    headRuntime,
    childTaskHeadRuntime,
    childBudgetHeadRuntime,
    contractBinding,
    requirement,
  };
}

function bindInput(
  f = fixture(),
  overrides:
    Partial<
      Parameters<
        typeof bindSecuritySpecialistStepRuntime
      >[0]
    > = {},
) {
  return {
    compiled: f.plan,
    compileOptions: f.context,
    parentRunState: f.parent,
    childTask: f.child,
    childTaskHeadRuntime:
      f.childTaskHeadRuntime,
    parentBudget: f.budget.parent,
    childBudget: f.budget.child,
    childBudgetHeadRuntime:
      f.childBudgetHeadRuntime,
    parentPolicyLayers,
    invocation: f.invocation,
    invocationHeadRuntime:
      f.headRuntime,
    invocationContractBinding:
      f.contractBinding,
    provider: provider(),
    stepId: "inspect-target",
    requestedBudget: {
      modelRequests: 0,
      inputTokens: 0,
      outputTokens: 0,
      toolCalls: 1,
      networkRequests: 0,
      retries: 0,
      wallClockMs: 100,
      childTasks: 0,
    },
    boundAt:
      "2026-10-04T05:04:02.000Z",
    ...overrides,
  };
}

test("SEC8 P2 contract-aware compile preserves P1 inspection-only law", () => {
  const plan = compiled();
  assert.deepEqual(
    plan.contractPlan.basePlan
      .effectiveCapabilities,
    [
      "host:file-read",
      "host:session",
    ],
  );
  assert.equal(
    plan.contractPlan
      .contractBindings.length,
    2,
  );
  assert.equal(
    plan.repairAuthorityIncluded,
    false,
  );
  assert.equal(
    plan.mergeAuthorityIncluded,
    false,
  );
});

test("SEC8 P2 binds one enabled specialist step across C1 H1 Q1 P5 and current P3", () => {
  const f = fixture();
  const bound =
    bindSecuritySpecialistStepRuntime(
      bindInput(f),
    );

  assert.equal(
    bound.record.stepId,
    "inspect-target",
  );
  assert.equal(
    bound.record.capabilityId,
    "host:file-read",
  );
  assert.equal(
    bound.record.childTaskId,
    "sec8-child",
  );
  assert.equal(
    bound.record.currentC1ContractVerified,
    true,
  );
  assert.equal(
    bound.record.currentH1HeadVerified,
    true,
  );
  assert.equal(
    bound.record.currentQ1BudgetVerified,
    true,
  );
  assert.equal(
    bound.record.currentP5DelegationVerified,
    true,
  );
  assert.equal(
    bound.record.authorityIncluded,
    false,
  );

  assert.doesNotThrow(() =>
    assertSecuritySpecialistStepRuntimeCurrent(
      bound,
      bindInput(f),
    ),
  );
});

test("SEC8 P2 refuses H1 intent substitution", () => {
  const f = fixture();
  const wrongRequested =
    createCapabilityInvocation({
      invocationId:
        "inv-wrong-intent",
      runId: "sec8-child",
      childTaskId: "sec8-child",
      capabilityId:
        "host:file-read",
      toolName: "host.file-read",
      intentSha256: H2,
      argumentsSha256: H6,
      createdAt:
        "2026-10-04T05:04:00.000Z",
    });
  const wrong =
    authorizeCapabilityInvocation(
      wrongRequested,
      {
        manifest:
          CORE_CAPABILITY_MANIFEST,
        policyLayers,
      },
      {
        now: () =>
          new Date(
            "2026-10-04T05:04:01.000Z",
          ),
      },
    );
  const runtime = {
    resolveCurrentInvocationHead() {
      return wrong;
    },
    claimCurrentInvocationHead() {
      return false;
    },
  };
  const binding =
    createCapabilityInvocationContractBinding(
      wrong,
      f.requirement,
      f.context.contractRegistry,
      provider(),
    );

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          invocation: wrong,
          invocationHeadRuntime:
            runtime,
          invocationContractBinding:
            binding,
        }),
      ),
    /intent does not match W1 step/,
  );
});

test("SEC8 P2 refuses stale H1 head", () => {
  const f = fixture();
  const runtime = {
    resolveCurrentInvocationHead() {
      return null;
    },
    claimCurrentInvocationHead() {
      return false;
    },
  };

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          invocationHeadRuntime:
            runtime,
        }),
      ),
    /current H1 head is unavailable/,
  );
});

test("SEC8 P2 refuses current P3 revocation through W1 and P5", () => {
  const f = fixture();
  const revokedContext = {
    ...f.context,
    policyLayers: [{
      scope: "agent" as const,
      subject:
        "sec8-runtime-child",
      decisions: {
        "host:file-read":
          "BLOCK" as const,
        "host:session":
          "ALLOW" as const,
      },
    }],
    compiledAt:
      "2026-10-04T05:05:00.000Z",
  };

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          compileOptions:
            revokedContext,
        }),
      ),
    /no longer authorized|not currently authorized/,
  );
});

test("SEC8 P2 refuses C1 descriptor drift", () => {
  const f = fixture();
  const changedRegistry =
    createCapabilityContractRegistry([
      {
        ...descriptor(
          "host:file-read",
          "toadaid.host.file-read",
          H2,
        ),
        resultSchema: {
          schemaId:
            "toadaid.host.file-read.result.v1",
          schemaSha256: H2,
        },
      },
      descriptor(
        "host:session",
        "toadaid.host.session",
        H3,
      ),
    ]);

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          compileOptions: {
            ...f.context,
            contractRegistry:
              changedRegistry,
            compiledAt:
              "2026-10-04T05:05:00.000Z",
          },
        }),
      ),
    /descriptor changed; recompile required/,
  );
});

test("SEC8 P2 refuses insufficient Q1 child budget", () => {
  const f = fixture();
  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          requestedBudget: {
            modelRequests: 0,
            inputTokens: 0,
            outputTokens: 0,
            toolCalls: 100,
            networkRequests: 0,
            retries: 0,
            wallClockMs: 100,
            childTasks: 0,
          },
        }),
      ),
    /exceeds current Q1 budget/,
  );
});

test("SEC8 P2 refuses network retry or nested-child budget requests", () => {
  const f = fixture();
  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          requestedBudget: {
            modelRequests: 0,
            inputTokens: 0,
            outputTokens: 0,
            toolCalls: 1,
            networkRequests: 1,
            retries: 0,
            wallClockMs: 100,
            childTasks: 0,
          },
        }),
      ),
    /cannot request network, retry, or child-task fuel/,
  );
});

test("SEC8 P2 current assertion refuses stale resealed runtime evidence", () => {
  const f = fixture();
  const bound =
    bindSecuritySpecialistStepRuntime(
      bindInput(f),
    );
  const changedInput =
    bindInput(f, {
      boundAt:
        "2026-10-04T05:04:03.000Z",
    });

  assert.throws(
    () =>
      assertSecuritySpecialistStepRuntimeCurrent(
        bound,
        changedInput,
      ),
    /stale relative to current authoritative runtime evidence/,
  );
});


test("SEC8 P2 refuses a stale RUNNING P5 predecessor after current child becomes BLOCKED", () => {
  const f = fixture();
  const blockedState =
    checkpointRunStateCapsule(
      f.child.runState,
      {
        updatedAt:
          "2026-10-04T05:05:00.000Z",
        reason: "CHECKPOINT",
        objective: {
          summary:
            "Inspect targeted security scope",
          status: "BLOCKED",
        },
      },
    );
  const blocked =
    transitionChildTask(
      f.child,
      {
        kind: "BLOCK",
        updatedAt:
          "2026-10-04T05:05:00.000Z",
        runState: blockedState,
      },
    );
  const currentRuntime = {
    resolveCurrentChildTaskHead() {
      return blocked;
    },
  };

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          childTaskHeadRuntime:
            currentRuntime,
        }),
      ),
    /stale relative to current P5 head/,
  );
});

test("SEC8 P2 refuses a stale Q1 child ledger after current budget was spent", () => {
  const f = fixture();
  const spent =
    recordRunBudgetUsage(
      f.budget.child,
      {
        receiptId:
          "sec8-current-budget-spend",
        kind: "TOOL",
        occurredAt:
          "2026-10-04T05:05:00.000Z",
        invocationId:
          "inv-sec8-file-read",
        sourceSha256: H1,
        delta: {
          modelRequests: 0,
          inputTokens: 0,
          outputTokens: 0,
          toolCalls: 10,
          networkRequests: 0,
          retries: 0,
          wallClockMs: 0,
          childTasks: 0,
        },
      },
    );
  const currentRuntime = {
    resolveCurrentRunBudgetHead() {
      return spent;
    },
  };

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          childBudgetHeadRuntime:
            currentRuntime,
        }),
      ),
    /stale relative to current Q1 head/,
  );
});

test("SEC8 P2 refuses unavailable P5 or Q1 authoritative heads", () => {
  const f = fixture();
  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          childTaskHeadRuntime: {
            resolveCurrentChildTaskHead() {
              return null;
            },
          },
        }),
      ),
    /current P5 child-task head is unavailable/,
  );

  assert.throws(
    () =>
      bindSecuritySpecialistStepRuntime(
        bindInput(f, {
          childBudgetHeadRuntime: {
            resolveCurrentRunBudgetHead() {
              return null;
            },
          },
        }),
      ),
    /current Q1 child budget head is unavailable/,
  );
});

test("SEC8 P2 current-head resolvers are evidence-only and add no authority surface", () => {
  const f = fixture();
  const bound =
    bindSecuritySpecialistStepRuntime(
      bindInput(f),
    );
  const serialized =
    JSON.stringify(bound);
  for (const forbidden of [
    "repairAuthorityIncluded\\\":true",
    "mutationAuthorityIncluded\\\":true",
    "gitAuthorityIncluded\\\":true",
    "prAuthorityIncluded\\\":true",
    "mergeAuthorityIncluded\\\":true",
  ]) {
    assert.equal(
      serialized.includes(forbidden),
      false,
    );
  }
});
