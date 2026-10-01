import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  CORE_CAPABILITY_MANIFEST,
  HOST_SERVICE_CONTRACT_IDS,
  HOST_SERVICE_TOOL_NAMES,
  composeCapabilityProviderRegistry,
  composeCapabilityRuntimeProviderRegistry,
  createCapabilityModuleManifest,
  createCapabilityProviderSelection,
  checkpointRunStateCapsule,
  childTaskSha256,
  createChildTask,
  createHumanInterrupt,
  createRunStateCapsule,
  createSecretLease,
  createSecretMaterializationGrant,
  enableCapabilityModule,
  createHumanInterruptResumeProof,
  parseChildTask,
  resolveCapabilityAuthority,
  resolveHumanInterrupt,
  resolveCapabilityProvider,
  resolveCapabilityRuntimeProvider,
  resolveResumeCapabilityAuthority,
  resumeRunStateCapsule,
  runStateCapsuleSha256,
  serializeChildTask,
  serializeRunStateCapsule,
  assertSecretMaterializationGrantUsable,
  installCapabilityModule,
  transitionChildTask,
} from "@toadaid/agent-capabilities";
import {
  assessCapabilityInvocationResume,
  authorizeCapabilityInvocation,
  completeCapabilityInvocation,
  createCapabilityInvocation,
  failCapabilityInvocation,
  parseCapabilityInvocation,
  serializeCapabilityInvocation,
  startCapabilityInvocation,
} from "@toadaid/agent-capabilities/invocation";
import {
  allocateChildRunBudget,
  createRunBudgetLedger,
  parseRunBudgetLedger,
  recordRunBudgetUsage,
  remainingRunBudget,
  serializeRunBudgetLedger,
} from "@toadaid/agent-capabilities/budget";
import {
  capabilityContractDescriptorSha256,
  assertCapabilityInvocationContractReady,
  assertContractBoundRecipePlanCurrent,
  compileGovernedRecipeWithContracts,
  createCapabilityContractRegistry,
  createCapabilityInvocationContractBinding,
} from "@toadaid/agent-capabilities/contracts";
import {
  createReplayFence,
  createReplayRetryAuthorization,
  openReplayReconciliation,
  resolveReplayReconciliation,
} from "@toadaid/agent-capabilities/replay";
import {
  assertFreshBrowserDom,
  assessBrowserNavigationReadiness,
  beginBrowserNavigation,
  createBrowserResilienceState,
  recordBrowserCaptureFailure,
  recordFreshBrowserDom,
} from "@toadaid/agent-capabilities/browser-resilience";

function sha(value) {
  return createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
}
function t(second) {
  return new Date(Date.parse("2026-09-25T12:00:00.000Z") + second * 1000).toISOString();
}
function zeroBudget() {
  return { modelRequests: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, networkRequests: 0, retries: 0, wallClockMs: 0, childTasks: 0 };
}

const hostProviderDescriptor = {
  schemaVersion: "toadaid.capability-contract.v1",
  capabilityId: "host:notification",
  contractId: HOST_SERVICE_CONTRACT_IDS["host:notification"],
  version: { major: 1, minor: 0 },
  features: [],
  requestSchemaId: "toadaid.host.notification.request.v1",
  receiptSchemaId: "toadaid.host.notification.receipt.v1",
  implementation: {
    implementationId: "v1-specialized-host-notification",
    fingerprintSha256: sha("v1-specialized-host-notification"),
  },
};
const hostProviderRegistration = {
  schemaVersion: "toadaid.host-service-adapter-registration.v1",
  adapterId: "v1-specialized-host-notification",
  capabilityId: "host:notification",
  toolName: HOST_SERVICE_TOOL_NAMES["host:notification"],
  contractId: hostProviderDescriptor.contractId,
  descriptorSha256: capabilityContractDescriptorSha256(hostProviderDescriptor),
  implementationFingerprintSha256:
    hostProviderDescriptor.implementation.fingerprintSha256,
};
const specializedHostProvider = {
  registration: hostProviderRegistration,
  async invoke(request) {
    return {
      schemaVersion: "toadaid.host-service-adapter-result.v1",
      operationId: request.operationId,
      hostId: request.hostId,
      sessionId: request.sessionId,
      capabilityId: request.capabilityId,
      evidenceSha256: sha(request.operationId),
    };
  },
};
const hostProviderManifest = createCapabilityModuleManifest({
  moduleId: "v1.specialized-host-provider",
  version: "1.0.0",
  capabilities: [{
    id: "host:notification",
    description: "Clean-room specialized host notification provider.",
    defaultDecision: "BLOCK",
  }],
  contractDescriptors: [hostProviderDescriptor],
  adapters: [specializedHostProvider.registration],
});
const hostProviderEnabled = enableCapabilityModule(
  installCapabilityModule(hostProviderManifest, { installedAt: t(0) }),
  t(1),
);
const hostProviderSelection = createCapabilityProviderSelection(
  hostProviderEnabled,
  specializedHostProvider.registration.adapterId,
);
const hostProviderRegistry = composeCapabilityProviderRegistry({
  modules: [hostProviderEnabled],
  selections: [hostProviderSelection],
});
const resolvedHostProvider = resolveCapabilityProvider(
  hostProviderRegistry,
  "host:notification",
  HOST_SERVICE_TOOL_NAMES["host:notification"],
  "HOST_SERVICE",
);
assert.equal(
  resolvedHostProvider.adapterRegistrationSha256,
  hostProviderSelection.adapterRegistrationSha256,
);
assert.deepEqual(resolvedHostProvider.registration, specializedHostProvider.registration);
const hostRuntimeRegistry = composeCapabilityRuntimeProviderRegistry(
  hostProviderRegistry,
  [hostProviderEnabled],
  [{
    moduleId: hostProviderManifest.moduleId,
    provider: specializedHostProvider,
  }],
);
assert.equal(
  resolveCapabilityRuntimeProvider(
    hostRuntimeRegistry,
    hostProviderRegistry,
    "host:notification",
    HOST_SERVICE_TOOL_NAMES["host:notification"],
    "HOST_SERVICE",
  ),
  specializedHostProvider,
);

const resolvedRoot = fileURLToPath(import.meta.resolve("@toadaid/agent-capabilities"));
assert.match(resolvedRoot, /node_modules[\\/]@toadaid[\\/]agent-capabilities[\\/]dist[\\/]src[\\/]index\.js$/);

const policyLayers = [{
  scope: "agent",
  subject: "v1-agent0",
  decisions: {
    "browser:evidence": "ALLOW",
    "review:fix": "ALLOW",
    "interrupt:create": "ALLOW",
    "interrupt:resolve": "ALLOW",
    "secret:lease": "ALLOW",
    "secret:materialize": "ALLOW",
  },
}];
const capabilityIds = Object.keys(policyLayers[0].decisions);
const authority = (id, layers = policyLayers) => resolveCapabilityAuthority(id, CORE_CAPABILITY_MANIFEST, layers);
const currentAuthority = capabilityIds.map((id) => authority(id));

const rootRun = createRunStateCapsule({
  runId: "v1-root",
  createdAt: t(0),
  objective: { summary: "Prove Agent0 vertical capability continuity", status: "ACTIVE" },
  phase: "PLAN",
  authoritySnapshot: { capturedAt: t(0), decisions: currentAuthority },
  work: { pending: [{ id: "vertical", summary: "Complete deterministic graduation proof" }] },
});

const browserDescriptor = {
  schemaVersion: "toadaid.capability-contract.v1",
  capabilityId: "browser:evidence",
  contractId: "toadaid.browser-evidence.v1",
  version: { major: 1, minor: 0 },
  features: ["evidence.capture"],
  requestSchemaId: "toadaid.browser-evidence.request.v1",
  receiptSchemaId: "toadaid.browser-evidence.receipt.v1",
  implementation: {
    implementationId: "v1-agent0-browser-evidence",
    fingerprintSha256: sha("v1-browser-evidence-implementation"),
  },
};
const browserRequirement = {
  capabilityId: "browser:evidence",
  contractId: "toadaid.browser-evidence.v1",
  major: 1,
  minMinor: 0,
  requiredFeatures: ["evidence.capture"],
};
const registry = createCapabilityContractRegistry([browserDescriptor]);
const recipe = {
  schemaVersion: "toadaid.governed-recipe.v1",
  recipeId: "v1-proof",
  version: "1.0.0",
  description: "Deterministic clean-room Agent0 graduation recipe",
  parameters: {
    url: { schema: { type: "STRING", minLength: 1, maxLength: 512 }, required: true },
  },
  responseSchema: {
    type: "OBJECT",
    properties: { status: { type: "STRING", enum: ["DEGRADED", "OK"] } },
    required: ["status"],
  },
  maxTurns: 8,
  maxRetries: 1,
  capabilities: {
    required: ["browser:evidence"],
    forbidden: ["review:fix"],
  },
  steps: [{ id: "capture", summary: "Capture bounded browser evidence", capabilityId: "browser:evidence", onUnavailable: "FAIL" }],
};
const contractProfile = {
  schemaVersion: "toadaid.recipe-contract-profile.v1",
  recipeId: recipe.recipeId,
  recipeVersion: recipe.version,
  requirements: [browserRequirement],
};
const recipeOptions = {
  manifest: CORE_CAPABILITY_MANIFEST,
  policyLayers,
  compiledAt: t(1),
  contractRegistry: registry,
  contractProfile,
};
const plan = compileGovernedRecipeWithContracts(recipe, { url: "https://example.test/start?secret=drop#fragment" }, recipeOptions);
assert.deepEqual(plan.basePlan.effectiveCapabilities, ["browser:evidence"]);
assert.ok(!plan.basePlan.effectiveCapabilities.includes("review:fix"));
assertContractBoundRecipePlanCurrent(plan, recipe, recipeOptions);

const parentBrowserAuthority = resolveResumeCapabilityAuthority("browser:evidence", rootRun, currentAuthority);
assert.equal(parentBrowserAuthority.decision, "ALLOW");
const childRun0 = createRunStateCapsule({
  runId: "v1-child",
  createdAt: t(2),
  objective: { summary: "Execute bounded browser evidence step", status: "ACTIVE" },
  phase: "CREATED",
  authoritySnapshot: { capturedAt: t(2), decisions: [authority("browser:evidence")] },
  work: { pending: [{ id: "capture", summary: "Capture bounded browser evidence" }] },
});
let childTask = createChildTask({
  childTaskId: "v1-child",
  parentRunId: rootRun.runId,
  createdAt: t(2),
  delegatedCapabilities: ["browser:evidence"],
  parentAuthority: [parentBrowserAuthority],
  runState: childRun0,
});
const childRun1 = checkpointRunStateCapsule(childRun0, { updatedAt: t(3), reason: "CHECKPOINT", phase: "EXECUTING" });
childTask = transitionChildTask(childTask, { kind: "START", updatedAt: t(3), runState: childRun1 });
assert.equal(childTask.status, "RUNNING");

const rootBudget0 = createRunBudgetLedger({
  budgetId: "v1-root-budget",
  runId: rootRun.runId,
  createdAt: t(0),
  limits: { modelRequests: 10, inputTokens: 10000, outputTokens: 5000, toolCalls: 10, networkRequests: 10, retries: 5, wallClockMs: 60000, childTasks: 2 },
});
const allocated = allocateChildRunBudget(rootBudget0, {
  allocationId: "v1-child-allocation",
  childBudgetId: "v1-child-budget",
  childRunId: childRun0.runId,
  childTaskId: childTask.childTaskId,
  allocatedAt: t(2),
  limits: { modelRequests: 2, inputTokens: 2000, outputTokens: 1000, toolCalls: 4, networkRequests: 4, retries: 2, wallClockMs: 10000, childTasks: 0 },
});
assert.equal(allocated.child.record.parentBinding?.allocationId, "v1-child-allocation");

let invocation = createCapabilityInvocation({
  invocationId: "v1-browser-invocation",
  runId: childRun0.runId,
  childTaskId: childTask.childTaskId,
  capabilityId: "browser:evidence",
  toolName: "browser.evidence.capture",
  intentSha256: sha("capture bounded evidence for graduation proof"),
  argumentsSha256: sha({ url: plan.basePlan.inputs.url }),
  createdAt: t(4),
});
invocation = authorizeCapabilityInvocation(invocation, { manifest: CORE_CAPABILITY_MANIFEST, policyLayers }, { now: () => new Date(t(4)) });
assert.equal(invocation.record.status, "AUTHORIZED");
const contractBinding = createCapabilityInvocationContractBinding(invocation, browserRequirement, registry);
const contractReady = assertCapabilityInvocationContractReady(contractBinding, invocation, browserRequirement, registry);
assert.equal(contractReady.compatibility.compatible, true);
const readFence = createReplayFence(invocation, { replayClass: "SAFE_READ", createdAt: t(4) });
invocation = startCapabilityInvocation(invocation, "v1-runtime", { manifest: CORE_CAPABILITY_MANIFEST, policyLayers }, { now: () => new Date(t(5)) });
assert.equal(invocation.record.status, "STARTED");
assert.equal(readFence.record.binding.invocationId, invocation.record.invocationId);

const startUrl = "https://example.test/start?secret=drop#fragment";
const nextUrl = "https://example.test/next?token=drop#state";
let resilience = createBrowserResilienceState(startUrl);
const fresh = recordFreshBrowserDom(resilience, {
  title: "V1 Fixture",
  textExcerpt: "bounded deterministic browser evidence",
  headings: [{ level: 1, text: "Graduation" }],
  interactiveElements: [{ tag: "a", role: null, ariaLabel: null, text: "Next", href: nextUrl, type: null, name: null }],
}, startUrl, { maxTextChars: 1000, maxHeadings: 10, maxInteractiveElements: 10 });
resilience = beginBrowserNavigation(fresh.state, nextUrl);
assert.throws(() => assertFreshBrowserDom(resilience, fresh.token, nextUrl), /stale DOM refused/);
const readiness = assessBrowserNavigationReadiness(resilience, {
  beforeUrl: startUrl,
  afterUrl: nextUrl,
  navigationKind: "FULL_DOCUMENT",
  domContentLoaded: false,
  timedOut: true,
  pageClosed: false,
});
assert.equal(readiness.decision, "DEGRADED");
const degraded = recordBrowserCaptureFailure(resilience, {
  phase: "capture",
  reason: "NAVIGATION_TIMEOUT",
  errorFingerprintSha256: sha("deterministic navigation timeout"),
  lastKnownUrl: nextUrl,
}, { now: () => new Date(t(6)) });
assert.equal(degraded.receipt.status, "DEGRADED");
assert.equal(degraded.receipt.staleDomRefused, true);
assert.equal(degraded.receipt.lastKnownUrl, "https://example.test/next");
const degradedSha = sha(degraded.receipt);
invocation = completeCapabilityInvocation(invocation, "v1-runtime", degradedSha, [{ id: "browser-degraded", sha256: degradedSha }], { now: () => new Date(t(7)) });
assert.equal(invocation.record.status, "COMPLETED");
assert.equal(assessCapabilityInvocationResume(invocation, { manifest: CORE_CAPABILITY_MANIFEST, policyLayers }, { now: () => new Date(t(8)) }).decision, "TERMINAL");

let childBudget = recordRunBudgetUsage(allocated.child, {
  receiptId: "v1-browser-cost",
  kind: "TOOL",
  occurredAt: t(7),
  invocationId: invocation.record.invocationId,
  sourceSha256: degradedSha,
  delta: { ...zeroBudget(), toolCalls: 1, networkRequests: 1, wallClockMs: 500 },
});
const budgetSerialized = serializeRunBudgetLedger(childBudget);
childBudget = parseRunBudgetLedger(budgetSerialized);
assert.equal(childBudget.recordSha256, parseRunBudgetLedger(budgetSerialized).recordSha256);
assert.equal(remainingRunBudget(childBudget).toolCalls, 3);
assert.equal(remainingRunBudget(childBudget).networkRequests, 3);

const childRun2 = checkpointRunStateCapsule(childRun1, {
  updatedAt: t(8),
  reason: "CHECKPOINT",
  objective: { summary: "Execute bounded browser evidence step", status: "COMPLETE" },
  phase: "COMPLETE",
  work: { completed: [{ id: "capture", summary: "Captured degraded bounded evidence" }], pending: [], blocked: [] },
  evidenceRefs: [{ id: "browser-degraded", locator: "v1://browser/degraded", sha256: degradedSha }],
});
childTask = transitionChildTask(childTask, { kind: "COMPLETE", updatedAt: t(8), runState: childRun2 });
assert.equal(childTask.status, "COMPLETE");
assert.equal(parseChildTask(serializeChildTask(childTask)).status, "COMPLETE");

// X1: uncertain mutation must never become a blind replay.
let mutation = createCapabilityInvocation({
  invocationId: "v1-nonreplayable-invocation",
  runId: rootRun.runId,
  capabilityId: "review:fix",
  toolName: "review.fix.simulated",
  intentSha256: sha("simulate a mutation boundary without executing it"),
  argumentsSha256: sha({ dryRun: true }),
  createdAt: t(9),
});
mutation = authorizeCapabilityInvocation(mutation, { manifest: CORE_CAPABILITY_MANIFEST, policyLayers }, { now: () => new Date(t(9)) });
const mutationFence = createReplayFence(mutation, { replayClass: "NON_REPLAYABLE", createdAt: t(9) });
mutation = startCapabilityInvocation(mutation, "v1-runtime", { manifest: CORE_CAPABILITY_MANIFEST, policyLayers }, { now: () => new Date(t(10)) });
let reconciliation = openReplayReconciliation(mutationFence, mutation, {
  reconciliationId: "v1-mutation-reconcile",
  reasonCode: "TRANSPORT_TIMEOUT",
  evidenceRefs: [{ id: "timeout", sha256: sha("transport timeout") }],
  openedAt: t(11),
});
reconciliation = resolveReplayReconciliation(reconciliation, {
  finding: "CONFIRMED_NOT_EXECUTED",
  proofSha256: sha("provider state proves no mutation occurred"),
  proofRefs: [{ id: "provider-state", sha256: sha("no mutation") }],
  resolvedAt: t(12),
});
assert.equal(reconciliation.record.disposition, "NEW_INVOCATION_REQUIRED");
assert.throws(() => createReplayRetryAuthorization(mutationFence, reconciliation, mutation, { now: () => new Date(t(12)) }), /does not authorize replay|NON_REPLAYABLE/);
mutation = failCapabilityInvocation(mutation, "v1-runtime", "REPLAY_REFUSED", sha("non-replayable invocation requires new identity"), [{ id: "reconciliation", sha256: reconciliation.recordSha256 }], { now: () => new Date(t(13)) });
assert.equal(parseCapabilityInvocation(serializeCapabilityInvocation(mutation)).record.status, "FAILED");

// P10: human response is typed data, bound to one exact P4 state.
const createInterruptAuthority = authority("interrupt:create");
const resolveInterruptAuthority = authority("interrupt:resolve");
const interruptOpen = createHumanInterrupt({
  interruptId: "v1-human-interrupt",
  createdAt: t(14),
  reason: "DECISION_REQUIRED",
  prompt: "Continue the deterministic graduation proof?",
  responseSchema: { type: "object", properties: { continue: { type: "boolean" } }, required: ["continue"], additionalProperties: false },
}, rootRun, createInterruptAuthority);
const driftedRoot = checkpointRunStateCapsule(rootRun, { updatedAt: t(15), reason: "CHECKPOINT", phase: "DRIFTED_FOR_REFUSAL_TEST" });
assert.throws(() => resolveHumanInterrupt(interruptOpen, { responderId: "operator", resolvedAt: t(15), response: { continue: true } }, driftedRoot, resolveInterruptAuthority), /run-state binding mismatch/);
const interruptResolved = resolveHumanInterrupt(interruptOpen, { responderId: "operator", resolvedAt: t(15), response: { continue: true } }, rootRun, resolveInterruptAuthority);
const interruptProof = createHumanInterruptResumeProof(interruptResolved, rootRun, t(16));
assert.equal(interruptProof.runRevision, rootRun.revision);

// P11: opaque handle only; grant is still useless after current authority is revoked.
const rawSecretSentinel = "RAW_SECRET_MUST_NEVER_ENTER_AGENT_STATE";
const opaqueHandle = `secret-ref:${"01".repeat(32)}`;
assert.notEqual(opaqueHandle.slice("secret-ref:".length), sha(rawSecretSentinel));
const target = { kind: "ENV", name: "V1_BROWSER_TOKEN" };
const lease = createSecretLease({
  leaseId: "v1-secret-lease",
  ownerId: "v1-agent0",
  providerId: "fixture-provider",
  profileId: "default",
  secretHandle: opaqueHandle,
  allowedCapabilities: ["browser:evidence"],
  allowedTargets: [target],
  createdAt: t(14),
  ttlMs: 600000,
}, authority("secret:lease"));
const grant = createSecretMaterializationGrant(lease, {
  materializationId: "v1-materialization",
  ownerId: "v1-agent0",
  providerId: "fixture-provider",
  profileId: "default",
  forCapabilityId: "browser:evidence",
  target,
  issuedAt: t(16),
  ttlMs: 60000,
}, { materialize: authority("secret:materialize"), consumer: authority("browser:evidence") }, { now: () => new Date(t(16)) });
const usableGrant = assertSecretMaterializationGrantUsable(grant, lease, { materialize: authority("secret:materialize"), consumer: authority("browser:evidence") }, { now: () => new Date(t(17)) });
assert.equal(usableGrant.secretHandle, opaqueHandle);
assert.doesNotMatch(JSON.stringify({ lease, grant }), new RegExp(rawSecretSentinel));
const revokeSecretLayers = [...policyLayers, { scope: "session", subject: "v1-secret-revoked", decisions: { "secret:materialize": "BLOCK" } }];
assert.throws(() => assertSecretMaterializationGrantUsable(grant, lease, {
  materialize: authority("secret:materialize", revokeSecretLayers),
  consumer: authority("browser:evidence", revokeSecretLayers),
}, { now: () => new Date(t(17)) }), /not authorized/);

// P4 restart: same identity/evidence, current policy still sovereign.
const rootCheckpoint = checkpointRunStateCapsule(rootRun, {
  updatedAt: t(18),
  reason: "CHECKPOINT",
  phase: "READY_TO_RESUME",
  evidenceRefs: [
    { id: "browser-degraded", locator: "v1://browser/degraded", sha256: degradedSha },
    { id: "human-resume", locator: "v1://human/resume", sha256: sha(interruptProof) },
    { id: "child-task", locator: "v1://child/task", sha256: childTaskSha256(childTask) },
  ],
  artifactRefs: [{ id: "recipe-plan", locator: "v1://recipe/plan", sha256: plan.planSha256 }],
  work: { completed: [{ id: "vertical", summary: "Completed deterministic graduation proof" }], pending: [], blocked: [] },
});
const checkpointSha = runStateCapsuleSha256(rootCheckpoint);
const resumed = resumeRunStateCapsule(serializeRunStateCapsule(rootCheckpoint), t(19));
assert.equal(resumed.runId, rootRun.runId);
assert.equal(resumed.continuity.reason, "RESTART");
assert.equal(resumed.continuity.previousCapsuleSha256, checkpointSha);
const resumeAllowed = resolveResumeCapabilityAuthority("browser:evidence", resumed, currentAuthority);
assert.equal(resumeAllowed.decision, "ALLOW");
const revokeBrowserLayers = [...policyLayers, { scope: "session", subject: "v1-browser-revoked", decisions: { "browser:evidence": "BLOCK" } }];
const browserRevoked = authority("browser:evidence", revokeBrowserLayers);
assert.equal(resolveResumeCapabilityAuthority("browser:evidence", resumed, [browserRevoked]).decision, "BLOCK");
assert.throws(() => assertContractBoundRecipePlanCurrent(plan, recipe, { ...recipeOptions, policyLayers: revokeBrowserLayers, compiledAt: t(19) }), /no longer authorized/);

const summary = Object.freeze({
  schemaVersion: "toadaid.v1-agent0-vertical-proof.v1",
  packageResolvedFromConsumer: true,
  runId: resumed.runId,
  runRevisionAfterRestart: resumed.revision,
  recipePlanSha256: plan.planSha256,
  childTaskSha256: childTaskSha256(childTask),
  browserInvocationSha256: invocation.recordSha256,
  degradedEvidenceSha256: degradedSha,
  budgetLedgerSha256: childBudget.recordSha256,
  humanResumeProofSha256: sha(interruptProof),
  secretHandleOnly: usableGrant.secretHandle === opaqueHandle,
  nonReplayableDisposition: reconciliation.record.disposition,
  browserRevocationAfterRestart: "BLOCK",
});
console.log(`V1_AGENT0_VERTICAL_OK ${JSON.stringify(summary)}`);
