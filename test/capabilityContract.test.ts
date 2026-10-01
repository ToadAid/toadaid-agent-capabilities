import test from "node:test";
import assert from "node:assert/strict";
import { createCapabilityManifest } from "../src/capabilityPolicy.js";
import {
  assertCapabilityContractCompatible,
  assertCapabilityInvocationContractReady,
  assertContractBoundRecipePlanCurrent,
  CapabilityContractCompatibilityError,
  compileGovernedRecipeWithContracts,
  createCapabilityContractRegistry,
  createCapabilityInvocationContractBinding,
  discoverCapabilityContracts,
} from "../src/capabilityContract.js";
import type { CapabilityContractDescriptor, CapabilityContractRequirement } from "../src/capabilityContract.js";
import type { CapabilityInvocationEnvelope, CapabilityInvocationStatus } from "../src/invocationTypes.js";
import type { GovernedRecipeDefinition } from "../src/recipeTypes.js";

const A = "a".repeat(64);
const B = "b".repeat(64);
const C = "c".repeat(64);

const descriptor = (patch: Partial<CapabilityContractDescriptor> = {}): CapabilityContractDescriptor => ({
  schemaVersion: "toadaid.capability-contract.v1",
  capabilityId: "browser:evidence",
  contractId: "toadaid.browser.evidence",
  version: { major: 1, minor: 3 },
  features: ["dom.bounded", "screenshot.sha256"],
  requestSchemaId: "toadaid.browser.evidence.request.v1",
  receiptSchemaId: "toadaid.browser.evidence.receipt.v1",
  implementation: { implementationId: "browser-evidence", fingerprintSha256: A },
  ...patch,
});

const requirement = (patch: Partial<CapabilityContractRequirement> = {}): CapabilityContractRequirement => ({
  capabilityId: "browser:evidence",
  contractId: "toadaid.browser.evidence",
  major: 1,
  minMinor: 2,
  requiredFeatures: ["dom.bounded"],
  ...patch,
});

const recipe = (): GovernedRecipeDefinition => ({
  schemaVersion: "toadaid.governed-recipe.v1",
  recipeId: "observe-page",
  version: "1",
  description: "Observe a page",
  responseSchema: { type: "BOOLEAN" },
  maxTurns: 4,
  maxRetries: 1,
  capabilities: { required: ["browser:evidence"] },
  steps: [{ id: "observe", summary: "Observe", capabilityId: "browser:evidence", onUnavailable: "FAIL" }],
});

const options = (registry: ReturnType<typeof createCapabilityContractRegistry>) => ({
  manifest: createCapabilityManifest([{ id: "browser:evidence", description: "test", defaultDecision: "BLOCK" }]),
  policyLayers: [{ scope: "agent" as const, subject: "agent0", decisions: { "browser:evidence": "ALLOW" as const } }],
  compiledAt: "2026-09-25T04:00:00.000Z",
  contractRegistry: registry,
  contractProfile: { schemaVersion: "toadaid.recipe-contract-profile.v1" as const, recipeId: "observe-page", recipeVersion: "1", requirements: [requirement()] },
});

const invocation = (status: CapabilityInvocationStatus = "AUTHORIZED", intent = B): CapabilityInvocationEnvelope => ({
  schemaVersion: "toadaid.capability-invocation-envelope.v1",
  recordSha256: C,
  record: {
    schemaVersion: "toadaid.capability-invocation.v1",
    invocationId: "inv-1", revision: 1, status, runId: "run-1", childTaskId: null,
    capabilityId: "browser:evidence", toolName: "capture", externalToolCallId: null,
    createdAt: "2026-09-25T04:00:00.000Z", updatedAt: "2026-09-25T04:00:01.000Z",
    request: { intentSha256: intent, argumentsSha256: null }, authorization: null, start: null,
    cancellation: null, outcome: null, continuity: { previousRecordSha256: null },
  },
});

test("registry discovery is deterministic", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  assert.equal(discoverCapabilityContracts(registry).registrySha256, registry.registrySha256);
});

test("exact major, minimum minor, and required features are enforced", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  assert.equal(assertCapabilityContractCompatible(registry, requirement()).compatible, true);
  assert.throws(() => assertCapabilityContractCompatible(registry, requirement({ major: 2 })), (error: unknown) => error instanceof CapabilityContractCompatibilityError && error.reason === "MAJOR_VERSION_MISMATCH");
  assert.throws(() => assertCapabilityContractCompatible(registry, requirement({ minMinor: 4 })), /MINOR_VERSION_TOO_OLD/);
  assert.throws(() => assertCapabilityContractCompatible(registry, requirement({ requiredFeatures: ["xhr.capture"] })), /MISSING_REQUIRED_FEATURE/);
});

test("deprecated contracts refuse unless explicitly accepted", () => {
  const registry = createCapabilityContractRegistry([descriptor({ deprecation: { sinceVersion: { major: 1, minor: 3 } } })]);
  assert.throws(() => assertCapabilityContractCompatible(registry, requirement()), /DEPRECATED_CONTRACT/);
  assert.equal(assertCapabilityContractCompatible(registry, requirement({ allowDeprecated: true })).compatible, true);
});

test("contract-aware W1 compile binds descriptor provenance", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  const plan = compileGovernedRecipeWithContracts(recipe(), {}, options(registry));
  assert.equal(plan.contractBindings.length, 1);
  assert.equal(plan.basePlan.effectiveCapabilities[0], "browser:evidence");
});

test("changed implementation descriptor requires W1 recompile", () => {
  const first = createCapabilityContractRegistry([descriptor()]);
  const plan = compileGovernedRecipeWithContracts(recipe(), {}, options(first));
  const changed = createCapabilityContractRegistry([descriptor({ implementation: { implementationId: "browser-evidence", fingerprintSha256: B } })]);
  assert.throws(() => assertContractBoundRecipePlanCurrent(plan, recipe(), { ...options(changed), compiledAt: "2026-09-25T04:05:00.000Z" }), /descriptor changed; recompile required/);
});

test("contract-bound W1 plan still obeys P3 revocation", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  const plan = compileGovernedRecipeWithContracts(recipe(), {}, options(registry));
  const revoked = { ...options(registry), policyLayers: [{ scope: "agent" as const, subject: "agent0", decisions: { "browser:evidence": "BLOCK" as const } }], compiledAt: "2026-09-25T04:05:00.000Z" };
  assert.throws(() => assertContractBoundRecipePlanCurrent(plan, recipe(), revoked), /no longer authorized/);
});

test("H1 binding requires AUTHORIZED invocation and stable intent", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  const binding = createCapabilityInvocationContractBinding(invocation(), requirement(), registry);
  assert.equal(assertCapabilityInvocationContractReady(binding, invocation(), requirement(), registry).invocationId, "inv-1");
  assert.throws(() => assertCapabilityInvocationContractReady(binding, invocation("REQUESTED"), requirement(), registry), /must be AUTHORIZED/);
  assert.throws(() => assertCapabilityInvocationContractReady(binding, invocation("AUTHORIZED", C), requirement(), registry), /identity\/intent/);
});

test("tampered registry hash is refused", () => {
  const registry = createCapabilityContractRegistry([descriptor()]);
  assert.throws(() => discoverCapabilityContracts({ ...registry, registrySha256: B }), /registry integrity mismatch/);
});
