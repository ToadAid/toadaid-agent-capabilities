import assert from "node:assert/strict";
import test from "node:test";

import { createCapabilityManifest, type CapabilityPolicyLayer } from "../src/capabilityPolicy.js";
import {
  assertGovernedRecipePlanCurrent,
  compileGovernedRecipe,
  governedRecipePlanSha256,
  governedRecipeSha256,
  validateGovernedRecipePlanIntegrity,
  normalizeGovernedRecipeDefinition,
  validateGovernedRecipeResult,
  type GovernedRecipeDefinition,
} from "../src/recipeCompiler.js";

const manifest = createCapabilityManifest([
  { id: "review:inspect", description: "review", defaultDecision: "BLOCK" },
  { id: "workspace:snapshot", description: "snapshot", defaultDecision: "BLOCK" },
  { id: "review:fix", description: "fix", defaultDecision: "BLOCK" },
  { id: "web:extract", description: "extract", defaultDecision: "BLOCK" },
]);

const allow = (...ids: string[]): readonly CapabilityPolicyLayer[] => [{
  scope: "agent",
  subject: "agent0",
  decisions: Object.fromEntries(ids.map((id) => [id, "ALLOW"])) as Record<string, "ALLOW">,
}];

const recipe = (): GovernedRecipeDefinition => ({
  schemaVersion: "toadaid.governed-recipe.v1",
  recipeId: "review-and-snapshot",
  version: "1.0.0",
  description: "Review a bounded change set and optionally capture web evidence.",
  parameters: {
    target: { schema: { type: "STRING", minLength: 1, maxLength: 120 }, required: true },
    attempts: { schema: { type: "INTEGER", minimum: 1, maximum: 3 }, default: 1 },
  },
  responseSchema: {
    type: "OBJECT",
    properties: {
      verdict: { type: "STRING", enum: ["PASS", "FAIL"] },
      count: { type: "INTEGER", minimum: 0, maximum: 100 },
    },
    required: ["verdict"],
  },
  maxTurns: 24,
  maxRetries: 2,
  capabilities: {
    required: ["review:inspect", "workspace:snapshot"],
    optional: ["web:extract"],
    forbidden: ["review:fix"],
  },
  steps: [
    { id: "snapshot", summary: "Capture workspace snapshot", capabilityId: "workspace:snapshot", onUnavailable: "FAIL" },
    { id: "review", summary: "Review changes", capabilityId: "review:inspect", onUnavailable: "FAIL" },
    { id: "web-context", summary: "Collect optional web context", capabilityId: "web:extract", onUnavailable: "SKIP" },
  ],
});

test("compiles required capabilities and skips unavailable optional capability", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot", "review:fix"),
    compiledAt: "2026-09-25T02:10:00.000Z",
  });
  assert.deepEqual(plan.effectiveCapabilities, ["review:inspect", "workspace:snapshot"]);
  assert.equal(plan.steps.find((step) => step.id === "web-context")?.status, "SKIPPED_OPTIONAL");
  assert.equal(plan.inputs.attempts, 1);
});

test("required capability denial fails closed", () => {
  assert.throws(() => compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect"),
  }), /workspace:snapshot/);
});

test("optional capability becomes enabled only when current policy allows it", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD", attempts: 2 }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot", "web:extract"),
  });
  assert.equal(plan.steps.find((step) => step.id === "web-context")?.status, "ENABLED");
  assert.equal(plan.effectiveCapabilities.includes("web:extract"), true);
});

test("forbidden capability never enters effective set even when ambient policy allows it", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot", "review:fix"),
  });
  assert.equal(plan.effectiveCapabilities.includes("review:fix"), false);
  assert.equal(plan.capabilityEvidence.find((row) => row.capabilityId === "review:fix")?.compileDecision, "FORBIDDEN");
});

test("recipe definition rejects overlapping capability roles", () => {
  const broken = recipe();
  assert.throws(() => normalizeGovernedRecipeDefinition({
    ...broken,
    capabilities: { required: ["review:inspect"], forbidden: ["review:inspect"] },
  }), /both required and forbidden/);
});

test("step cannot use undeclared capability", () => {
  const broken = recipe();
  assert.throws(() => normalizeGovernedRecipeDefinition({
    ...broken,
    steps: [{ id: "bad", summary: "bad", capabilityId: "review:fix", onUnavailable: "FAIL" }],
  }), /not declared required\/optional/);
});

test("required steps must fail and optional steps must skip when unavailable", () => {
  const broken = recipe();
  assert.throws(() => normalizeGovernedRecipeDefinition({
    ...broken,
    steps: [{ id: "bad", summary: "bad", capabilityId: "web:extract", onUnavailable: "FAIL" }],
  }), /optional capability step/);
});

test("undeclared parameters are refused and required parameter is enforced", () => {
  assert.throws(() => compileGovernedRecipe(recipe(), { target: "HEAD", surprise: true }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  }), /undeclared parameter/);
  assert.throws(() => compileGovernedRecipe(recipe(), {}, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  }), /missing required parameter/);
});

test("bounded result schema accepts declared fields and refuses undeclared fields", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  });
  assert.deepEqual(validateGovernedRecipeResult(plan, { verdict: "PASS", count: 2 }), { verdict: "PASS", count: 2 });
  assert.throws(() => validateGovernedRecipeResult(plan, { verdict: "PASS", note: "extra" }), /undeclared field/);
});

test("turn and retry ceilings are bounded", () => {
  const broken = recipe();
  assert.throws(() => normalizeGovernedRecipeDefinition({ ...broken, maxTurns: 999 }), /maxTurns/);
  assert.throws(() => normalizeGovernedRecipeDefinition({ ...broken, maxRetries: 99 }), /maxRetries/);
});

test("recipe hash is deterministic across capability ordering", () => {
  const a = recipe();
  const b = { ...recipe(), capabilities: { required: ["workspace:snapshot", "review:inspect"], optional: ["web:extract"], forbidden: ["review:fix"] } };
  assert.equal(governedRecipeSha256(a), governedRecipeSha256(b));
});

test("current authority check refuses revoked enabled capability", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot", "web:extract"),
  });
  assert.throws(() => assertGovernedRecipePlanCurrent(plan, recipe(), {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  }), /web:extract/);
});

test("newly allowed optional capability does not silently widen an old plan", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  });
  const receipt = assertGovernedRecipePlanCurrent(plan, recipe(), {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot", "web:extract"),
  });
  assert.equal(receipt.checks.find((row) => row.capabilityId === "web:extract")?.compiledEnabled, false);
  assert.equal(plan.steps.find((step) => step.id === "web-context")?.status, "SKIPPED_OPTIONAL");
});


test("compiled recipe plan is SHA-256 tamper-evident", () => {
  const plan = compileGovernedRecipe(recipe(), { target: "HEAD" }, {
    manifest,
    policyLayers: allow("review:inspect", "workspace:snapshot"),
  });
  assert.equal(governedRecipePlanSha256(plan), plan.planSha256);
  const tampered = { ...plan, effectiveCapabilities: [...plan.effectiveCapabilities, "web:extract"] };
  assert.throws(() => validateGovernedRecipePlanIntegrity(tampered), /integrity mismatch/);
});
