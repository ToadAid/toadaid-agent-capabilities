import assert from "node:assert/strict";
import test from "node:test";

import type { CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  createLoopBreakerState,
  fingerprintLoopObservation,
  recordLoopObservation,
  repairToolCallSyntax,
} from "../src/loopBreaker.js";

function repairAuthority(
  decision: "ALLOW" | "BLOCK" = "ALLOW",
  capabilityId = "runtime:bounded-repair",
): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision,
    reason: decision === "ALLOW" ? "AUTHORIZED_BY_POLICY" : "BLOCKED_BY_POLICY",
    trace: [],
  };
}

test("repeated equivalent model failures halt after the configured bound", () => {
  let state = createLoopBreakerState();
  for (const payload of [" brain   came back empty ", "brain\ncame back empty"]) {
    ({ state } = recordLoopObservation(state, {
      kind: "MODEL_OUTPUT",
      outcome: "FAILURE",
      payload,
    }));
  }

  const result = recordLoopObservation(state, {
    kind: "MODEL_OUTPUT",
    outcome: "FAILURE",
    payload: "brain came back empty",
  });

  assert.equal(result.decision.decision, "HALT");
  assert.equal(result.decision.reason, "REPEATED_FINGERPRINT");
  assert.equal(result.state.consecutiveIdentical, 3);
  assert.equal("payload" in result.state.history[0]!, false);
});

test("halted state is sticky and cannot be revived by a later success", () => {
  let state = createLoopBreakerState();
  for (let index = 0; index < 3; index += 1) {
    ({ state } = recordLoopObservation(state, {
      kind: "EMPTY_OUTPUT",
      outcome: "FAILURE",
      payload: "",
    }));
  }

  const result = recordLoopObservation(state, {
    kind: "MODEL_OUTPUT",
    outcome: "SUCCESS",
    payload: "recovered",
  });
  assert.equal(result.decision.reason, "ALREADY_HALTED");
  assert.equal(result.state, state);
});

test("distinct consecutive failures halt independently of fingerprint repetition", () => {
  let state = createLoopBreakerState();
  for (let index = 0; index < 4; index += 1) {
    ({ state } = recordLoopObservation(state, {
      kind: "TOOL_FAILURE",
      outcome: "FAILURE",
      payload: `failure-${index}`,
    }));
  }

  const result = recordLoopObservation(state, {
    kind: "TOOL_FAILURE",
    outcome: "FAILURE",
    payload: "failure-4",
  });
  assert.equal(result.decision.reason, "CONSECUTIVE_FAILURES");
});

test("success resets the consecutive-failure counter", () => {
  let state = createLoopBreakerState();
  ({ state } = recordLoopObservation(state, {
    kind: "TOOL_FAILURE",
    outcome: "FAILURE",
    payload: "failed",
  }));
  ({ state } = recordLoopObservation(state, {
    kind: "MODEL_OUTPUT",
    outcome: "SUCCESS",
    payload: "ok",
  }));
  assert.equal(state.consecutiveFailures, 0);
});

test("model output fingerprints normalize presentation whitespace", () => {
  assert.equal(
    fingerprintLoopObservation({ kind: "MODEL_OUTPUT", outcome: "FAILURE", payload: "a  b" }),
    fingerprintLoopObservation({ kind: "MODEL_OUTPUT", outcome: "FAILURE", payload: " a\n b " }),
  );
});

test("tool-call fingerprints preserve whitespace inside argument strings", () => {
  assert.notEqual(
    fingerprintLoopObservation({ kind: "TOOL_CALL", outcome: "FAILURE", payload: '{"x":"a  b"}' }),
    fingerprintLoopObservation({ kind: "TOOL_CALL", outcome: "FAILURE", payload: '{"x":"a b"}' }),
  );
});

test("valid tool-call JSON passes without repair", () => {
  const result = repairToolCallSyntax(
    '{"tool":"browser.inspect","arguments":{"url":"https://example.com"}}',
    repairAuthority(),
  );
  assert.equal(result.status, "VALID");
  assert.deepEqual(result.operations, []);
  assert.equal(result.toolCall.tool, "browser.inspect");
  assert.equal(result.toolCall.arguments.url, "https://example.com");
});

test("bounded repair unwraps a JSON fence and removes trailing commas only", () => {
  const result = repairToolCallSyntax(
    '```json\n{"tool":"browser.inspect","arguments":{"url":"https://example.com",},}\n```',
    repairAuthority(),
  );
  assert.equal(result.status, "REPAIRED");
  assert.deepEqual(result.operations, ["UNWRAP_JSON_CODE_FENCE", "REMOVE_TRAILING_COMMAS"]);
  assert.equal(result.toolCall.tool, "browser.inspect");
  assert.equal(result.toolCall.arguments.url, "https://example.com");
});

test("repair refuses semantic invention such as single-quoted JSON", () => {
  const result = repairToolCallSyntax(
    "{'tool':'browser.inspect','arguments':{}}",
    repairAuthority(),
  );
  assert.equal(result.status, "REFUSED");
  if (result.status !== "REFUSED") assert.fail("expected refusal");
  assert.equal(result.reason, "INVALID_JSON");
});

test("repair never infers missing tool or argument fields", () => {
  const result = repairToolCallSyntax('{"arguments":{}}', repairAuthority());
  assert.equal(result.status, "REFUSED");
  if (result.status !== "REFUSED") assert.fail("expected refusal");
  assert.equal(result.reason, "INVALID_TOOL_CALL_SHAPE");
});

test("repair requires explicit runtime:bounded-repair authority", () => {
  for (const authority of [
    repairAuthority("BLOCK"),
    repairAuthority("ALLOW", "browser:evidence"),
  ]) {
    const result = repairToolCallSyntax('{"tool":"x","arguments":{}}', authority);
    assert.equal(result.status, "REFUSED");
    if (result.status !== "REFUSED") assert.fail("expected refusal");
    assert.equal(result.reason, "AUTHORITY_REQUIRED");
  }
});

test("repaired nested arguments are recursively frozen", () => {
  const result = repairToolCallSyntax(
    '{"tool":"x","arguments":{"nested":{"value":1}}}',
    repairAuthority(),
  );
  assert.equal(result.status, "VALID");
  assert.equal(Object.isFrozen(result.toolCall.arguments), true);
  assert.equal(Object.isFrozen(result.toolCall.arguments.nested), true);
});
