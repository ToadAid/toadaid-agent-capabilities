# P7 — Loop Breaker + Bounded Repair

P7 prevents an agent runtime from spinning indefinitely on repeated model output, repeated tool attempts, or consecutive failures, and provides a deliberately narrow syntax-repair path for malformed tool-call JSON.

## Safety split

The loop breaker is a runtime safety invariant. It does not require a capability grant to stop work.

Bounded repair is different: it can turn malformed text into parseable tool-call data, so it is exposed as `runtime:bounded-repair` and is `BLOCK` by default under P3.

## Loop breaker

`recordLoopObservation()` consumes bounded observations such as model output, tool calls, tool failures, and empty output. It persists only SHA-256 fingerprints and small metadata, never the raw payload.

The default breaker halts on either:

- 3 consecutive identical fingerprints, or
- 5 consecutive failures

Both thresholds and history size are bounded by policy.

Once halted, the state is sticky. A later successful-looking response cannot revive the same breaker state. The embedding runtime must perform an explicit higher-level recovery/restart decision instead of silently continuing the loop.

Model-output fingerprints normalize presentation whitespace so cosmetically equivalent empty/garbled responses collapse to one fingerprint. Tool-call payloads are treated more conservatively so whitespace inside argument strings is not erased and distinct actions are not accidentally merged.

## Bounded syntax repair

`repairToolCallSyntax()` accepts only current `runtime:bounded-repair` authority and performs a small allowlist of deterministic transformations:

- strip a UTF-8 BOM
- trim outer whitespace
- unwrap one whole JSON code fence
- remove trailing commas outside JSON strings

It does **not**:

- convert single quotes to double quotes
- add missing braces
- invent or rename keys
- infer a tool name
- infer arguments
- infer capability authority
- execute the resulting tool call

The repaired document must still be an exact top-level object with only `tool` and `arguments`, a bounded tool name, and bounded plain JSON arguments. Unsupported/malformed shapes return a structured refusal.

Returned argument data is recursively frozen so downstream code cannot mutate the parsed repair result in place.

## Authority law

Syntax repair is not execution authority.

A repaired tool call must still pass the target tool/capability's normal P3 authority check. For example, repairing JSON that names `workspace:restore` cannot grant `workspace:restore`; it only makes the original syntax parseable.

> Syntax may be repaired. Semantics and authority are never invented.

## Receipts and privacy

Loop-breaker history stores fingerprints rather than raw model/tool payloads. Bounded-repair results store input/output SHA-256 digests plus the repair-operation list; raw input text is not copied into a repair receipt.

## Non-authority

P7 does not execute tools, grant capabilities, retry indefinitely, change wallet/trading authority, or recover a halted run automatically. It detects repetition, stops bounded loops, and optionally performs syntax-only repair when explicitly authorized.
