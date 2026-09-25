# P10 — Governed Human Interrupts

P10 adds a durable typed human-decision gate for runs that cannot safely continue without a sovereign human response.

The interrupt is not an approval token. The response is not capability authority. P3 remains the only authority source.

## Capabilities

P10 installs two independent capabilities, both `BLOCK` by default:

- `interrupt:create` — create a durable typed interrupt bound to the exact paused P4 state
- `interrupt:resolve` — accept one schema-valid human response for that exact interrupt/run binding

A caller allowed to create interrupts is not automatically allowed to resolve them.

## Runtime shape

The embedding runtime should first checkpoint the P4 run into the state it intends to pause. `createHumanInterrupt()` then binds the interrupt to:

- `runId`
- exact P4 `revision`
- exact P4 capsule SHA-256

The resulting record is `OPEN`, revision `0`, SHA-256 sealed, and has no resolution.

A later `resolveHumanInterrupt()` succeeds only when:

1. current `interrupt:resolve` authority is `ALLOW`
2. the interrupt envelope still passes integrity validation
3. the interrupt is still `OPEN`
4. the current P4 run matches the saved run-id, revision, and capsule SHA-256 exactly
5. the human response satisfies the saved response schema

The transition produces `RESOLVED`, revision `1`, and binds `previousRecordSha256` to the exact OPEN record. A resolved interrupt cannot be resolved again.

## Response schemas

P10 intentionally supports a small deterministic schema surface rather than arbitrary executable validators:

- bounded string, with optional enum
- boolean
- bounded safe integer
- flat object containing those scalar field types
- explicit required fields
- no additional undeclared properties

This is enough for decisions, choices, bounded notes, quantities, and other operator input without turning the interrupt into a general programming surface.

## Resume proof

`createHumanInterruptResumeProof()` requires a sealed `RESOLVED` interrupt and the same exact still-paused P4 state.

The proof binds:

- interrupt ID
- resolved interrupt-record SHA-256
- run ID / revision / capsule SHA-256
- responder ID
- response SHA-256
- verification time

The runtime may then use that proof as evidence when it creates the next P4 checkpoint. The proof itself grants no capability and does not mutate P4.

## Human sovereignty and non-authority

P10 deliberately keeps human decision data separate from authority data.

A response such as `{"decision":"approve"}` cannot grant `workspace:restore`, `review:fix`, wallet, trading, browser, secret, or any other capability. Those capabilities must still be allowed by current P3 policy at the moment of use.

Likewise, an unrelated `yes` cannot resolve another interrupt: the response transition is bound to the exact interrupt and exact paused P4 state.

Responder identity is asserted by the embedding runtime. P10 preserves that identity and binds it into the resolution, but does not itself authenticate a human account or UI session.

## Persistence

The interrupt envelope is bounded and SHA-256 sealed. It may be persisted beside P4/P5 state or referenced from run evidence/artifact records.

P10 has no ambient storage, notification, UI, shell, repository, browser, wallet, or economic authority.
