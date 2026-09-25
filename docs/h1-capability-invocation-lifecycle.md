# H1 — Capability Invocation Lifecycle

H1 gives every real capability invocation one stable identity from request through policy, execution, outcome, cancellation request, progress evidence, and resume assessment.

It is lifecycle infrastructure, not a new execution capability. P3 remains the authority source.

## Stable invocation identity

`createCapabilityInvocation()` creates a SHA-256 sealed `REQUESTED` record containing only bounded metadata and digests:

- invocation ID
- run ID and optional child-task ID
- capability ID
- tool name and optional external/model tool-call ID
- intent SHA-256
- optional arguments SHA-256

Raw arguments are deliberately not stored in the H1 record.

## Lifecycle

The state machine is:

```text
REQUESTED
  -> AUTHORIZED -> STARTED -> COMPLETED
  |                 |        -> FAILED
  |                 -> CANCEL_REQUESTED -> COMPLETED / FAILED
  -> REFUSED
```

Every transition increments the revision and binds `previousRecordSha256` to the exact predecessor.

`authorizeCapabilityInvocation()` resolves current P3 policy. A denied or unknown capability becomes terminal `REFUSED` evidence.

`startCapabilityInvocation()` performs another current P3 check immediately before start. Authority revoked after authorization therefore prevents execution.

## Manager changes and resume

Authorization evidence is historical, never a permission token. A different manager or resumed runtime cannot rely on an old `AUTHORIZED` record without rechecking current policy.

`assessCapabilityInvocationResume()` returns one of:

- `REAUTHORIZE` — request exists but has not been policy checked
- `READY_TO_START` — authorized plan remains currently allowed
- `BLOCKED_BY_REVOCATION` — current policy has revoked the capability
- `RECONCILIATION_REQUIRED` — invocation had already started, so blind retry is forbidden
- `TERMINAL` — refused/completed/failed

The reconciliation case is intentionally handed to X1 Idempotency / Replay Fence rather than guessed inside H1.

## Progress and cancellation

`createCapabilityInvocationProgressReceipt()` produces bounded progress evidence tied to the exact current invocation hash. It carries no raw tool output.

`requestCapabilityInvocationCancellation()` records `CANCEL_REQUESTED`. This is cooperative intent only:

> cancellation requested does not mean the external side effect stopped.

A later completion or failure may still arrive and is preserved as truth.

## Outcomes and post-tool evidence

Completion stores:

- result SHA-256
- bounded evidence references
- completion time
- manager identity

Failure stores:

- bounded error class
- error fingerprint SHA-256
- bounded evidence references
- failure time
- manager identity

H1 does not persist raw result bodies, raw error text, credentials, or tool arguments by default.

## Non-authority

H1 does not execute tools, grant capabilities, retry side effects, approve actions, cancel external work, or decide idempotency.

It gives the rest of the runtime a tamper-evident invocation spine so Q1 budgets, C1 contracts, X1 replay discipline, recipes, child tasks, and later telemetry can all bind to the same action identity.
