# X1 — Idempotency / Replay Fence

X1 prevents uncertain external outcomes from turning into blind retries.

The core law is simple:

> a timeout or lost response does not prove that an external side effect did not happen.

H1 remains the lifecycle spine. X1 sits beside an active H1 invocation and governs whether another transport attempt is safe.

## Replay classes

Every invocation that may be retried must be classified before it starts:

- `SAFE_READ` — the adapter asserts that repeating the transport operation cannot mutate external state.
- `IDEMPOTENT_WRITE` — replay is permitted only when a C1 contract-ready receipt advertises an explicit idempotency mechanism for this exact invocation/capability.
- `NON_REPLAYABLE` — the same logical invocation can never be replayed.

There is no default mutating classification. Git/provider/economic writes remain `NON_REPLAYABLE` unless the adapter contract explicitly proves an idempotency feature.

## Deterministic idempotency key

The key is SHA-256 over bounded logical identity:

- run ID
- invocation ID
- capability ID
- intent SHA-256

The key is stable for transport attempts inside one logical H1 invocation and changes when the invocation or intent changes.

The key is evidence/deduplication material, not capability authority.

## Contract-bound idempotency guarantees

`IDEMPOTENT_WRITE` requires a guarantee created from a C1 `CapabilityInvocationContractReadyReceipt`.

Supported mechanisms map to explicit C1 features:

- `PROVIDER_KEY` -> `idempotency.provider-key`
- `COMPARE_AND_SET` -> `idempotency.compare-and-set`
- `EXTERNAL_DEDUPLICATION` -> `idempotency.external-deduplication`

The guarantee binds invocation ID, capability ID, C1 contract binding SHA, exact descriptor SHA, implementation fingerprint SHA, and mechanism/feature.

A guarantee cannot be reused for a different invocation or capability. A changed implementation/descriptor requires a new C1 binding and therefore a new X1 fence.

## Unknown outcomes and H1

Unknown outcome handling occurs while the H1 invocation is still `STARTED` or `CANCEL_REQUESTED`.

Do not mark the H1 invocation `FAILED` merely because a transport timed out. X1 first opens a reconciliation record. After reconciliation establishes truth, the embedding runtime can complete/fail H1 or perform an authorized transport retry.

A terminal H1 invocation cannot be reopened for X1 replay reconciliation.

## Reconciliation

Opening reconciliation immediately yields `BLOCKED_PENDING_RECONCILIATION`.

The finding is one of:

- `CONFIRMED_NOT_EXECUTED`
- `CONFIRMED_EXECUTED`
- `STILL_UNKNOWN`

Confirmed findings require proof SHA-256. Proof/evidence bodies stay external; X1 stores only bounded references and hashes.

Disposition law:

- confirmed executed -> `DO_NOT_RETRY`
- `SAFE_READ` -> retry may be allowed only after an explicit reconciliation resolution is recorded
- `IDEMPOTENT_WRITE` -> retry requires `CONFIRMED_NOT_EXECUTED` proof and the exact original idempotency key
- `NON_REPLAYABLE` + confirmed not executed -> `NEW_INVOCATION_REQUIRED`, never replay of the same invocation
- unresolved/unknown mutating outcome -> remains blocked

## Stale-state refusal

Reconciliation binds the exact active H1 invocation record SHA. Retry authorization refuses if that H1 record changed after reconciliation opened.

Reconciliation itself is SHA-sealed and one-way `OPEN -> RESOLVED` with predecessor continuity.

## Non-authority

X1 never grants P3 authority, never performs the external action, never proves a provider result by itself, and never turns an uncertain mutation into success.

A retry authorization means only that the replay discipline has been satisfied. H1, Q1, C1, P3 and the adapter must still independently permit the next transport attempt.
