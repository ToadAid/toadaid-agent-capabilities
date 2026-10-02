# H1/X1B-P1 — Reconciliation-locked H1 core

H1 and X1 previously proved different parts of execution truth but could evolve
as separate immutable branches. An uncertain external outcome could open X1
while H1 remained `STARTED` or `CANCEL_REQUESTED`, leaving ordinary
`COMPLETED` / `FAILED` terminalizers structurally available.

P1 introduces an explicit cross-lifecycle lock.

## Open law

`beginCapabilityInvocationReconciliation(...)` accepts one active H1 invocation
and its exact replay fence, opens X1, then creates the direct H1 successor:

```text
STARTED | CANCEL_REQUESTED
        ↓ exact X1 open
RECONCILIATION_REQUIRED
```

The H1 lock binds reconciliation ID, replay-fence SHA, open-reconciliation SHA,
the exact predecessor invocation-record SHA, and X1 open time. X1 `openedAt`
must be at or after the active H1 predecessor `updatedAt`; continuity may not
move lifecycle time backward. The sealed lock also requires its captured
invocation-record SHA to equal the direct H1 predecessor SHA.

Ordinary H1 `complete` and `fail` functions accept only `STARTED` or
`CANCEL_REQUESTED`, so a reconciliation-locked invocation cannot be
terminalized through those paths.

## Close law

`closeCapabilityInvocationReconciliation(...)` requires a `RESOLVED` X1 record
that continues the exact open reconciliation and the exact H1 predecessor.

The resulting H1 status is `RECONCILED`, not fabricated `COMPLETED` or `FAILED`.
Its terminal outcome binds the exact resolved reconciliation SHA, replay-fence
SHA, finding, disposition, proof SHA when present, and explicit execution truth:

- `CONFIRMED_EXECUTED` → `EXECUTED`
- `CONFIRMED_NOT_EXECUTED` → `NOT_EXECUTED`
- `STILL_UNKNOWN` → `UNKNOWN`

The X1 disposition is preserved exactly. Sealed `RECONCILED` records also
cross-check reconciliation ID and replay-fence SHA against the H1/X1 lock, so a
caller cannot reseal a terminal outcome that names different reconciliation
identity.

## Public surface

The cross-lifecycle functions are re-exported from `capabilityInvocation.ts`,
which is the package's existing `@toadaid/agent-capabilities/invocation`
subpath. P1 therefore adds no new package export and does not wait for D2 to be
usable by package consumers.

## Continuity

The resolved X1 record must name the lock's open reconciliation as its
predecessor. The H1 lock must directly descend from the invocation record whose
SHA X1 captured when it opened. Cross-invocation, cross-run, cross-capability,
and cross-intent substitutions fail closed.

## P2 remains

P1 provides the lifecycle primitive. P2 must route every current uncertain
producer—connector execution, desktop interaction, and host service—through
this lock and return the updated H1 truth beside X1 evidence.
