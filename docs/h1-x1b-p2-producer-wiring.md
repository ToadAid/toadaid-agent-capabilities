# H1/X1B-P2 — Producer wiring

P1 made H1 capable of representing reconciliation truth. P2 makes current
external-effect producers consume that lifecycle law.

## Producer outcome law

Connector execution, desktop interaction, and host service outcomes carry the
exact current H1 envelope.

- normal success returns the unchanged active H1;
- read-only host degradation returns the unchanged active H1;
- uncertain post-dispatch execution returns the
  `RECONCILIATION_REQUIRED` H1 successor created by
  `beginCapabilityInvocationReconciliation(...)`.

Desktop and host-service receipts bind `invocationRecordSha256` to that exact
returned H1 envelope. Connector execution outcomes carry both the envelope and
its record SHA directly.

Consumers propagate `outcome.invocation` as current H1 truth. In addition, each
producer requires a `CapabilityInvocationHeadRuntime`: it resolves the exact
current H1 before provider entry and refuses a stale envelope. On uncertainty,
the producer atomically claims the current H1 head from the active predecessor
to the `RECONCILIATION_REQUIRED` successor before returning. Reusing the old
`STARTED` envelope after that transition therefore fails before provider entry.

## Pre-dispatch lockability

The producer establishes valid reconciliation identity and monotonic time before
mutation entry.

- connector execution validates or derives reconciliation identity and captures
  the dispatch-boundary time before provider entry;
- desktop interaction derives reconciliation identity from the exact invocation
  and interaction epoch and refuses H1 time regression before dispatch;
- host service derives reconciliation identity from the exact invocation and
  operation ID and refuses H1 time regression before adapter entry.

This prevents discovering only after an external side effect that the H1/X1
successor cannot be formed because lifecycle metadata is invalid or backward.

## Exact pair binding

For uncertain outcomes:

```text
returned invocation.status = RECONCILIATION_REQUIRED
returned invocation.reconciliation.openReconciliationSha256
  = returned reconciliation.recordSha256
receipt/outcome invocationRecordSha256
  = returned invocation.recordSha256
```

The locked H1 successor directly names the pre-dispatch H1 predecessor. X1
remains OPEN until explicit reconciliation resolves it, after which P1 terminal
closeout produces `RECONCILED` execution truth.

## Scope

P2 does not invent a second invocation lifecycle. The narrow head runtime is a
current-envelope CAS seam, matching the repository's existing current-head
patterns. It closes the producer split-brain in the immutable-envelope model:
uncertain execution returns X1 evidence only together with the matching H1
reconciliation lock, publishes that lock as current H1 truth, and rejects stale
predecessor reuse before another provider entry.
