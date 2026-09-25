# Q1 — Unified Run Budget Ledger

Q1 gives a run tree one tamper-evident resource budget covering model, tool, network, retry, time, and child-task consumption.

The ledger is accounting state, not authority. A remaining budget never grants a capability, and an exhausted budget never erases work already performed.

## Budget dimensions

Every ledger has explicit ceilings for:

- model requests
- input tokens
- output tokens
- tool calls
- network requests
- retries
- wall-clock milliseconds
- child tasks

Zero is a valid ceiling. Availability is operation-specific: a run with zero retry allowance may still perform a first authorized model/tool action if those dimensions remain available.

## Append-only accounting

Usage is appended as bounded receipts. A receipt carries only identifiers, timestamps, an optional H1 invocation ID, an optional source SHA-256, and non-negative metric deltas.

Raw prompts, model output, credentials, tool arguments, and tool results do not belong in Q1.

Every ledger revision is SHA-256 sealed and predecessor-bound. `assertRunBudgetPredecessor()` verifies that earlier usage and child allocations remain byte-semantically unchanged and that history only grows.

Already-spent usage cannot be rewritten, deleted, or "refunded" by producing a later ledger revision.

## Child sub-allocation

`allocateChildRunBudget()` creates two things atomically in plain data:

1. a parent ledger revision containing a durable child allocation
2. a new child ledger bound to that allocation

The parent immediately reserves the child's complete metric limits and consumes one direct child-task slot. The child can spend only inside the reserved sub-budget. `assertChildRunBudgetBinding()` verifies that a resumed child ledger matches the exact allocation still present in its parent ledger.

A child's own `childTasks` ceiling represents how much descendant capacity it may allocate. Because that value is already reserved in the parent, nested delegation cannot escape the root budget.

Q1 intentionally has no automatic reclaim/refund operation in v1. If a child crashes or finishes with unused fuel, that reservation remains committed. This conservative rule prevents stale/resumed child state from double-spending budget that a parent thought had been returned.

## Remaining-budget calculation

For each metric:

```text
remaining = limit - direct usage - child reservations
```

If a proposed usage/allocation exceeds any required dimension, the operation fails closed before producing a new ledger revision.

`evaluateRunBudgetAvailability()` returns a deterministic receipt showing requested, remaining-before, remaining-after, and exceeded metrics. The receipt is evidence only.

## H1 / P4 / P5 composition

Q1 is designed to bind naturally to the existing runtime spine:

- H1 invocation IDs may be attached to usage receipts for provenance.
- P4 may persist the sealed budget envelope or an artifact/evidence reference to it.
- P5 child creation should use an explicit Q1 child allocation rather than inventing independent fuel.
- resumed work must continue from the latest verified ledger revision; saved historical budget state never creates new fuel.

The embedding runtime is responsible for reporting trustworthy provider/tool usage into Q1. Q1 validates accounting transitions but cannot independently measure provider token counts or elapsed wall-clock time.

## Non-authority

Q1 does not execute tools, call models, authorize network access, grant capabilities, create P5 children, or approve economic actions.

Budget availability answers only: "is there enough previously allocated fuel for this proposed consumption?"

P3/H1 still answer whether the action itself is permitted.
