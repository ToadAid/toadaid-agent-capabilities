# P5 — Persistent Child-Task Lifecycle

P5 gives subordinate agent work a durable, resumable identity instead of treating a spawned child as disposable model context.

## Parent / child binding

Each child task records:

- `childTaskId`
- root `parentRunId`
- optional `parentChildTaskId` for nested ownership
- lifecycle revision and continuity digest
- attempt count
- fixed delegated capability set
- a full P4 run-state capsule for the child's durable objective/work/evidence state

The child run-state `runId` must equal the `childTaskId`.

## Lifecycle

The bounded state machine is:

- `CREATED -> RUNNING` via `START`
- `RUNNING -> RUNNING` via `CHECKPOINT`
- `RUNNING -> BLOCKED` via `BLOCK`
- `RUNNING -> FAILED` via `FAIL`
- `BLOCKED|FAILED -> RUNNING` via `RESUME`
- `RUNNING -> COMPLETE` via `COMPLETE`

`COMPLETE` is terminal.

Every transition must carry the immediate P4 run-state predecessor. Child-task revision and P4 run-state revision therefore advance together as a verifiable continuity chain.

## Delegated authority

Delegation is bounded at creation: a parent can delegate only capabilities that its current P4 resume authority still allows.

A child run-state may not contain an `ALLOW` authority decision outside that delegated set.

At execution/resume time, a child capability is allowed only when all three conditions hold:

1. the capability was originally delegated to the child
2. the parent still has effective resumed authority for it
3. the child's own P4 snapshot/current-policy intersection still allows it

This means restart, compaction, a parent policy change, or a child policy change can remove authority, but none can silently widen it.

## Integrity

Child-task records are canonicalized and SHA-256 sealed in `toadaid.child-task-envelope.v1`.

Each non-initial record binds to the exact previous child-task digest, while the embedded P4 capsule independently binds to its previous P4 state.

## Non-authority

P5 does not itself spawn a model, execute a tool, grant a capability, or move funds. It defines durable subordinate-task identity, lifecycle, continuity, and bounded delegated authority for embedding runtimes such as Agent0/Agent1.
