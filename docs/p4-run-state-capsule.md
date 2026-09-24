# P4 — Resumable Run-State Capsule

P4 gives an agent run a compact, provider-neutral state object that can survive model compaction, process restart, or a fresh model context without relying on prose memory.

## What survives

A capsule carries only bounded plain data:

- run identity and revision
- objective summary and lifecycle status
- current phase
- P3 capability-authority snapshot
- evidence references
- artifact references
- completed / pending / blocked work
- continuity metadata linking the capsule to its predecessor

The capsule does not embed model prompts, secrets, browser profiles, wallet material, executable code, or arbitrary nested state.

## Integrity and continuity

`serializeRunStateCapsule()` wraps the capsule in a SHA-256 envelope. Parsing verifies that digest before the capsule is accepted.

Each checkpoint or restart increments the revision and continuity generation and records the SHA-256 of the exact predecessor capsule. `assertRunStatePredecessor()` verifies that a transition is contiguous and belongs to the same run.

This creates a tamper-evident continuity chain without making the capsule itself an execution authority.

## Authority law

The P3 authority snapshot is historical evidence, not a permission token.

On resume, `resolveResumeCapabilityAuthority()` uses an intersection rule:

- snapshot `ALLOW` + current `ALLOW` → `ALLOW`
- snapshot `ALLOW` + current `BLOCK` → `BLOCK`
- snapshot `BLOCK` + current `ALLOW` → `BLOCK`
- capability absent from either side → `BLOCK`

Therefore a stale capsule cannot resurrect revoked authority, and a newly granted capability does not silently widen an old run. If an operator intentionally wants a run to gain new authority, that should happen through a separate explicit governed transition rather than ordinary restart/compaction continuity.

## Checkpoint behavior

Automatic checkpoint and restart continuity preserves the authority snapshot unchanged. Checkpoints may update objective state, phase, evidence/artifact references, and work buckets.

Supported continuity reasons:

- `INITIAL`
- `CHECKPOINT`
- `COMPACTION`
- `RESTART`
- `MANUAL`

## Work-state invariant

A work item ID may appear in exactly one lifecycle bucket at a time: completed, pending, or blocked. This prevents a compacted or resumed run from claiming contradictory work state.

## Non-authority

P4 does not execute tools, mutate repositories, restore workspaces, sign transactions, grant capabilities, or infer missing authority. It preserves and verifies run continuity only.
