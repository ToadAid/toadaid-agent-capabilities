# P3 — Capability Identity + Policy

P3 makes capability installation separate from authority.

> Installed does not mean authorized.

The repository ships a manifest of known capabilities and resolves sparse policy layers into a plain-data authority decision before a capability is used.

## Built-in capability identities

- `browser:evidence`
- `browser:interaction`

Both are installed with a manifest default of `BLOCK`. A caller must explicitly grant an installed capability before use.

## Policy layers

Layers are ordered from broad identity to narrow delegation:

1. `agent`
2. `project`
3. `session`
4. `delegation`

Each layer may specify:

- `ALLOW` — grant the capability unless an earlier layer has explicitly blocked it
- `DEFAULT` — inherit the current decision
- `BLOCK` — refuse the capability and make the refusal sticky for all downstream layers

The chain is sparse: missing capability entries behave like `DEFAULT`.

## Fail-closed rules

- unknown requested capabilities resolve to `BLOCK`
- policy entries naming capabilities that are not installed are rejected
- malformed or duplicate capability IDs are rejected
- policy layers must follow canonical scope order
- a downstream layer cannot undo an upstream explicit `BLOCK`

## Decision evidence

Resolution returns `toadaid.capability-authority-decision.v1`, including:

- capability ID
- whether the capability is installed
- effective `ALLOW` / `BLOCK`
- reason code
- ordered decision trace showing every policy layer and the sticky-block state

This is intentionally plain data so Agent0/Agent1 runtimes can attach the authority decision to receipts without importing policy logic into model prompts.

## Non-authority

P3 does not itself execute browser actions, shell commands, repository writes, wallet signing, trading, or any other side effect. It only answers whether a named installed capability is authorized under a supplied policy chain.
