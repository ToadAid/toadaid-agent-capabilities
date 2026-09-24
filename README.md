# ToadAid Agent Capabilities

Governed reusable capabilities for ToadAid agents.

This repository provides bounded capability modules that agents can consume without inheriting unrestricted host, wallet, repository, or execution authority.

Implemented lanes:

- **P1 — browser evidence:** open a permitted URL, observe rendered HTML, capture bounded DOM evidence and a screenshot receipt.
- **P2 — browser interaction:** execute a bounded operator-authorized plan of navigation, click, and type actions, then return evidence of the resulting state.
- **P3 — capability identity + policy:** keep capability installation separate from authority with sparse fail-closed policy resolution and decision traces.
- **P4 — resumable run-state capsule:** preserve objective, phase, authority evidence, references, and work state across compaction/restart with tamper-evident continuity.
- **P5 — persistent child-task lifecycle:** preserve subordinate task identity/state across failure and resume with fixed, non-widening delegated authority.

See [`BUILD_LIST.md`](./BUILD_LIST.md) for the canonical roadmap.

## Design rule

Capabilities are explicit. Authority is not ambient.

Agent intent never grants itself network or action authority. The embedding runtime/operator supplies the policy boundary.

Installed does not mean authorized.

Saved state does not grant authority.

Delegation can only narrow authority.
