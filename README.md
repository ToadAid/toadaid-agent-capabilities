# ToadAid Agent Capabilities

Governed reusable capabilities for ToadAid agents.

This repository provides bounded capability modules that agents can consume without inheriting unrestricted host, wallet, repository, or execution authority.

Implemented browser lane:

- **P1 — browser evidence:** open a permitted URL, observe rendered HTML, capture bounded DOM evidence and a screenshot receipt.
- **P2 — browser interaction:** execute a bounded operator-authorized plan of navigation, click, and type actions, then return evidence of the resulting state.

Planned capability lanes:

- workspace snapshots
- review adapters
- additional capability contracts
- structured receipts

## Design rule

Capabilities are explicit. Authority is not ambient.

Agent intent never grants itself network or action authority. The embedding runtime/operator supplies the policy boundary.
