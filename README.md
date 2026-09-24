# ToadAid Agent Capabilities

Governed reusable capabilities for ToadAid agents.

This repository provides bounded capability modules that agents can consume without inheriting unrestricted host, wallet, repository, or execution authority.

Initial capability lanes:

- browser evidence
- workspace snapshots
- review adapters
- capability contracts
- structured receipts

The first implementation lane is browser evidence: open a permitted URL, observe the rendered page, capture a screenshot and bounded DOM evidence, and return a structured receipt.

## Design rule

Capabilities are explicit. Authority is not ambient.
