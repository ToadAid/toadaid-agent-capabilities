# BUILD LIST

Canonical capability roadmap for `ToadAid/toadaid-agent-capabilities`.

Checkbox law: mark an item complete only when the implementation is landed on canonical `main`. GitHub Actions runner failures caused solely by account spending limits do not change implementation status; runtime proofs remain separately recorded when available.

## Core capability lane

- [x] **P1 — Browser evidence core**
  - exact origin policy
  - bounded DOM evidence
  - screenshot + SHA-256 receipt
  - fresh non-persistent Chromium context
- [x] **P2 — Governed browser interaction**
  - bounded navigate / click / type
  - GET/HEAD-only browser network guard
  - action limits and redacted receipts
  - no secret/password entry authority
- [x] **P3 — Capability identity + policy**
  - canonical capability IDs
  - installed does not mean authorized
  - sparse agent/project/session/delegation policy
  - sticky explicit BLOCK
  - fail-closed unknown/stale capability handling
  - plain-data authority decision trace
- [x] **P4 — Resumable run-state capsule**
  - objective and current phase
  - authority snapshot as evidence, never a permission token
  - evidence/artifact references
  - completed/pending/blocked work
  - SHA-256 sealed capsule + predecessor continuity
  - compaction/restart continuity
  - resume authority = snapshot/current-policy intersection
- [x] **P5 — Persistent child-task lifecycle**
  - parent/child ownership and nested parent binding
  - fixed bounded delegated capability set
  - embedded P4 durable child run state
  - CREATED/RUNNING/BLOCKED/FAILED/COMPLETE state machine
  - failed/blocked child resume
  - parent/delegation/child-policy authority intersection
  - SHA-256 child-task continuity chain
- [x] **P6 — Workspace Time Travel**
  - immutable bounded content-addressed snapshots outside project Git
  - deterministic path-sorted diff
  - separately authorized exact restore with object preflight
  - `.git` and policy-excluded paths preserved
  - retention + orphan-object cleanup
  - exclusive history lock with stale/corrupt lock quarantine
  - corrupt snapshot/object quarantine
- [x] **P7 — Loop breaker + bounded repair**
  - SHA-256 repeated-output/tool/failure fingerprinting without raw-payload persistence
  - bounded identical-output and consecutive-failure hard stops
  - sticky halted state; no silent self-revival
  - `runtime:bounded-repair` installed BLOCK by default
  - allowlisted syntax-only repair for BOM / outer whitespace / whole JSON fence / trailing commas
  - exact tool-call shape validation with recursively frozen plain JSON arguments
  - semantics, missing fields, and authority are never repaired or inferred

## Next integration cut

- [ ] **R1 — OpenCodeReview adapter**
  - deterministic review surface and semantic grouping
  - mandatory review coverage accounting
  - `review:inspect` authority separate from `review:fix`
  - bounded reviewer/reflection children through P5
  - P6 snapshot before authorized fixes + deterministic diff after
  - capability-policy binding and structured review evidence/receipts

## Remaining capability lane

- [ ] **P8 — Scoped browser sessions**
  - explicit session ownership
  - origin-scoped session lease
  - bounded expiry/persistence
  - no shared authenticated browser state by default
- [ ] **P9 — Adaptive Web Intelligence**
  - `web:extract` deterministic structured extraction
  - `web:adaptive-locate` change-tolerant element identity + confidence threshold
  - `web:crawl` bounded/resumable crawl worker
  - `web:xhr-capture` explicit background API evidence
  - isolated Scrapling adapter/worker; no direct sovereign MCP authority
  - crawl checkpoints bound to P4/P5 continuity
  - safe redirect/address-resolution hardening for SSRF-sensitive paths
  - adaptive throttling / per-origin crawl budgets
  - optional stealth fetch remains separate and BLOCK by default

## Standing design rules

- Capabilities are explicit; authority is not ambient.
- Agent intent never grants itself authority.
- Saved state never grants or widens authority.
- Delegation can only narrow authority; it can never widen it.
- Workspace history is external to project Git and restore requires separate authority.
- Loop breakers may halt without authority; repair may fix syntax only and never invent semantics or authority.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
