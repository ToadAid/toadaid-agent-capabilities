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
- [ ] **P6 — Workspace Time Travel**
  - snapshot
  - deterministic diff
  - governed restore
  - retention/orphan cleanup
  - lock recovery/corruption quarantine
- [ ] **P7 — Loop breaker + bounded repair**
  - repeated-output/failure fingerprinting
  - malformed tool-call syntax repair
  - hard stop after bounded repetition
  - authority is never repaired or inferred
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

## Later integration lane

- [ ] **OpenCodeReview adapter**
  - deterministic review surface
  - mandatory review coverage accounting
  - capability-policy binding
  - structured review evidence/receipts

## Standing design rules

- Capabilities are explicit; authority is not ambient.
- Agent intent never grants itself authority.
- Saved state never grants or widens authority.
- Delegation can only narrow authority; it can never widen it.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
