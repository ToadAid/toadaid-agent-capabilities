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

## Integration lane

- [x] **R1 — OpenCodeReview adapter**
  - OCR Delegation Mode schema-v1 preview/rule adapter; no OCR-managed LLM required
  - argv-only command construction; no shell-string authority
  - deterministic review surface and bounded rule/diff-size batching
  - mandatory `(path, status)` review coverage accounting
  - `review:inspect` and `review:fix` installed separately, both BLOCK by default
  - P5-ready reviewer/reflection child specs delegate only `review:inspect`
  - P6 snapshot before authorized fix + exact snapshot-bound diff after
  - structured review, reflection, and fix receipts

## Remaining capability lane

- [x] **P8 — Scoped browser sessions**
  - explicit owner-bound session lease
  - exact-origin scope with bounded origin count
  - 30-minute default TTL / 24-hour hard maximum
  - SHA-256 sealed lease with bounded serialization
  - current-authority recheck on every use
  - sticky revocation and expiry refusal
  - `browser:session` and `browser:session-persist` separate, both BLOCK by default
  - persistent state represented only by opaque owner/session-bound runtime reference
  - no shared authenticated browser state by default; P1/P2 remain fresh-context unless explicitly opted in
- [x] **P9 — Adaptive Web Intelligence**
  - `web:extract` deterministic structured extraction with bounded declared fields
  - `web:adaptive-locate` deterministic structural fingerprints, confidence threshold, and ambiguity refusal
  - `web:crawl` sealed resumable crawl checkpoints bound to exact P4/P5 continuity hashes
  - `web:xhr-capture` explicit guarded background API evidence; body hash-only by default
  - isolated one-request/one-response Scrapling worker; no direct MCP or Python-shell authority
  - HTTP GET-only redirect loop validates every target before following
  - browser worker pre-navigation guard allows GET/HEAD only and separates top-level/resource origins
  - private/local/reserved address refusal with worker DNS evidence and host-side verification
  - per-origin crawl budgets, deduplication, depth/URL ceilings, and adaptive latency/429 backoff
  - `web:stealth-fetch` remains separate and BLOCK by default
  - resumable checkpoints refuse query/fragment URLs to avoid persisting tokens/secrets

## Standing design rules

- Capabilities are explicit; authority is not ambient.
- Agent intent never grants itself authority.
- Saved state never grants or widens authority.
- Delegation can only narrow authority; it can never widen it.
- Workspace history is external to project Git and restore requires separate authority.
- Loop breakers may halt without authority; repair may fix syntax only and never invent semantics or authority.
- Review inspection never implies review fixes; external review engines are deterministic evidence providers, not sovereign runtimes.
- Browser session leases are owner/origin/expiry scoped; saved or persistent state never grants browser action authority.
- Adaptive web evidence remains evidence; crawl/XHR/stealth authority is explicit and never implies mutation or economic authority.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
