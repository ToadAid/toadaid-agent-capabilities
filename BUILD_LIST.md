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
- [x] **P10 — Governed human interrupts**
  - `interrupt:create` and `interrupt:resolve` installed separately, both BLOCK by default
  - OPEN -> RESOLVED one-way lifecycle with SHA-256 sealed predecessor continuity
  - exact P4 run-id / revision / capsule-hash binding
  - bounded scalar/object response schemas with no undeclared fields
  - resolution refuses stale/different run state and second resolution attempts
  - resume proof requires a resolved interrupt bound to the unchanged paused run state
  - human response data never grants, repairs, or widens capability authority
  - durable interruption is a pause/decision primitive, not an approval token

## Next research-derived capability lane

- [x] **P11 — Scoped secret leases**
  - `secret:lease` and `secret:materialize` installed separately, both BLOCK by default
  - broker-generated opaque secret handles only; raw secret bytes never enter lease/grant state
  - fixed owner/provider/profile + consumer-capability scope with bounded lease TTL
  - short-lived materialization grants cannot outlive the parent lease
  - materialization rechecks both current `secret:materialize` and exact consumer capability authority
  - ENV and 0600 FILE projection targets are explicit and path-safe
  - revocation is one-way, SHA-256 predecessor-bound, and needs no widening authority
  - P4/P5 saved state may carry handles but can never self-authorize secret access
- [x] **W1 — Governed recipe compiler**
  - bounded declarative parameters and response schema
  - explicit max-turn and retry ceilings
  - disjoint required / optional / forbidden capability sets
  - required capability denial or unknown capability fails compilation closed
  - optional denied capabilities become explicit `SKIPPED_OPTIONAL` steps
  - forbidden capabilities never enter the effective plan even when ambient policy allows them
  - every step must bind to a declared required/optional capability
  - normalized recipe + compiled plan are SHA-256 fingerprinted/sealed
  - pre-execution/resume authority recheck refuses revocation and never silently adopts newly granted optional authority
  - compiled plans are bounded non-authority state intended to seed P4/P5 execution
- [x] **H1 — Capability invocation lifecycle**
  - stable invocation identity across request / policy / start / result / failure
  - SHA-256 sealed predecessor continuity; raw arguments/results stay out of lifecycle state
  - deterministic pre-start P3 recheck so stale authorization cannot start work
  - bounded post-tool evidence references and result/error fingerprints
  - manager changes and resumed runs never bypass current revocation
  - progress receipts bind to the exact invocation state
  - cooperative `CANCEL_REQUESTED` records intent only; it never claims the external side effect stopped
  - resumed STARTED/CANCEL_REQUESTED work becomes `RECONCILIATION_REQUIRED`, never blind retry
- [x] **Q1 — Unified run budget ledger**
  - explicit ceilings for model requests, input/output tokens, tool calls, network requests, retries, wall-clock time, and child tasks
  - SHA-256 sealed predecessor-bound ledger with append-only usage receipts
  - deterministic remaining budget = limits - direct usage - child reservations
  - H1 invocation/source hashes may bind usage provenance without persisting raw prompts/results
  - child sub-allocation reserves its full budget plus one direct child slot from the parent
  - nested child allocation can only narrow already-reserved parent fuel
  - no silent reclaim/refund in v1; crashed/stale child state cannot cause double-spend
  - operation-specific availability fails closed only on the metrics that proposed work needs
  - budget state is accounting evidence, never capability authority
- [x] **C1 — Capability contract + version discovery**
  - SHA-sealed self-describing descriptor registry with capability ID, contract ID, major/minor version, schemas, feature set, and implementation fingerprint
  - exact-major / minimum-minor / required-feature compatibility checks; unknown or incompatible installed capabilities fail closed
  - deprecation refuses by default unless the caller explicitly opts into that exact deprecated contract
  - contract-aware W1 profiles cover every required/optional recipe capability before base W1 compilation
  - truly absent optional capabilities remain explicit skips; installed optional capabilities must advertise a compatible contract
  - compiled enabled capability bindings retain exact descriptor SHA; descriptor/implementation changes require recompile rather than silent adoption
  - H1 contract binding ties capability + run + invocation + intent to the compatible descriptor and must pass while the invocation is `AUTHORIZED`
  - discovery/implementation fingerprints are provenance and compatibility evidence only; they never grant P3 authority
- [ ] **X1 — Idempotency / replay fence**
  - classify invocations as `SAFE_READ`, `IDEMPOTENT_WRITE`, or `NON_REPLAYABLE`
  - deterministic idempotency key binding run + invocation + capability + intent
  - timeout/unknown-outcome becomes reconciliation, never blind retry
  - prior receipt/external-state proof required before retrying a mutating invocation
  - economic/Git/provider writes stay non-replayable unless an adapter proves idempotency
- [ ] **B1 — Browser resilience hardening**
  - stale-DOM refusal after failed capture
  - recoverable degraded browser evidence instead of fabricated state
  - navigation-readiness and same-document navigation handling
  - bounded DOM fanout and stable selector/index identity across sessions
  - distinct timeout/truncation/recoverable-error receipts

## Pre-wiring integration proof

- [ ] **V1 — Deterministic Agent0 vertical proof harness**
  - exercise W1 -> P4/P5 -> H1 -> real bounded capability -> receipt -> restart/resume
  - recorded/deterministic model and tool fixtures for replayable regression tests
  - prove P10 human interrupt and P11 secret-handle boundaries without exposing raw credentials
  - prove Q1 budget consumption, C1 contract checks, X1 replay discipline, and B1 degraded browser recovery
  - no wallet, trading, irreversible economic authority, push, or merge in the graduation proof
  - capability library becomes integration-ready only after the vertical proof closes

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
- Human interrupt responses are typed data, not approvals or authority; resume is bound to the exact paused run state.
- Secret handles are references, never credentials; materialization requires fresh current authority and raw secret bytes stay runtime-owned.
- Recipe definitions declare workflow bounds; compiled plans are non-authority state and must be rechecked against current P3 policy before execution/resume.
- Invocation lifecycle evidence never becomes authority; fresh policy checks govern start/resume and already-started work requires reconciliation before replay.
- Budgets, capability contracts, and replay fences bound execution economics/compatibility/retries without granting new authority.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
