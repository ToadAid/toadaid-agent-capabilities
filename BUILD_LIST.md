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
- [x] **X1 — Idempotency / replay fence**
  - explicit `SAFE_READ`, `IDEMPOTENT_WRITE`, or `NON_REPLAYABLE` classification before H1 start
  - deterministic idempotency key binds run + invocation + capability + intent
  - idempotent writes require a C1 contract-ready receipt advertising an exact idempotency feature for the same invocation/capability
  - timeout/unknown outcome opens sealed reconciliation while H1 remains active; terminal H1 work cannot be reopened
  - confirmed findings require proof SHA; raw provider evidence remains external behind bounded references
  - `IDEMPOTENT_WRITE` replay requires confirmed-not-executed proof and preserves the exact original idempotency key
  - `NON_REPLAYABLE` never replays the same invocation; confirmed-not-executed can only require a new invocation
  - retry authorization refuses stale/changed H1 invocation records after reconciliation opens
  - economic/Git/provider mutations remain non-replayable unless the adapter contract explicitly proves idempotency
- [x] **B1 — Browser resilience hardening**
  - navigation epochs invalidate prior DOM immediately; fresh DOM tokens bind exact epoch + sanitized page identity + DOM SHA
  - capture failure clears current DOM and emits bounded `DEGRADED` evidence with typed reason, recoverability, and error fingerprint
  - stale DOM is never reused as fallback after navigation, timeout, page-identity change, or failed capture
  - same-document navigation does not wait for a nonexistent new `DOMContentLoaded`; full-document readiness timeout degrades explicitly
  - bounded text/headings/interactive fanout carries explicit truncation flags instead of pretending output is complete
  - deterministic semantic element IDs survive session/CDP index changes and strip href query/fragment data
  - recovery state remains non-authority; H1/Q1/X1 still govern lifecycle, budget, and replay

## Pre-wiring distribution + integration proof

- [x] **D1 — Package distribution surface**
  - consumer build uses `tsconfig.build.json` so published/Git-installed output contains `dist/src` without compiled repository tests
  - Git installs build through standard `prepare`; ordinary repository tests retain the full `tsconfig.json` path
  - `files` allowlist constrains package payload to compiled distribution plus README/package metadata
  - package verifier self-imports every declared public export through Node package self-reference
  - `npm pack --dry-run` must contain every JS/declaration export target and refuse source/test/docs/workflow/script leakage
  - package remains private during alpha; D1 does not publish, change repository access, or grant capability authority
  - V1 must consume the package boundary rather than repository source paths
- [x] **V1 — Deterministic Agent0 vertical proof harness**
  - clean-room harness packs the package and executes from a temporary consumer `node_modules`; repository `src/` paths are never imported
  - exercise contract-aware W1 -> P4/P5 child -> H1 -> bounded browser resilience evidence -> receipt -> checkpoint -> restart/resume
  - prove Q1 parent/child budget reservation + durable usage accounting and C1 exact contract binding before start
  - prove X1 `NON_REPLAYABLE` uncertain mutation resolves to `NEW_INVOCATION_REQUIRED`, never same-invocation replay
  - prove P10 interrupt resolution refuses changed P4 state and P11 secret materialization stays opaque + current-authority-bound
  - prove B1 stale-DOM refusal and explicit degraded evidence without launching a live browser or using network fixtures
  - no wallet, trading, irreversible economic action, provider mutation, push, or merge occurs in the graduation scenario
  - completion marker is exactly `V1_AGENT0_VERTICAL_OK`
  - 2026-09-25 TNG clean-room proof emitted `PACKAGE_DISTRIBUTION_OK exports=6 files=146` then `V1_AGENT0_VERTICAL_OK` with `packageResolvedFromConsumer=true`, `secretHandleOnly=true`, `nonReplayableDisposition=NEW_INVOCATION_REQUIRED`, and post-restart browser authority `BLOCK`
  - capability library is integration-ready after this clean-room vertical proof closure

## Post-graduation integration lane

- [x] **P12 — Governed connector adapter boundary**
  - explicit adapter registration binds adapter ID, capability ID, tool name, contract ID, C1 descriptor SHA, and implementation fingerprint
  - adapter invocation requires an H1 invocation already in `STARTED`; installed connector code never self-authorizes
  - exact current C1 compatibility, invocation binding, and contract-ready receipt must match the started invocation
  - exact H1 intent, tool identity, and arguments SHA prevent connector-call substitution after authorization
  - connector arguments/results are bounded immutable plain JSON; adapter receives a frozen request
  - receipt carries hashes/provenance only; raw result remains outside the receipt
  - no dynamic plugin loading, shell-string execution, secret materialization, retry, H1 completion, budget mutation, or authority widening occurs inside the adapter bridge
  - provider-specific connectors may implement the interface without changing the shared governance spine

- [x] **P13 — Governed connector outcome + reconciliation bridge**
  - exact X1 replay fence must match run / invocation / capability / intent before provider adapter entry
  - pre-dispatch P12 validation refusal remains a refusal and never fabricates an uncertain external outcome
  - successful provider execution binds the exact replay-fence SHA and P12 adapter-receipt SHA while leaving H1 completion to the caller
  - once provider adapter code is entered, thrown errors are conservatively treated as uncertain external outcomes
  - malformed or non-JSON provider results after adapter entry are also reconciliation-required because an external side effect may already have occurred
  - uncertain outcomes open X1 `BLOCKED_PENDING_RECONCILIATION` with bounded error class + SHA-256 fingerprint only
  - no automatic retry/replay, H1 completion, budget mutation, secret materialization, or authority widening

- [x] **R2 — Review session identity + resume lineage**
  - bind review resume to exact repository identity, reviewed-source SHA, resolved-rule/config SHA, review mode, and R1 review-plan SHA
  - same-session resume refuses changed repository/source/rules instead of silently adopting new review truth
  - provider/model changes require explicit transition and produce parent -> child lineage evidence
  - model/provider lineage is provenance only and never grants review/fix authority
  - review presentation state may evolve separately from immutable review evidence
  - R1 fix authority remains independently governed; resume continuity never implies permission to mutate

- [ ] **P14 — Governed capability module lifecycle**
  - explicit module manifest binds module ID, version, capability IDs, contract descriptors, implementation fingerprints, and owned runtime resources
  - installation makes code available only; installed / enabled / authorized remain separate states
  - install/update/remove operations are explicit lifecycle transitions with bounded receipts
  - updates refuse dirty/local-conflict state rather than overwriting operator changes
  - removal may stop only module-owned runtime resources and must not delete unrelated state
  - pre-install/security inspection is evidence, not a trust grant
  - no arbitrary dynamic plugin execution, shell-string installer authority, or implicit P3/C1 registration

- [ ] **P9B — Governed reusable web-session hygiene**
  - pooled/reusable browser state remains behind explicit P8 session authority
  - every request reapplies its exact timeout/header/resource/network policy instead of inheriting prior request settings
  - effective per-request settings are fingerprinted so reuse cannot silently widen behavior
  - errored/poisoned pages are quarantined or evicted rather than returned to the reusable pool
  - one-shot anonymous operations remain separate from persistent authenticated-session operations
  - reuse is an optimization only; it never grants browser, secret, or economic authority

- [ ] **P15 — Scoped host-connector session lease**
  - host connection identity is distinct from permission to read files, write files, execute commands, invoke tools, or use MCP/skills
  - lease binds exact host/session/owner plus an explicit narrow capability set and expiry
  - permissions may be narrowed or revoked without disconnecting unrelated host capabilities
  - persistent configuration is evidence only; each active use rechecks current P3 authority
  - remote execution, filesystem mutation, tool invocation, and connector use remain separately scoped
  - host attachment never becomes ambient machine authority

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
- Package distribution proves build/export integrity only; installation never implies P3 authority and V1 consumes package exports rather than source paths.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
