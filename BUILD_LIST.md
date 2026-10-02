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
  - SHA-sealed self-describing descriptor registry with capability ID, contract ID, major/minor version, feature set, and enforceable request/result/receipt schema fingerprints
  - exact-major / minimum-minor / required-feature compatibility checks; unknown or incompatible installed capabilities fail closed
  - deprecation refuses by default unless the caller explicitly opts into that exact deprecated contract
  - contract-aware W1 profiles cover every required/optional recipe capability before base W1 compilation
  - truly absent optional capabilities remain explicit skips; installed optional capabilities must advertise a compatible contract
  - compiled enabled capability bindings retain exact semantic descriptor SHA; semantic changes require recompile rather than silent adoption
  - H1 contract binding ties capability + run + invocation + intent to the compatible descriptor and must pass while the invocation is `AUTHORIZED`
  - discovery and schema fingerprints are provenance and compatibility evidence only; they never grant P3 authority
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

- [x] **P14 — Governed capability module lifecycle**
  - explicit module manifest binds module ID, version, capability IDs, contract descriptors, implementation fingerprints, and owned runtime resources
  - installation makes code available only; installed / enabled / authorized remain separate states
  - install/update/remove operations are explicit lifecycle transitions with bounded receipts
  - updates refuse dirty/local-conflict state rather than overwriting operator changes
  - removal may stop only module-owned runtime resources and must not delete unrelated state
  - pre-install/security inspection is evidence, not a trust grant
  - no arbitrary dynamic plugin execution, shell-string installer authority, or implicit P3/C1 registration

- [x] **P9B — Governed reusable web-session hygiene**
  - pooled/reusable browser state remains behind explicit P8 session authority
  - every request reapplies its exact timeout/header/resource/network policy instead of inheriting prior request settings
  - effective per-request settings are fingerprinted so reuse cannot silently widen behavior
  - errored/poisoned pages are quarantined or evicted rather than returned to the reusable pool
  - one-shot anonymous operations remain separate from persistent authenticated-session operations
  - reuse is an optimization only; it never grants browser, secret, or economic authority

- [x] **P15 — Scoped host-connector session lease**
  - host connection identity is distinct from permission to read files, write files, execute commands, invoke tools, or use MCP/skills
  - lease binds exact host/session/owner plus an explicit narrow capability set and expiry
  - permissions may be narrowed or revoked without disconnecting unrelated host capabilities
  - persistent configuration is evidence only; each active use rechecks current P3 authority
  - remote execution, filesystem mutation, tool invocation, and connector use remain separately scoped
  - host attachment never becomes ambient machine authority

- [x] **P16 — Governed desktop observation**
  - split read-only host observation into explicit `host:display-inventory`, `host:screenshot`, `host:ui-snapshot`, and `host:wait-for` capability contracts
  - observation requires a live P15 host/session lease plus fresh P3/C1/H1 authority; machine attachment alone never grants visibility
  - screenshots may be scoped to exact display(s) or bounded desktop regions so unrelated screen content is not captured by default
  - rich UI snapshots expose bounded accessibility/DOM-derived element evidence separately from fast screenshot-only capture
  - every observation binds exact host/session, display/window identity, observation epoch, capture parameters, and evidence SHA-256
  - `host:wait-for` performs bounded local polling for declared UI conditions with explicit timeout/interval ceilings and Q1 accounting rather than burning repeated model turns
  - capture failure produces typed `DEGRADED` evidence and invalidates dependent element references; stale observation state is never silently reused
  - observation artifacts and element metadata are evidence only and never grant click/type/filesystem/shell or other mutation authority

- [x] **P17 — Governed desktop interaction**
  - split desktop mutation into explicit `host:pointer-click`, `host:pointer-move`, `host:scroll`, `host:text-input`, and `host:shortcut` contracts; no omnibus `computer-control` capability
  - every interaction requires a live P15 lease plus fresh P3/C1/H1 authority for the exact action capability
  - semantic UI element references bind to the exact P16 host/session/window/observation epoch that produced them; navigation, focus/window replacement, or fresh incompatible observation makes old references stale
  - coordinate actions require bounded finite coordinates inside the authorized display/region and never silently retarget another monitor/window; v1 raw coordinates require an explicit bounded region unless display geometry is separately proven
  - text-input authority is separate from pointer authority; secret/password entry remains separately governed and cannot be inferred from ordinary text-input permission
  - click/type/drag/shortcut operations are classified through X1 before dispatch; uncertain external outcomes require reconciliation rather than blind replay
  - interaction receipts bind intent, target evidence SHA, action parameters hash, resulting observation reference when available, and bounded error provenance without persisting raw sensitive text
  - interaction state never widens filesystem, process, registry, command, network, economic, or provider authority

- [x] **P18 — Governed host service capabilities**
  - expose host services as narrow contracts such as `host:app-launch`, `host:clipboard-read`, `host:clipboard-write`, `host:process-read`, `host:process-stop`, `host:file-read`, `host:file-write`, `host:notification`, `host:registry-read`, `host:registry-write`, and `host:command-exec`
  - read/write/destructive surfaces remain distinct even when the underlying OS adapter implements them in one module
  - filesystem capabilities require explicit bounded path scope with canonicalization, traversal/symlink escape refusal, and separate read vs mutation authority
  - process-stop, registry-write, file-write, and command execution are mutation capabilities; P18 v1 requires `NON_REPLAYABLE` X1 classification and reconciliation on uncertain outcomes, while process-stop additionally requires fresh process-identity evidence enforced by the adapter contract
  - `host:command-exec` accepts structured executable + argv + explicit bounded cwd + non-inherited env policy; no ambient shell-string authority, implicit elevation, UNC/device executable path, or ambient cwd/env inheritance
  - app launch/control, clipboard, process, registry, filesystem, command, and notification use each recheck the live P15 lease and current P3/C1/H1 authority
  - adapters run with least available host privilege and never convert the connected user's OS permissions into automatic agent permissions
  - P14 module lifecycle may install an OS-specific implementation, but installation/enabled state never authorizes any P18 service
  - host-service receipts remain bounded provenance/evidence; raw clipboard data, command output, secrets, and file contents stay outside authority state

## Provider-runtime integration lane

- [x] **P14B — Typed provider module composition**
  - generalize P14 manifests from connector-only registrations to a discriminated union of connector, desktop-observation, desktop-interaction, and host-service adapter registrations
  - share exact adapter/capability/tool/contract/descriptor/implementation bindings while retaining adapter-kind-specific validation and typed P16/P17/P18 runtime interfaces
  - compose enabled module projections into one runtime provider registry without treating enabled state as P3 authority
  - distinguish known capability definitions from actually installed module capabilities
  - refuse duplicate active capability/tool bindings unless the runtime supplies one explicit provider selection; legacy/structured host capability aliases must not create ambiguous dual bindings
  - bind provider selection to module lifecycle record SHA, adapter registration SHA, contract descriptor SHA, and implementation fingerprint
  - prove disabled, removed, stale, conflicting, or mismatched provider registrations cannot enter runtime dispatch
  - add a clean package-consumer proof using a fixture specialized host provider through public exports

- [x] **C1B — Contract / implementation identity separation**
  - keep semantic contract identity separate from provider implementation identity so Windows/Linux/multiple compatible providers may implement one contract without pretending the contract changed
  - semantic descriptors bind capability ID, contract ID/version, feature set, and enforceable request/result/receipt schema fingerprints
  - provider implementation descriptors bind module/provider ID, adapter kind/ID, supported contract/features, platform requirements, and implementation fingerprint
  - invocation binding retains exact contract descriptor SHA + selected adapter registration SHA + implementation fingerprint; provider changes require explicit rebind
  - schema IDs without enforceable digests must not be described as self-describing contract truth

- [x] **P19 — Provider selection + availability + health projection**
  - separate `KNOWN`, `INSTALLED`, `ENABLED`, `AVAILABLE`, and `AUTHORIZED`; none may silently imply another
  - health refines availability as `AVAILABLE_HEALTHY`, `AVAILABLE_DEGRADED`, or `UNAVAILABLE` and remains non-authority state
  - compose the active P3 installed manifest from built-ins plus installed/enabled module projections instead of treating the full capability catalog as installed truth
  - select one explicit compatible provider for the current host/session; fail closed on duplicate compatible providers until an explicit selection exists
  - bind availability to live provider/module/host-session identity without granting action authority
  - prove provider disappearance, degradation, restart, module disable/remove, or selection change invalidates stale runtime bindings

- [x] **P16B — Observation evidence semantics hardening**
  - treat bounded wait timeout (`matched=false`) as a valid observation with explicit `completionReason: MATCHED | TIMED_OUT`, not malformed adapter output
  - bind live element/window evidence to provider generation/evidence namespace so provider restart makes old live references provably stale
  - exact-window observation emits authorized geometry with explicit coordinate space and display-topology evidence so P17 raw-coordinate targeting has a valid contract path
  - distinguish `DESKTOP_PHYSICAL` from `WINDOW_CLIENT_PHYSICAL` coordinates rather than overloading raw x/y semantics
  - bind numeric display selection to display-inventory/topology epoch rather than treating display indexes as durable monitor identity
  - require `now + maxWallClockMs <= P15 lease.expiresAt` for wait operations; cancellation truth distinguishes requested, delivered, confirmed-quiescent, and uncertain

- [x] **P17B — Prepared desktop mutation dispatch**
  - separate provider read-only preparation from the mutation boundary so target/evidence/focus/generation validation may refuse cleanly before dispatch without opening X1 reconciliation
  - preparation ticket binds request/parameter hash, selected provider generation/fingerprint, exact resolved target identity, short expiry, and provider nonce
  - claim mutation lifecycle/budget state at the actual dispatch boundary rather than merely on entry to provider code
  - fix the currently unreachable raw-coordinate path by consuming P16B exact-window geometry + explicit coordinate-space evidence
  - typed `REFUSED_BEFORE_DISPATCH` is a safe refusal; failure/transport loss after dispatch begins remains reconciliation-required
  - no provider may silently retarget a changed window/element after preparation

- [x] **P18B — Host-service identity + containment contracts**
  - [x] **P18B-P1 — Host identity foundations:** governed process-read references for stop, provider generation/evidence namespace binding, explicit registry view, P15 lease-duration containment, and legacy/new alias conflict refusal.
  - [x] **P18B-P2 — Execution/content containment:** executable identity + argv profiles, child-process/termination/quiescence bounds, and narrow runtime content resolution for content/value/stdin/environment references.
  - bind `host:process-stop` to a governed `host:process-read` reference carrying receipt/evidence SHA, provider evidence namespace/processRef, and observation time
  - add explicit registry view `REGISTRY_32 | REGISTRY_64`; never inherit worker architecture as authority semantics
  - command/app executable authority binds exact executable identity/hash or trusted allowlisted identity plus capability-specific argv profile; absolute path alone is insufficient
  - define child-process policy, process-count bounds, termination policy, and confirmed timeout quiescence for command execution
  - define a narrow bounded runtime content resolver for `contentRef` / `valueRef` / `stdinRef` / environment references; adapters never receive ambient secret/content-store authority
  - require long-running host operations to fit inside remaining P15 lease lifetime
  - document/deprecate legacy `host:filesystem-read`, `host:filesystem-write`, and `host:command-execute` versus structured P18 names so both families cannot become an operator-policy trap

- [x] **H1/X1B — Reconciliation terminal closeout**
  - [x] **H1/X1B-P1 — Reconciliation-locked H1 core:** explicit `RECONCILIATION_REQUIRED` lifecycle lock plus terminal `RECONCILED` truth bound to exact resolved X1 SHA/finding/disposition/proof.
  - [x] **H1/X1B-P2 — Producer wiring:** route connector, desktop-interaction, and host-service uncertain outcomes through the H1/X1 lock so current invocation truth cannot bypass reconciliation closeout.
  - consume exact resolved X1 reconciliation evidence into a terminal H1 transition instead of leaving reconciliation and invocation lifecycle separately mutable
  - prevent H1 `COMPLETED`/`FAILED` outcomes that contradict open or resolved reconciliation truth
  - terminal evidence binds the exact reconciliation SHA and disposition
  - represent reconciled-executed, reconciled-not-executed, and outcome-unknown truth explicitly enough that the old invocation cannot be silently reused

- [x] **D2 — Capability-specific package surfaces**
  - add package subpath exports for policy, invocation, contracts, modules, host-session, desktop-observation, desktop-interaction, host-services, and browser-runtime
  - verify host/provider consumers can import authority/types without traversing or installing browser runtime implementation code such as Playwright
  - keep one package initially; split packages only when independent release/install boundaries justify it
  - add clean consumer proofs for each declared subpath and fail if browser-only dependencies leak into host-only surfaces

## Security-audit specialist lane

> Research source: `cloudflare/security-audit-skill`. Adopt the useful security-audit workflow as a governed ToadAid capability rather than granting an external skill ambient authority.

- [x] **SEC1 — Security audit evidence + threat-model contract**
  - bind each audit to exact repository identity, source revision/tree SHA, declared scope, configuration/rule-set fingerprint, and run identity
  - reconnaissance produces a bounded architecture/trust-boundary snapshot before hunting begins
  - derive target-specific attack classes from the repository instead of assuming one generic checklist is complete
  - canonical finding states are `CANDIDATE`, `CONFIRMED`, `NEEDS_VALIDATION`, and `REJECTED`; suspicion never silently becomes a vulnerability
  - evidence references and source locations are immutable plain data; security findings never grant mutation authority

- [x] **SEC2 — Coverage ledger + attack-class planning**
  - maintain a durable `(area × attack class)` coverage ledger with explicit unexplored/thin/covered states
  - every hunter assignment binds exact scope, attack class, source revision, budget, and predecessor coverage state
  - gap analysis selects thin or unexplored cells deterministically instead of repeatedly reviewing the same files
  - repeated audits extend prior coverage while changed source invalidates only the affected evidence/coverage lineage
  - coverage percentage is evidence of inspection breadth only; it never means the code is secure

- [x] **SEC3 — Isolated security Hunter children**
  - spawn P5-bounded security-research children with read-only source access by default and Q1 model/tool/network/time budgets
  - each Hunter receives one narrow attack class and repository slice rather than unrestricted whole-repo authority
  - Hunters may emit candidates plus reproduction/proof plans but cannot confirm their own findings
  - child outputs bind exact source/evidence SHA and preserve disagreements rather than collapsing them into one verdict
  - no Hunter receives fix, Git push, merge, secret materialization, live economic, or unrelated host authority

- [x] **SEC4 — Adversarial validation + independent re-verification**
  - candidate validation runs in a fresh child/context whose objective is to disprove the finding before confirming it
  - the discovering Hunter and confirming validator must be distinct audit identities; self-confirmation is refused
  - `NEEDS_VALIDATION` remains first-class whenever proof cannot safely or deterministically establish exploitability
  - confirmed findings require bounded reproduction evidence plus exact source binding; rejected findings retain the disproof reason and evidence fingerprint
  - optional final re-verifier independently checks confirmed source locations and proof claims before report publication
  - provider/model diversity may be recorded as provenance but never treated as proof by itself

- [ ] **SEC5 — Governed security execution sandbox**
  - active proof execution requires a dedicated sandbox capability separate from ordinary repository read/review authority
  - default network is disabled; environment is sanitized; writable paths are scratch-only; CPU/memory/process/wall-clock limits are explicit and Q1-accounted
  - target build/test/probe commands use structured executable + argv + bounded cwd with no ambient shell-string, inherited secrets, or host-home authority
  - proof artifacts leave the sandbox only through bounded content-addressed evidence references
  - if required sandbox guarantees are unavailable, execution is refused or the finding stays `NEEDS_VALIDATION` rather than pretending it was confirmed
  - timeout/crash/unknown execution outcomes never trigger blind replay of side-effecting proof steps

- [ ] **SEC6 — Durable resumable audit state + source-change invalidation**
  - persist reconnaissance, attack-class plan, coverage ledger, candidate/validation states, evidence references, and child-task lineage through P4/P5
  - resume requires the exact repository/source/config identity expected by the audit; source drift produces explicit stale/invalidated evidence rather than silent reuse
  - completed validated findings remain immutable historical evidence while changed affected regions re-enter the coverage queue
  - budget exhaustion, interrupted children, and provider changes resume through explicit state transitions with no duplicate uncontrolled hunting
  - audit state is non-authority data and cannot restore revoked repository, sandbox, network, or host capabilities

- [ ] **SEC7 — Canonical findings + verified report generation**
  - canonical machine-readable `findings.json` is schema-validated before any human-facing report is generated
  - findings carry severity/risk fields, source locations, attack class, proof status, evidence references, affected revision, and validator provenance without embedding secrets
  - generate `REPORT.md`, detailed finding views, coverage summary, and `NEEDS_VALIDATION` queue mechanically from canonical audit state
  - report generation must not upgrade candidate state, alter proof truth, or hide rejected/uncertain evidence
  - provide deterministic diff/report comparison between audit revisions so newly introduced, fixed, regressed, and still-open findings are distinguishable

- [ ] **SEC8 — Agent0 security specialist + separately governed repair handoff**
  - expose the audit workflow as an Agent0/ToadGang security specialist using W1 recipes and the shared P3/C1/H1/Q1/P5 spine
  - support repository preflight, targeted audit, gap-fill audit, validation-only, and re-verification modes as explicit bounded recipes
  - security inspection authority is separate from `review:fix`, file mutation, Git commit/push, PR, and merge authority
  - confirmed findings may produce a bounded repair proposal or handoff package, but a finder/validator cannot merge its own fix
  - repairs should snapshot source before mutation and bind the post-fix diff/test evidence back to the originating confirmed finding
  - package/adapter integration remains provider-neutral so Codex, Claude-like harnesses, local models, or future workers can consume the same governed security capability

## Standing design rules

- Capabilities are explicit; authority is not ambient.
- Agent intent never grants itself authority.
- Saved state never grants or widens authority.
- Delegation can only narrow authority; it can never widen it.
- Workspace history is external to project Git and restore requires separate authority.
- Loop breakers may halt without authority; repair may fix syntax only and never invent semantics or authority.
- Review inspection never implies review fixes; external review engines are deterministic evidence providers, not sovereign runtimes.
- Security discovery, validation, and reporting never imply fix, Git, merge, sandbox, secret, network, host, or economic authority; the finder cannot confirm or merge its own work.
- Browser session leases are owner/origin/expiry scoped; saved or persistent state never grants browser action authority.
- Adaptive web evidence remains evidence; crawl/XHR/stealth authority is explicit and never implies mutation or economic authority.
- Human interrupt responses are typed data, not approvals or authority; resume is bound to the exact paused run state.
- Secret handles are references, never credentials; materialization requires fresh current authority and raw secret bytes stay runtime-owned.
- Recipe definitions declare workflow bounds; compiled plans are non-authority state and must be rechecked against current P3 policy before execution/resume.
- Invocation lifecycle evidence never becomes authority; fresh policy checks govern start/resume and already-started work requires reconciliation before replay.
- Budgets, capability contracts, and replay fences bound execution economics/compatibility/retries without granting new authority.
- Package distribution proves build/export integrity only; installation never implies P3 authority and V1 consumes package exports rather than source paths.
- Host attachment grants connectivity, not machine authority; observation, interaction, filesystem, process, registry, and command execution remain separately authorized.
- Desktop observation is evidence only; element references expire with their bound observation/window epoch and can never self-authorize interaction.
- Desktop interaction is narrowly capability-scoped; pointer/text/shortcut authority never implies host-service, secret, economic, or provider authority.
- Shared infrastructure stays provider/model neutral.
- Prefer useful vertical capability cuts over framework ceremony.
- Live economic authority remains outside this repository unless explicitly introduced through a separate governed boundary.
