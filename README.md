# ToadAid Agent Capabilities

Governed reusable capabilities for ToadAid agents.

This repository provides bounded capability modules that agents can consume without inheriting unrestricted host, wallet, repository, or execution authority.

Implemented lanes:

- **P1 — browser evidence:** open a permitted URL, observe rendered HTML, capture bounded DOM evidence and a screenshot receipt.
- **P2 — browser interaction:** execute a bounded operator-authorized plan of navigation, click, and type actions, then return evidence of the resulting state.
- **P3 — capability identity + policy:** keep capability installation separate from authority with sparse fail-closed policy resolution and decision traces.
- **P4 — resumable run-state capsule:** preserve objective, phase, authority evidence, references, and work state across compaction/restart with tamper-evident continuity.
- **P5 — persistent child-task lifecycle:** preserve subordinate task identity/state across failure and resume with fixed, non-widening delegated authority.
- **P6 — workspace Time Travel:** capture immutable content-addressed snapshots, deterministic diffs, governed restore, and bounded history maintenance outside project Git.
- **P7 — loop breaker + bounded repair:** fingerprint repeated failures, stop bounded loops, and optionally perform syntax-only tool-call repair without inventing semantics or authority.
- **R1 — OpenCodeReview adapter:** bind OCR Delegation Mode into deterministic review planning, mandatory coverage, P5 reviewer/reflection specs, and a separately authorized P6-backed fix boundary.
- **R2 — review session identity + resume lineage:** bind resumed review work to exact repository/source/rules/R1-plan evidence, require explicit provider/model transitions with predecessor lineage, and keep presentation state outside immutable review-session evidence.
- **P8 — scoped browser sessions:** bind optional browser state to explicit owner/origin/expiry leases while keeping persistent state behind separate authority.
- **P9 — adaptive web intelligence:** deterministic extraction, confidence-gated adaptive element relocation, sealed resumable crawl checkpoints, guarded XHR evidence, and an isolated Scrapling worker boundary.
- **P10 — governed human interrupts:** create typed durable human decision gates bound to exact P4 state, accept one schema-validated resolution, and produce a resume proof without turning human text into authority.
- **P11 — scoped secret leases:** keep raw secret bytes outside agent state while binding opaque handles to owner/provider/profile scope, exact consumer capabilities, short-lived materialization grants, and path-safe projection targets.
- **W1 — governed recipe compiler:** compile declarative parameters, response schemas, turn/retry ceilings, and explicit required/optional/forbidden capability sets through current P3 policy before P4/P5 execution.
- **H1 — capability invocation lifecycle:** bind request, current-policy authorization, start, progress/cancellation intent, completion/failure evidence, and resume assessment to one tamper-evident invocation identity.
- **Q1 — unified run budget ledger:** bound model/token/tool/network/retry/time/child consumption with append-only usage receipts and conservative child sub-allocation across the run tree.
- **C1 — capability contract + version discovery:** discover self-describing capability contracts, prove major/minor/feature compatibility before contract-aware W1 compile and H1 start, and bind compiled/runtime use to exact descriptor provenance.
- **X1 — idempotency / replay fence:** classify logical invocations before start, bind deterministic replay identity, and require reconciliation proof before retrying uncertain side effects.
- **B1 — browser resilience hardening:** invalidate stale DOM across navigation/failure, emit degraded evidence instead of fabricated state, distinguish same-document/full-document readiness, bound truncation, and provide deterministic semantic element IDs.
- **V1 — Agent0 graduation harness:** clean-room package-consumer proof exercises governed recipe, continuity, delegation, invocation, budgets, contracts, replay discipline, human interrupts, secret handles, browser degradation, checkpoint, and restart through public package boundaries; canonical proof emits `V1_AGENT0_VERTICAL_OK`.
- **D1 — package distribution surface:** build consumer-only `dist/src`, support Git installs through `prepare`, constrain packed files, and verify every public package export through the package boundary.
- **P12 — governed connector adapter boundary:** invoke provider-specific adapters only from an already-started H1 invocation whose capability/tool/intent/arguments and exact current C1 descriptor + implementation binding still match; connector receipts retain hashes/provenance without becoming authority.
- **P13 — governed connector outcome + reconciliation bridge:** require an exact X1 replay fence before provider entry, preserve pre-dispatch refusals, bind successful P12 receipts to replay classification, and turn any post-entry throw/malformed result into explicit `BLOCKED_PENDING_RECONCILIATION` without automatic retry or H1 completion.
- **P14 — governed capability module lifecycle:** bind module identity/version to exact P3 capability defaults, C1 descriptors, P12 adapter registrations, and owned-resource fingerprints; installation starts disabled, enablement never grants P3 authority, and update/remove refuse dirty owned state.
- **P9B — governed reusable web-session hygiene:** keep pooling behind current P8 lease authority, reset and reapply exact per-request settings on every checkout, fingerprint effective policy, quarantine errored/poisoned pages, and keep anonymous one-shot work separate from persistent authenticated state.
- **P15 — scoped host-connector session lease:** bind host/session/owner identity to a narrow maximum capability set and expiry while requiring fresh P3 `ALLOW` for every filesystem read/write, command execution, tool invocation, or connector/MCP use; narrowing never widens and persistent config remains provenance only.
- **P16 — governed desktop observation:** split display inventory, scoped screenshot, rich UI snapshot, and bounded exact-window wait-for into separate read-only host contracts behind a live P15 lease, fresh P3/C1/H1 checks, Q1 reservation, observation epochs, and degraded-on-failure evidence.
- **P17 — governed desktop interaction:** split pointer click/move, scroll, ordinary text input, and shortcuts into separately authorized mutations bound to current P16 evidence, live P15/P3/C1/H1 authority, Q1 budget, and X1 non-replayable uncertainty handling.
- **P18 — governed host services:** expose app launch, clipboard, process, file, notification, registry, and structured command execution as narrow BLOCK-by-default contracts with canonical scope, P15/P3/C1/H1/Q1 checks, and X1 reconciliation for mutations.
- **P14B — typed provider module composition:** compose connector, desktop-observation, desktop-interaction, and host-service registrations from exact enabled P14 lifecycle heads; separate known/installed/enabled capability truth, require explicit selection for duplicate providers, and bind dispatch resolution to lifecycle/registration/descriptor/implementation identity.

See [`BUILD_LIST.md`](./BUILD_LIST.md) for the canonical roadmap.

## Design rule

Capabilities are explicit. Authority is not ambient.

Agent intent never grants itself network or action authority. The embedding runtime/operator supplies the policy boundary.

Installed does not mean authorized.

Saved state does not grant authority.

Delegation can only narrow authority.

Workspace history never lives inside or rewrites project Git.

Loop breakers may halt work as a safety invariant; bounded repair requires explicit authority and never invents semantics or authority.

Review inspection never implies review fixes, and external review engines never receive sovereign runtime authority.

Review resume lineage is provenance, not permission. R2 may prove that a resumed review is bound to the same repository/source/rules/plan and explicitly record a provider/model transition, but it never grants `review:inspect`, `review:fix`, or workspace mutation authority.

Browser session leases never imply browser action authority, and persistent authenticated state is never ambient or shared by default.

Adaptive web evidence never implies arbitrary HTTP, browser-action, stealth, or economic authority; the Scrapling worker is isolated behind typed policy.

Human interrupt responses are typed run data, never capability grants; resume requires the exact bound P4 state and a sealed resolved interrupt.

Secret leases contain opaque broker handles, never secret bytes; materialization requires fresh secret and consumer authority, and revocation can only narrow access.

Recipes declare workflow intent and capability bounds; compiled plans are tamper-evident non-authority state and must be rechecked against current P3 policy before execution or resume.

Invocation records are evidence, not permission tokens; authorization is rechecked immediately before start, cancellation requests do not imply side effects stopped, and already-started resumed work requires reconciliation instead of blind retry.

Run budgets are accounting state, not capability grants; child allocations reserve parent fuel and already-spent or reserved capacity is never silently recreated on resume.

Capability contract discovery is compatibility evidence, not authority. Contract-aware plans and invocations still require current P3 permission, and a changed implementation descriptor requires explicit recompile/rebind instead of silent adaptation.

Replay fences are retry-discipline evidence, not authority. Unknown external outcomes remain blocked until reconciliation; non-replayable mutations never become replayable merely because a transport timed out.

Browser resilience evidence is recovery state, not browser authority; stale DOM is refused after navigation/capture failure, degraded receipts never fabricate page state, and recoverable does not mean automatically retryable.

Package installation makes code available; it never grants authority. Distribution checks prove export/build integrity only, and V1 must consume the package boundary instead of repository source paths.

Connector adapters are runtime implementations, not grants. P12 only invokes an adapter after exact H1/C1 identity and argument binding; provider-specific code cannot widen authority, silently swap implementation provenance, materialize secrets, or claim invocation completion on its own.

Connector execution uncertainty is evidence, not permission to retry. P13 requires X1 replay classification before provider entry and converts any post-entry ambiguity into reconciliation while leaving H1 active; only X1 reconciliation may later determine whether retry, no retry, or a new invocation is required.

Capability-module lifecycle is availability state, not authority. P14 requires module-owned capabilities to default `BLOCK`, separates installed / enabled / authorized states, binds C1 + P12 registration provenance, and permits update/removal only from exact clean module-owned resource state; it never executes arbitrary installer shell or grants policy permission.

Reusable browser state is an optimization, not permission. P9B rechecks P8 on checkout and before returning persistent state to the pool, forces reset-before-apply for every request, fingerprints the exact effective timeout/header/resource/network policy, refuses sensitive authentication headers, and quarantines any errored, poisoned, stale-authority, or stale-lease page instead of reusing it.

Host attachment is identity, not machine authority. P15 separates `host:session` from filesystem read/write, command execution, tool invocation, and connector use; the lease is only a maximum scope, every active use rechecks current P3 authority plus the runtime-owned current lease head, stale predecessor leases are refused after narrowing/revocation, and saved connection configuration can prove provenance without granting access.

Desktop observation is evidence, not interaction authority. P16 requires explicit display/region/window scope, a current P15 lease head, exact H1 arguments, current C1 implementation provenance, and Q1 reservation before adapter entry; exact-window observations publish a runtime-owned current observation head before adapter entry, old receipts cannot keep old element references alive after a newer/degraded epoch, adapter artifact kinds are request-bound, and failures produce `DEGRADED` evidence with no reusable element references.

Desktop interaction is mutation, not observation. P17 splits pointer click/move, scroll, ordinary text input, and shortcuts into separate BLOCK-by-default capabilities; every dispatch requires current P16 exact-window evidence, a live P15 lease, fresh P3/C1/H1 authority, Q1 budget, and an X1 `NON_REPLAYABLE` fence. The exact P16 head is atomically claimed into `PENDING` before adapter entry so a fresher observation cannot be overwritten by a stale action, raw coordinates require explicit bounded-region evidence unless display geometry is separately proven, ordinary text input requires receipt-bound P16 `ORDINARY_TEXT` target evidence, shortcuts require a real command-modifier chord, and uncertain post-entry outcomes require X1 reconciliation instead of blind replay.

Host-service authority is narrow and operation-specific. P18 separates reads from writes/destructive actions, requires a live P15 lease plus exact P3/C1/H1 and Q1 checks for every use, requires realpath-enforced canonical root/path contracts for filesystem access, and uses structured absolute executable + argv + explicit bounded cwd + non-inherited opaque env bindings with `shell=false`, `elevation=NONE`, and no UNC/device executable path. P18 v1 treats host mutations as `NON_REPLAYABLE`, process-stop requires fresh adapter-enforced process identity evidence, and uncertain post-entry mutations enter X1 reconciliation. Runtime adapters receive the opaque content references and notification text needed to perform authorized work, while raw file/clipboard/command/provider content and those runtime references never enter authority receipts.

Provider composition is availability evidence, not authority. P14B admits only exact enabled P14 lifecycle heads into dispatch, retains adapter-kind-specific runtime types, refuses ambiguous providers without an exact selection, and makes disable/remove/update/re-enable invalidate stale provider bindings. Known, installed, and enabled capability projections never imply P3 `ALLOW`.

## Graduation proof

Run `npm run v1:proof` from an installed checkout. The harness packs the current package, extracts it into a temporary Agent0-style consumer, links only the already-installed declared Playwright runtime dependency (no registry/network access), and executes the deterministic vertical scenario through package imports. V1 closes only when the command emits `V1_AGENT0_VERTICAL_OK`.
