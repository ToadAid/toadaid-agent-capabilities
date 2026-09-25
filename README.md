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
- **P8 — scoped browser sessions:** bind optional browser state to explicit owner/origin/expiry leases while keeping persistent state behind separate authority.
- **P9 — adaptive web intelligence:** deterministic extraction, confidence-gated adaptive element relocation, sealed resumable crawl checkpoints, guarded XHR evidence, and an isolated Scrapling worker boundary.
- **P10 — governed human interrupts:** create typed durable human decision gates bound to exact P4 state, accept one schema-validated resolution, and produce a resume proof without turning human text into authority.
- **P11 — scoped secret leases:** keep raw secret bytes outside agent state while binding opaque handles to owner/provider/profile scope, exact consumer capabilities, short-lived materialization grants, and path-safe projection targets.
- **W1 — governed recipe compiler:** compile declarative parameters, response schemas, turn/retry ceilings, and explicit required/optional/forbidden capability sets through current P3 policy before P4/P5 execution.
- **H1 — capability invocation lifecycle:** bind request, current-policy authorization, start, progress/cancellation intent, completion/failure evidence, and resume assessment to one tamper-evident invocation identity.

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

Browser session leases never imply browser action authority, and persistent authenticated state is never ambient or shared by default.

Adaptive web evidence never implies arbitrary HTTP, browser-action, stealth, or economic authority; the Scrapling worker is isolated behind typed policy.

Human interrupt responses are typed run data, never capability grants; resume requires the exact bound P4 state and a sealed resolved interrupt.

Secret leases contain opaque broker handles, never secret bytes; materialization requires fresh secret and consumer authority, and revocation can only narrow access.

Recipes declare workflow intent and capability bounds; compiled plans are tamper-evident non-authority state and must be rechecked against current P3 policy before execution or resume.

Invocation records are evidence, not permission tokens; authorization is rechecked immediately before start, cancellation requests do not imply side effects stopped, and already-started resumed work requires reconciliation instead of blind retry.
