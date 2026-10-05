# ToadAid Agent Capabilities

**Status:** `0.1.0-alpha.0` — the current declared capability roadmap through SEC8 is implemented on canonical `main`  
**Runtime:** Node.js 22+  
**License:** Apache-2.0

Governed reusable capabilities for ToadAid agents.

ToadAid Agent Capabilities is the shared capability and governance spine for agents that need to browse, inspect, resume, delegate, use host services, interact with desktops, invoke providers, and perform bounded specialist work **without inheriting ambient authority**.

The core rule is simple:

> **Capabilities are explicit. Authority is not ambient.**

Installing code, attaching a host, saving state, discovering a provider, receiving a human response, or paying for a service never grants execution authority by itself.

## Architecture

```text
agent / specialist
       |
       v
W1 governed recipe
       |
       v
P3 current authority
       |
       v
C1 contract + implementation binding
       |
       v
H1 invocation lifecycle
       |
       +---- Q1 bounded budget
       +---- X1 replay / reconciliation discipline
       |
       v
provider / adapter / host capability
       |
       v
bounded result + evidence + receipts

P4/P5 preserve resumable parent/child continuity across interruption or restart.
```

The library keeps several kinds of truth separate:

```text
KNOWN != INSTALLED != ENABLED != AVAILABLE != AUTHORIZED != INVOKED
```

Those distinctions are deliberate. Availability is not permission, evidence is not authority, and continuity does not restore revoked rights.

## Capability map

### Governance, continuity, and bounded autonomy

- **P3 — capability identity + policy:** canonical capability IDs, sparse fail-closed policy, explicit `BLOCK`, and plain-data authority decision traces.
- **P4 — resumable run-state capsule:** tamper-evident objective/work/evidence continuity across compaction and restart.
- **P5 — persistent child-task lifecycle:** durable subordinate tasks with fixed delegated capability sets that can only narrow authority.
- **P6 — workspace Time Travel:** immutable content-addressed snapshots, deterministic diffs, governed restore, and bounded history outside project Git.
- **P7 — loop breaker + bounded repair:** repeated-failure detection plus syntax-only repair that cannot invent semantics or authority.
- **P10 — governed human interrupts:** typed durable decision gates bound to exact paused state; human text remains data, not a capability grant.
- **P11 — scoped secret leases:** opaque secret handles, short-lived materialization grants, and no raw secret bytes in durable agent state.

### Workflow, contracts, budgets, and replay discipline

- **W1 — governed recipe compiler:** declarative workflows with explicit required/optional/forbidden capabilities, turn ceilings, retry ceilings, and response schemas.
- **H1 — capability invocation lifecycle:** request, authorization, start, progress, cancellation intent, completion/failure, and resume evidence bound to one invocation identity.
- **Q1 — unified run budget ledger:** bounded model, token, tool, network, retry, time, and child-task consumption with conservative child allocation.
- **C1 — capability contract + version discovery:** exact semantic contract compatibility before compile and invocation.
- **C1B — contract / implementation identity separation:** semantic capability identity stays distinct from the selected provider/module/adapter implementation.
- **X1 — idempotency / replay fence:** classifies work before dispatch and blocks blind replay after uncertain external outcomes.
- **H1/X1B — reconciliation terminal closeout:** uncertain mutations remain reconciliation-locked until exact resolved X1 evidence closes the invocation truth.

### Browser and web capabilities

- **P1 — browser evidence:** permitted navigation, bounded DOM evidence, and screenshot receipts.
- **P2 — browser interaction:** bounded operator-authorized navigate/click/type plans with action limits and guarded network behavior.
- **P8 — scoped browser sessions:** owner/origin/expiry-bound browser state with separate persistent-session authority.
- **P9 — adaptive web intelligence:** deterministic extraction, adaptive element relocation, resumable crawl checkpoints, guarded XHR evidence, and an isolated Scrapling worker boundary.
- **P9B — reusable web-session hygiene:** reset-before-reuse, exact effective policy fingerprints, stale-authority checks, and poisoned-page quarantine.
- **B1 — browser resilience:** navigation epochs, stale-DOM refusal, degraded evidence, bounded truncation, and deterministic semantic element IDs.

### Review and repository work

- **R1 — OpenCodeReview adapter:** deterministic review planning and coverage with `review:inspect` kept separate from `review:fix`.
- **R2 — review session identity + resume lineage:** exact repository/source/rules/plan continuity and explicit provider/model transition provenance.

### Connectors, modules, and provider runtime

- **P12 — governed connector adapter boundary:** provider adapters may run only from an already-started, exactly bound invocation.
- **P13 — connector outcome + reconciliation bridge:** pre-dispatch refusal stays a refusal; post-entry ambiguity becomes reconciliation-required rather than automatic retry.
- **P14 — governed capability module lifecycle:** install, enable, update, and remove are explicit lifecycle states; installation never grants P3 authority.
- **P14B — typed provider module composition:** connector, desktop-observation, desktop-interaction, and host-service providers share one typed composition boundary.
- **P15 — scoped host-connector session lease:** host attachment proves identity/connectivity, not filesystem, command, tool, or connector permission.
- **P19 — provider selection + availability + health:** `KNOWN`, `INSTALLED`, `ENABLED`, `AVAILABLE`, and `AUTHORIZED` remain separate; stale provider generations invalidate old bindings.

### Desktop observation, interaction, and host services

- **P16 — governed desktop observation:** display inventory, bounded screenshots, UI snapshots, and exact-window wait operations behind current host and policy authority.
- **P16B — observation evidence semantics:** provider-generation binding, display-topology epochs, explicit coordinate spaces, and valid negative timeout evidence.
- **P17 — governed desktop interaction:** pointer, scroll, ordinary text input, and shortcut capabilities are separated and bound to current observation evidence.
- **P17B — prepared desktop mutation dispatch:** read-only target preparation happens before the mutation boundary so safe pre-dispatch refusal does not become false reconciliation.
- **P18 — governed host services:** narrow app, clipboard, process, file, notification, registry, and structured command capabilities with BLOCK-by-default authority.
- **P18B — host-service identity + containment:** process evidence, executable identity, argv profiles, registry views, lease containment, and bounded runtime content resolution.

## Security-audit specialist

The completed **SEC1–SEC8** lane turns repository security work into a governed specialist rather than an ambient superpower:

1. **SEC1 — threat-model contract:** exact repository/revision/scope binding and canonical finding states.
2. **SEC2 — coverage ledger:** durable area × attack-class planning with explicit unexplored/thin/covered truth.
3. **SEC3 — isolated Hunter children:** bounded read-only P5/Q1 security researchers with narrow attack classes and repository slices.
4. **SEC4 — adversarial validation:** a distinct validator tries to disprove candidates before confirmation; self-confirmation is refused.
5. **SEC5 — governed security sandbox:** optional proof execution with sanitized environment, scratch-only writes, bounded resources, and network disabled by default.
6. **SEC6 — durable audit state:** resumable reconnaissance, coverage, findings, evidence, and source-change invalidation.
7. **SEC7 — canonical reporting:** schema-validated `findings.json`, deterministic human reports, and preserved uncertain/rejected evidence.
8. **SEC8 — Agent0/ToadGang security specialist:** five bounded specialist modes plus a separately governed repair handoff bound to the shared P3/C1/H1/Q1/P5 spine.

The security law is intentionally strict:

> A finder cannot confirm its own finding, inspection does not imply repair authority, and a finder/validator cannot grant itself merge authority.

Confirmed findings may produce bounded repair proposals and verification packages, but file mutation, Git, PR, review, and merge remain separately governed.

See [`docs/sec8-security-specialist.md`](docs/sec8-security-specialist.md) and the SEC1–SEC7 documents under [`docs/`](docs/).

## Package surfaces

The package is `@toadaid/agent-capabilities`. During alpha it remains intentionally marked `"private": true` so npm publication cannot happen accidentally.

Git/checkout consumption is supported through the build boundary, and capability-specific subpath exports let host/provider consumers avoid importing unrelated runtime code:

```text
@toadaid/agent-capabilities
@toadaid/agent-capabilities/invocation
@toadaid/agent-capabilities/budget
@toadaid/agent-capabilities/contracts
@toadaid/agent-capabilities/replay
@toadaid/agent-capabilities/workspace-history
@toadaid/agent-capabilities/browser-resilience
@toadaid/agent-capabilities/policy
@toadaid/agent-capabilities/modules
@toadaid/agent-capabilities/host-session
@toadaid/agent-capabilities/desktop-observation
@toadaid/agent-capabilities/desktop-interaction
@toadaid/agent-capabilities/host-services
@toadaid/agent-capabilities/browser-runtime
```

`playwright-chromium` is an optional peer owned by the explicit `browser-runtime` surface. Host-only consumers do not need the browser runtime dependency.

See [`docs/d2-capability-specific-package-surfaces.md`](docs/d2-capability-specific-package-surfaces.md).

## Generic-agent installation

For an unrelated Node.js agent, start with [`INSTALL_AGENT.md`](INSTALL_AGENT.md).
Generic Install P1 provides a no-authority bootstrap, a provider-neutral host
integration contract, a bounded coding-agent install prompt, and the initial
[`safe-observe`](profiles/safe-observe.json) profile.

The installer produces an exact local package artifact plus a host-owned
integration manifest. It does **not** publish to npm, mutate the host, create
capability grants, bind providers, or switch any capability to `ALLOW`.

See:

- [`INSTALL_AGENT.md`](INSTALL_AGENT.md)
- [`docs/GENERIC_AGENT_INTEGRATION.md`](docs/GENERIC_AGENT_INTEGRATION.md)
- [`docs/AGENT_INSTALL_PROMPT.md`](docs/AGENT_INSTALL_PROMPT.md)
- [`docs/CAPABILITY_PROFILES.md`](docs/CAPABILITY_PROFILES.md)

## Verification

From a checkout:

```bash
npm install
npm test
npm run package:check
npm run v1:proof
```

`npm run package:check` proves declared export/build integrity and clean package-consumer boundaries.

`npm run v1:proof` performs the deterministic Agent0 clean-room consumer scenario through package imports. Graduation closes only when it emits:

```text
V1_AGENT0_VERTICAL_OK
```

The proof exercises governed recipe compilation, continuity, delegation, invocation, budgets, contracts, replay discipline, human interrupts, secret handles, browser degradation, checkpoint, and restart without granting wallet, trading, push, merge, or other live economic authority.

See [`docs/v1-deterministic-agent0-vertical-proof.md`](docs/v1-deterministic-agent0-vertical-proof.md).

## Standing authority laws

- **Installed does not mean authorized.**
- **Enabled does not mean authorized.**
- **Available does not mean authorized.**
- **Saved state does not grant authority.**
- **Delegation can only narrow authority.**
- **Evidence and receipts are not permission tokens.**
- **Human interrupt responses are typed run data, not capability grants.**
- **Secret handles are references, never credentials.**
- **Observation does not imply interaction authority.**
- **Host attachment does not imply machine authority.**
- **Unknown mutation outcomes require reconciliation, not blind retry.**
- **Package installation and provider discovery never widen P3 policy.**
- **Live economic authority remains outside this repository unless introduced through a separate governed boundary.**

## Documentation

- [`BUILD_LIST.md`](BUILD_LIST.md) — canonical capability roadmap and completion truth.
- [`docs/p3-capability-policy.md`](docs/p3-capability-policy.md) — capability identity and fail-closed policy.
- [`docs/p4-run-state-capsule.md`](docs/p4-run-state-capsule.md) — resumable agent state.
- [`docs/x1-idempotency-replay-fence.md`](docs/x1-idempotency-replay-fence.md) — retry/reconciliation discipline.
- [`docs/d2-capability-specific-package-surfaces.md`](docs/d2-capability-specific-package-surfaces.md) — package subpath boundaries.
- [`docs/sec8-security-specialist.md`](docs/sec8-security-specialist.md) — governed security specialist and repair handoff.
- [`docs/toadaid-agent-economy.md`](docs/toadaid-agent-economy.md) — future hosted MCP/ACP/Base settlement direction; **design direction, not an implementation promise**.

The full `docs/` directory contains the lane-by-lane contracts and proofs behind the summarized surfaces above.

## Engineering doctrine

The repository follows a simple rule:

> **Capability is the product. Ceremony is not the product.**

Verification, receipts, provenance, lifecycle state, and approval boundaries exist to make useful capability safe and inspectable. They are not substitutes for working capability.

Shared infrastructure stays provider/model neutral wherever practical, and the system prefers useful vertical cuts over framework ceremony.

## License

Licensed under the [Apache License 2.0](LICENSE).

## ToadAid community

ToadAid builds for the **Toadgang community, Tobyworld, builders, and the people**.  
ToadAid Agent Capabilities is one part of that larger effort: reusable capabilities that help agents do useful work while keeping identity, evidence, policy, and execution authority explicitly bounded.

If this project is useful to you, we would be grateful if you also took a little time to discover the community and world that inspired much of this work:

- 🐸 **Join the Toadgang community on Telegram:** [https://t.me/toadgang](https://t.me/toadgang)
- 📖 **Explore Tobyworld:** [https://tobyworld.app](https://tobyworld.app)
- 🌱 **Follow Toadgod and explore the lore on X:** [https://twitter.com/toadgod1017](https://twitter.com/toadgod1017)

There is no requirement to join any community in order to read, evaluate, or work with ToadAid projects under their published terms.

We believe tools are better when people, stories, builders, and communities grow around them.

**Built by ToadAid. Built for the Toadgang. Built for the people.**
