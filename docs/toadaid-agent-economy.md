# ToadAid Agent Economy — Hosted MCP, ACP, and Base Settlement

Status: design direction, not an implementation promise.

This document records the architecture we believe fits ToadAid best as its capabilities become useful to agents outside our own stack.

## 1. Core idea

ToadAid should remain local-first and modular while also supporting optional hosted access.

The public surface should eventually have two distinct entry points:

- **Hosted MCP** — other agents buy or invoke a bounded tool/capability.
- **Hosted ACP** — other agents hire or hand work to a bounded ToadAid specialist agent/session.

Both surfaces consume the same governed capability spine underneath. Payment, transport, protocol choice, or agent identity must never bypass ToadAid authority rules.

```text
                         TOADAID
                            |
              +-------------+-------------+
              |                           |
        Hosted MCP                    Hosted ACP
      "use a tool"                 "hire an agent"
              |                           |
              +-------------+-------------+
                            |
                 governed capability spine
             P3 / C1 / H1 / Q1 / P5 / X1
                            |
         contracts / authority / budgets / receipts
                            |
                 provider-neutral adapters
```

## 2. MCP is the tool shop

MCP should expose narrow capabilities rather than our whole runtime.

Examples:

- browser evidence / research
- repository review
- security audit
- security validation
- knowledge retrieval / compiled knowledge
- bounded code analysis
- future specialist tools

A caller pays for or receives entitlement to a declared capability contract, submits a bounded request, and receives structured output plus evidence/receipts.

MCP should not imply persistent agent identity, broad workspace ownership, or ambient machine authority.

## 3. ACP is the specialist doorway

ACP should expose persistent or resumable specialist work rather than single tool calls.

Examples:

- ToadAid Coder
- Security Auditor
- Researcher
- Reviewer
- future domain specialists

An ACP client can hand a task to a specialist, exchange messages, receive progress, pause/resume, and let that specialist use multiple ToadAid capabilities internally under a bounded job budget.

The exact ACP protocol adapter may evolve. ToadAid's internal specialist/session contract should remain provider- and protocol-neutral so a future protocol change does not force us to redesign the agent core.

## 4. Local and hosted are peers

Hosted access must not replace the local system.

```text
Local ToadAid
  - local MCP
  - local ACP/session adapters
  - private local agents
  - local models and local tools

Hosted ToadAid
  - hosted MCP capability endpoints
  - hosted ACP specialist endpoints
  - metering / entitlement / settlement
  - shared or paid specialist services
```

A user should be able to choose:

1. run the capability locally,
2. connect to a hosted ToadAid capability,
3. hire a hosted ToadAid specialist.

## 5. Base is the settlement rail, not the authority system

Base is a strong fit for future machine-to-machine settlement, especially where x402-style pay-per-request flows and USDC are useful.

The important ToadAid rule is:

> **Payment grants entitlement to request a service. Payment never grants authority to bypass policy.**

A future hosted invocation may look like:

```text
service discovery
      |
      v
price / terms
      |
      v
Base / x402 payment
      |
      v
ENTITLEMENT
      |
      v
capability contract compatibility
      |
      v
current authority check
      |
      v
budget reservation
      |
      v
bounded invocation
      |
      v
evidence + receipt + result
```

The settlement layer can change without changing the authority model.

Base, x402, USDC, agent wallets, identity, and reputation are therefore adapters/services around the capability system, not the capability system itself.

## 6. Entitlement is a separate state

Hosted distribution introduces one state our local capability model does not need to treat as authority: **ENTITLED**.

A useful lifecycle is:

```text
KNOWN
  -> ADVERTISED
  -> ENTITLED
  -> ENABLED
  -> AVAILABLE
  -> AUTHORIZED
  -> INVOKED
```

These states must remain distinct.

- `KNOWN` — ToadAid understands the capability contract.
- `ADVERTISED` — a provider offers it publicly or to a scoped customer.
- `ENTITLED` — payment/subscription/grant permits the customer to request it.
- `ENABLED` — the provider has enabled the implementation.
- `AVAILABLE` — the implementation is currently healthy/reachable.
- `AUTHORIZED` — current ToadAid policy permits this exact invocation.
- `INVOKED` — the governed lifecycle has actually started.

Entitlement must never substitute for P3 authority, C1 compatibility, H1 lifecycle checks, Q1 budget accounting, or X1 replay rules.

## 7. Agent spending is also governed capability use

A ToadAid agent may eventually buy external services from other agents.

That must be handled as a separately authorized economic capability, not as ordinary tool use.

A specialist may receive:

- a maximum job budget,
- a maximum per-purchase amount,
- an allowlist of providers/service classes,
- a maximum number of purchases,
- an expiry,
- explicit network/chain scope,
- required receipts and reconciliation rules.

The agent may choose among permitted services, but it cannot widen its own spending authority.

```text
Human / parent agent
        |
        v
bounded economic budget
        |
        v
ToadAid specialist
        |
        +--> own capabilities
        +--> permitted external paid capability
        +--> permitted inference/data/compute service
        |
        v
work product + spend receipts
```

## 8. Selling tools and selling workers are different products

### MCP product model

Sell a bounded capability invocation.

Possible pricing units:

- per request
- per repository/review slice
- per browser/network budget
- per security-validation run
- per token/compute allowance

### ACP product model

Sell bounded specialist work.

Possible pricing units:

- per job
- per time budget
- per model/tool budget
- per milestone
- customer-provided maximum spend allowance

The ACP specialist can internally consume MCP-like capabilities, but the customer still buys a job with declared boundaries rather than unlimited agent access.

## 9. Canonical product principle

ToadAid should sell **capabilities and specialists**, not unrestricted access to a machine.

A third-party agent should be able to request:

```text
security.audit
browser.evidence.capture
review.inspect
repo.analyze
knowledge.query
```

without receiving:

```text
ambient shell
ambient filesystem
ambient secrets
wallet signing
Git push / merge
unbounded child agents
unbounded network
```

Higher-authority actions, when ever offered, require their own explicit contract, entitlement, current policy decision, budget, invocation lifecycle, and receipt.

## 10. Evidence and receipts are part of the product

A paid agent service should not return only prose.

Where useful, the result should bind:

- capability contract/version
- selected provider implementation
- request/intent hash
- source/repository revision where applicable
- budget consumed
- evidence references
- result fingerprint
- timestamps
- settlement/entitlement reference without embedding secrets
- reconciliation state for uncertain external effects

This gives machine customers something they can verify and reason about rather than trusting a free-form answer blindly.

## 11. Provider neutrality remains mandatory

The same ToadAid capability should be consumable through different front doors and different model providers.

```text
Codex -----------+
Claude-like -----+
Local model -----+--> MCP / ACP adapters --> ToadAid contracts/runtime
Other agent -----+
```

Likewise, a ToadAid specialist may use different inference providers internally without changing the semantic capability contract.

Protocol adapter, model provider, payment rail, and capability contract are separate identities.

## 12. Likely responsibility split

### `toadaid-agent-capabilities`

Owns the reusable governance and capability semantics:

- contracts
- authority/policy
- invocation lifecycle
- budgets
- child-task boundaries
- replay/reconciliation
- evidence/receipts
- entitlement semantics when introduced

It should **not** become the hosted storefront itself.

### ToadAid MCP service

Owns:

- MCP transport/public discovery
- hosted capability catalog
- customer/provider routing
- metering
- entitlement lookup
- settlement adapter
- invocation-to-capability bridge

### ToadAid ACP service

Owns:

- specialist/session transport
- persistent job/session identity
- progress/resume interface
- specialist selection
- job budget envelope
- delegation into the shared capability spine

### ToadAid specialists / Agent0 descendants

Own domain reasoning and workflow:

- coder
- security auditor
- researcher
- reviewer
- future specialists

They do not own the authority system.

### Mirror / governed host boundary

Where host or desktop access is required, it remains a separately governed runtime boundary. Hosted payment or ACP session state never becomes host authority.

## 13. Suggested rollout order

Do not build the marketplace before the tools are worth buying.

### Stage A — useful local capabilities

Finish and harden real tools and specialists first.

### Stage B — hosted MCP

Expose a small number of proven read-only or low-risk capabilities with clear contracts, quotas, receipts, and manual/free entitlements first.

### Stage C — hosted ACP

Expose one useful specialist with bounded persistent jobs, explicit budgets, pause/resume, and no ambient economic authority.

### Stage D — Base/x402 settlement

Add machine-payable entitlement to mature services. Keep settlement outside authority decisions.

### Stage E — agent-to-agent economy

Allow separately governed ToadAid agents to purchase approved third-party capabilities with bounded spending authority.

### Stage F — discovery/reputation/marketplace

Only after repeated real usage proves which services are useful should ToadAid add broader discovery, reputation, provider competition, or marketplace behavior.

## 14. Non-goals

The first implementation should **not**:

- create a ToadAid token just because payments exist,
- put every internal receipt or state transition onchain,
- make Base mandatory for local/private use,
- let payment bypass human/operator policy,
- grant buyers broad runtime or host access,
- merge MCP, ACP, specialists, capability contracts, and settlement into one giant repository,
- require one model vendor,
- require one protocol adapter forever,
- auto-purchase third-party services without explicit economic authority and spend ceilings,
- treat an onchain identity or reputation score as proof that a capability is safe.

## 15. Standing doctrine for the agent economy

1. **MCP sells the tool; ACP hires the specialist.**
2. **Payment grants entitlement, not authority.**
3. **The capability contract is more durable than the transport or payment rail.**
4. **Local-first remains supported; hosted is optional.**
5. **Economic authority is explicit, scoped, budgeted, and revocable.**
6. **A paid result should carry evidence and receipts where the domain allows it.**
7. **Agents may be both buyers and sellers, but neither role grants ambient authority.**
8. **Provider/model/protocol/payment identities remain separate.**
9. **Useful capability comes before marketplace ceremony.**
10. **Keep the stack modular enough that each piece can evolve independently.**

## 16. North-star picture

```text
                         TOADAID CLOUD
                              |
                  +-----------+-----------+
                  |                       |
              Hosted MCP              Hosted ACP
             capability calls        specialist jobs
                  |                       |
                  +-----------+-----------+
                              |
                  Entitlement / Metering
                              |
          Base/x402/USDC settlement adapter (optional)
                              |
                 Governed capability runtime
              P3 C1 H1 Q1 P5 X1 + receipts
                              |
          +-------------------+-------------------+
          |                   |                   |
      Browser              Security             Coder
     capabilities          specialist          specialist
          |                   |                   |
          +-------------------+-------------------+
                              |
               local/host/provider adapters
```

The long-term product is not simply an MCP server or an ACP server. It is a governed capability economy in which ToadAid tools and specialists can be consumed locally or remotely, and where machine-to-machine payment is another bounded input to the same authority system rather than a replacement for it.
