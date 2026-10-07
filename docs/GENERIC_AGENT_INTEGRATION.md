# Generic Agent Integration

This document defines the provider-neutral seam for integrating ToadAid Agent
Capabilities into an unrelated agent.

The host remains authoritative for identity, memory, model/provider choice,
tool dispatch, approvals, secrets, lifecycle, and final action policy. ToadAid
Agent Capabilities supplies reusable capability contracts and governance
machinery; it does not become the host agent.

## Architecture

```text
host model/tool request
        |
        v
host central dispatcher
        |
        v
P3 current capability authority
        |
        v
C1 semantic contract + implementation/provider binding
        |
        v
H1 invocation lifecycle
        |
        +---- Q1 budget
        +---- X1 replay/reconciliation
        |
        v
provider-neutral capability surface
        |
        v
host/provider adapter
        |
        v
bounded result + code-owned evidence/receipt
        |
        v
host-controlled model projection
```

The integration invariant is:

```text
KNOWN != INSTALLED != ENABLED != AVAILABLE != AUTHORIZED != INVOKED
```

## Distribution

During alpha, `@toadaid/agent-capabilities` remains `"private": true` to prevent
accidental npm publication.

Use the repository installer to create an exact local package artifact:

```bash
npm ci --include=dev
bin/toadaid-capabilities-install-agent --check-only
bin/toadaid-capabilities-install-agent --profile safe-observe
```

Then install the emitted `.tgz` into the host project. The installer itself does
not modify the host. To fail closed on any checkout other than the exact
reviewed commit, add `--expect-commit <reviewed-40-hex-commit>` (see
[`INSTALL_AGENT.md`](../INSTALL_AGENT.md)). On native Windows the entrypoint is
`bin\toadaid-capabilities-install-agent.cmd`; it runs the same core and
produces the byte-identical artifact.

## Central-dispatch requirement

Do not let capability-backed tool implementations bypass the host's central
dispatch seam.

A host integration should have one code-owned path that:

1. validates the model/tool arguments;
2. resolves the requested capability ID;
3. resolves current P3 authority;
4. binds the invocation to the exact semantic contract;
5. binds the exact provider/adapter implementation identity;
6. classifies replay behavior before dispatch;
7. reserves/updates the Q1 budget;
8. starts the H1 invocation;
9. rechecks current authority immediately before provider entry;
10. enters the bounded provider adapter; and
11. projects only code-owned receipt metadata back to the model.

Raw provider entrypoints should not also be exposed as ordinary model tools.

## `safe-observe` provider seams

### `browser:evidence`

Use the browser runtime/provider surfaces. Keep navigation/evidence limits,
origin policy, runtime generation, and bounded returned evidence host-owned.
Installing the package does not create a browser session or grant navigation.

### `workspace:snapshot` and `workspace:diff`

Use the workspace-history surface for immutable/content-addressed observation
history. The host chooses the workspace root, history root, exclusion law,
file/byte ceilings, ownership identity, and lifecycle.

Do not confuse workspace-history snapshots with a host's replaceable coding
baseline or Git.

### `host:process-read`

Use P15 `host-session` plus P18 `host-services`. A safe initial adapter should
return only fields the host explicitly chooses to expose. For example, a Linux
provider may return PID plus process name without exposing command line,
environment, cwd, open files, signals, or execution authority.

Host attachment proves connectivity/identity only. It grants no ambient machine
authority.

## Activation and policy

Treat the generated profile as a requested integration shape, not policy.

Recommended rollout:

```text
OFF
  ↓ host wiring + refusal tests
BLOCK
  ↓ provider binding + positive-path tests
ALLOW
```

Each `ALLOW` decision remains host policy. The host may enable only a subset of
a profile.

Never infer `ALLOW` from package installation, provider availability, a model
request, a previous successful call, a receipt, or a human message that was not
processed through the host's real approval/policy boundary.

## Receipt projection

If receipt metadata is shown to the model, project it from a code-owned branded
or otherwise unforgeable result channel. Do not trust arbitrary provider/model
data merely because it has receipt-shaped fields.

Useful receipt identity normally includes:

```text
capabilityId
authorization decision identity
contract binding / descriptor identity
provider descriptor / generation identity
adapter / implementation identity
invocation identity
replay classification / fence identity
budget ledger identity
toolExecuted
authorityGranted
```

Individual capability adapters may add bounded capability-specific receipt
fields.

## Required host tests

Before enabling `ALLOW`, prove:

- OFF: provider not entered;
- BLOCK: provider not entered;
- ALLOW: only the intended provider is entered;
- unknown/malformed rollout mode fails closed;
- current authority is re-resolved before provider entry;
- revoked authority cannot reuse stale authorization;
- provider-generation drift invalidates old binding;
- contract mismatch refuses before provider dispatch;
- replay behavior matches the declared class;
- budget exhaustion refuses or terminates according to Q1 law;
- model-visible receipt projection rejects receipt-shaped untrusted data;
- one capability cannot inherit another capability's authority;
- host identity, memory, secrets, approval law, and unrelated tools are
  unchanged by installation or refusal; and
- all capability-specific result bounds are enforced.

## Host-specific adapters

The package intentionally cannot know every host runtime.

A host adapter owns details such as:

- browser engine/session construction;
- workspace root and durable history location;
- OS-specific process observation;
- desktop bridge;
- filesystem implementation;
- notification backend;
- connector/provider client; and
- runtime-specific tool registration.

Those choices must remain narrower than the semantic capability contract and the
host's current policy.

## Live activation

A coding agent may prepare and test the integration, but the operator should
deliberately choose the first `ALLOW` transition.

For higher-consequence capability families—mutation, command execution,
secrets, deployment, wallet/economic action, process control, or desktop
interaction—use a separate operator decision and capability-specific review.
Do not extend `safe-observe` by implication.
