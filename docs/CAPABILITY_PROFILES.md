# Capability Profiles

Capability profiles are installation/request bundles. They are **not** policy.

```text
PROFILE != POLICY
PROFILE != P3 GRANT
PROFILE != PROVIDER AVAILABILITY
PROFILE != APPROVAL
```

A profile describes a useful set of capability contracts that a host may choose
to integrate. The host still owns provider binding, rollout state, current P3
authority, approvals, budgets, replay law, and final action policy.

## `safe-observe`

Generic Install P1 ships one profile:

[`profiles/safe-observe.json`](../profiles/safe-observe.json)

Requested capabilities:

| Capability | Purpose | Initial activation | Replay note |
| --- | --- | --- | --- |
| `browser:evidence` | bounded browser/navigation evidence | `OFF` | host adapter may use `SAFE_READ` only when its exact contract allows |
| `workspace:snapshot` | immutable/content-addressed workspace observation history | `OFF` | keep package/adapter-declared non-replayable semantics where durable history may change |
| `workspace:diff` | compare exact workspace-history snapshots | `OFF` | do not silently relabel replay class |
| `host:process-read` | bounded host process observation | `OFF` | suitable narrow adapters may be `SAFE_READ` |

The profile grants zero capabilities:

```json
{
  "activationDefault": "OFF",
  "installationGrantsAuthority": false,
  "capabilityGrants": []
}
```

## Explicit exclusions

`safe-observe` does not imply or request authority for:

- command execution;
- file write;
- process stop/signal;
- desktop interaction;
- clipboard write;
- registry write;
- app launch;
- secret materialization;
- deployment or Git mutation;
- wallet, trading, or economic execution.

A host may have some of those capabilities for unrelated reasons. Installing
this profile must not widen them.

## Provider mapping

A typical host maps:

```text
browser:evidence
  -> browser-runtime/provider adapter

workspace:snapshot
workspace:diff
  -> workspace-history adapter

host:process-read
  -> P15 host-session lease
  -> P18 host-services process-read adapter
```

The profile intentionally does not prescribe OS-specific provider code.

## Future profiles

Future profiles may bundle coding, desktop-observe, desktop-operate, connector,
or specialist capability sets. Each profile should preserve the same law:

- installation requests capability contracts;
- host policy grants authority;
- provider availability is separate;
- higher-consequence mutation profiles receive their own review/activation
  boundary rather than silently extending `safe-observe`.
