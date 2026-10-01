# P14B — Typed provider module composition

P14B extends the P14 module manifest from connector-only registrations to the
four runtime adapter families currently governed by this package:

- connector
- desktop observation
- desktop interaction
- host service

The registration `schemaVersion` is the discriminant. Each family retains its
own normalization rules and typed runtime interface; composition does not turn
them into an untyped universal invocation surface.

## Composition model

`composeCapabilityProviderRegistry` accepts the current lifecycle head for each
module. It validates every envelope and rejects duplicate module heads. Removed
modules remain known but are not installed. Disabled modules remain installed
but do not contribute enabled capabilities or dispatchable providers. Only an
`INSTALLED_ENABLED` head can produce a provider binding.

The resulting registry publishes three separate manifests:

- `knownCapabilityManifest`: definitions known from supplied catalog entries
  and all supplied module heads
- `installedCapabilityManifest`: definitions from non-removed modules
- `enabledCapabilityManifest`: definitions from enabled modules only

These are availability projections, not P3 authority. Every module capability
continues to default to `BLOCK`, and dispatch still requires the existing
capability-specific P3/C1/H1/Q1/X1 checks.

## Provider identity and selection

Every selected binding retains:

- module ID, version, manifest SHA, and current lifecycle-record SHA
- adapter kind, ID, registration SHA, capability ID, and tool name
- C1 descriptor SHA and implementation fingerprint

One active `(capabilityId, toolName)` binding is selected automatically. Two or
more active candidates fail closed until the runtime supplies an exact
`CapabilityProviderSelection`. A selection is valid only for the precise live
lifecycle record, registration, descriptor, and implementation it names.
Disable, removal, update, re-enable, or implementation drift therefore makes an
old selection stale rather than silently retargeting it.

Legacy `host:filesystem-read`, `host:filesystem-write`, and
`host:command-execute` registrations cannot coexist with their structured P18
aliases in one active registry. P14B refuses that ambiguous configuration.

`resolveCapabilityProvider` also accepts an expected adapter kind, preventing a
registration selected for one runtime family from entering another family's
dispatch path.

`composeCapabilityRuntimeProviderRegistry` then binds the selected metadata to
actual typed connector, observation, interaction, or host-service provider
objects. Every implementation must match the selected module ID and exact
registration digest; missing, extra, stale, disabled, and unselected
implementations are refused. `resolveCapabilityRuntimeProvider` preserves the
adapter-kind-specific TypeScript interface at dispatch.

## Runtime truth

`assertCapabilityProviderRegistryCurrent` recomposes against current lifecycle
heads and refuses stale registry state. The registry and its SHA are evidence of
the provider projection; neither grants capability authority.
