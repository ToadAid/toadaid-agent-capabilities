# C1 — Capability Contract + Version Discovery

C1 gives an embedding runtime a bounded, self-describing compatibility layer for installed capabilities without turning implementation metadata into authority.

P3 still answers **whether** a capability may run. C1 answers **which contract** the runtime currently implements and whether that contract is compatible with what a recipe or invocation expects.

## Descriptor registry

A runtime publishes one descriptor for each capability implementation it wants to advertise. Each descriptor carries:

- capability ID
- contract ID
- major/minor contract version
- bounded feature set
- request schema ID
- receipt schema ID
- implementation ID
- implementation fingerprint SHA-256
- optional bounded deprecation metadata

The registry is sorted and SHA-256 sealed. Duplicate descriptors for the same capability are refused.

Implementation fingerprints are provenance only. They never authorize execution.

## Compatibility law

A requirement fixes:

- exact capability ID
- exact contract ID
- exact major version
- minimum minor version
- required feature set
- whether a deprecated descriptor is explicitly accepted

Compatibility requires all of those constraints to hold. Unknown installed capabilities, contract-ID changes, major-version changes, insufficient minor versions, missing features, and unaccepted deprecations fail closed.

Minor version compatibility is one-way: a runtime at `1.4` may satisfy a requirement for `1.2`; a runtime at `1.1` may not.

## W1 integration

`compileGovernedRecipeWithContracts()` validates a recipe contract profile before calling base W1 compilation.

The profile must cover every required and optional recipe capability.

- required capability with no compatible contract -> refuse
- installed optional capability with no compatible contract -> refuse
- truly absent optional capability -> remain an explicit W1 optional skip

Only capabilities enabled in the compiled base W1 plan receive durable contract bindings. Those bindings retain the exact descriptor SHA seen during compilation.

`assertContractBoundRecipePlanCurrent()` performs the normal W1 current-authority check and then rechecks every enabled contract binding. If the descriptor or implementation fingerprint changed, the old plan refuses with a recompile-required result instead of silently adopting the new implementation.

Newly appearing optional capability/authority still does not widen an old W1 plan.

## H1 invocation boundary

`createCapabilityInvocationContractBinding()` binds one H1 invocation to:

- invocation ID
- run ID
- capability ID
- request intent SHA-256
- normalized contract requirement
- exact compatible descriptor SHA

The binding intentionally follows stable invocation identity/intent rather than an H1 revision hash, because H1 advances from `REQUESTED` to `AUTHORIZED` before execution.

Immediately before H1 start, `assertCapabilityInvocationContractReady()` requires the invocation to be `AUTHORIZED`, verifies the stable invocation identity/intent, rechecks current contract compatibility, and refuses if the descriptor changed.

P3 still performs its own fresh pre-start authority check. C1 compatibility never substitutes for P3 permission.

## Deprecation

Deprecated contracts refuse by default. A caller must explicitly opt into the exact deprecated requirement to use it. Deprecation metadata is bounded and may point to a replacement contract ID.

A deprecation marker cannot claim a version newer than the descriptor that carries it.

## Discovery

`discoverCapabilityContracts()` returns bounded descriptors plus the sealed registry hash. Discovery is read-only compatibility evidence.

C1 does not load plugins, install packages, grant capabilities, execute tools, update adapters, choose providers, or mutate runtime policy.

## Non-authority

A matching contract proves compatibility, not permission.

The runtime still needs:

- P3 current capability authority
- W1/H1 execution boundaries where applicable
- Q1 available budget
- later X1 replay discipline for retryable/mutating work
