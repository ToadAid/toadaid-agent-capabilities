# C1B contract / implementation identity separation

C1B separates portable semantic compatibility from the concrete provider selected to execute it.

The semantic `toadaid.capability-contract.v2` descriptor binds the capability and contract IDs, major/minor version, feature set, and SHA-256 fingerprints for the request, result, and receipt schemas. A schema identifier without its enforceable digest is rejected. Changing these semantics changes the contract descriptor SHA and requires contract-aware plans to be recompiled.

The separate `toadaid.capability-provider-implementation.v1` descriptor binds module and provider IDs, adapter kind and ID, the supported semantic contract and features, normalized platform requirements, the exact adapter-registration SHA, and the implementation fingerprint. Module manifests seal these descriptors and the provider registry carries them into exact provider selection.

An H1 invocation binding records both identities: the semantic contract descriptor SHA and the selected provider descriptor, adapter-registration, and implementation fingerprint SHAs. The contract-ready check compares the current provider tuple with the original binding. Any provider change fails closed and requires an explicit new binding; it does not invalidate an otherwise unchanged cross-platform semantic contract.

Neither descriptor grants authority. P3 permission, module enablement, lifecycle freshness, and the existing H1/runtime guards remain independently required.
