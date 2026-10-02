# P18B-P2 — Execution and content containment

P18B-P2 closes the execution/content half of the P18 host-service contract.

## Executable identity

`host:app-launch` and `host:command-exec` no longer rely on an absolute path as
sufficient executable authority. Immediately before dispatch the trusted host
runtime resolves a sealed executable binding for the exact host/session,
capability, and path.

The binding is either `EXACT_SHA256`, carrying the current executable hash, or
`TRUSTED_ALLOWLIST`, carrying a host-owned allowlist identity. The same binding
names one capability-specific argv profile. The host resolves that sealed
profile and checks argument count, required prefix, and forbidden exact
arguments before adapter entry. The adapter receives the sealed execution
binding but receives no policy resolver.

## Content resolution

Opaque references are host-side inputs, not adapter authority. Clipboard/file/
registry writes, app/command environment values, and command stdin are resolved
through one narrow callback bound to exact host/session/owner/capability,
purpose/name, reference, expected SHA-256, expected byte length, and a hard
maximum byte bound.

The host re-hashes resolved bytes and refuses mismatch before Q1 spend or
adapter entry. Adapter parameters redact raw `contentRef`, `valueRef`,
`stdinRef`, and environment `valueRef` strings. The adapter receives only
ephemeral resolved bytes plus hashes and lengths. No content-store or secret
resolver function crosses the provider boundary. Receipts store only the
resolved-content set SHA.

Because the adapter sees a redacted dispatch projection rather than the raw
H1 request, that projection has its own `dispatchParametersSha256`. Result
evidence and host-service receipts bind the original request hashes, the
provider-visible dispatch hash, executable binding SHA, and resolved-content
set SHA together so audit evidence cannot detach runtime containment truth
from the operation it describes.

## Command process containment

Every `host:command-exec` request declares `FORBID` or `ALLOW_BOUNDED` child
process policy, a hard child-process count, `TERMINATE_PROCESS_TREE` timeout
termination, and `REQUIRE_CONFIRMED` quiescence.

Adapter command results carry bounded execution evidence. Child-process counts
must fit policy. Any accepted command result requires confirmed process-tree
quiescence. A timeout is a known result only after termination was requested and
quiescence was confirmed. Malformed, over-bound, or non-quiescent post-dispatch
results remain uncertain mutation outcomes and enter X1 reconciliation.

## Authority law

Executable bindings, argv profiles, provider identity, and content resolution
are host-owned runtime truth. They refine what an already-authorized P3/P15/C1/
H1 invocation may do; none grants capability authority by itself.
