# P11 — Scoped Secret Leases

P11 lets an embedding runtime give an agent a bounded reference to a credential without putting raw secret bytes into agent state, receipts, P4 run capsules, P5 child tasks, or capability policy.

## Capabilities

P11 installs two independent capabilities. Both are `BLOCK` by default:

- `secret:lease` — create an owner/provider/profile-scoped lease over an opaque secret handle
- `secret:materialize` — request a short-lived runtime materialization grant for one exact consumer capability and one exact projection target

Revocation is intentionally a safety narrowing operation. It does not require a capability grant; the embedding runtime remains responsible for authenticating who may invoke the revocation surface.

## Secret handles, never secret bytes

The P11 data model accepts only opaque handles of the form:

```text
secret-ref:<64-hex opaque-id>
```

There is no field for an API key, token, password, seed phrase, private key, cookie, or other secret material.

The 64-hex value is a broker-generated opaque identifier and MUST NOT be derived by hashing the secret material itself. The runtime-owned secret broker maps that handle to secret bytes outside this library. P11 never returns those bytes.

## Lease scope

A lease fixes:

- owner ID
- provider ID
- profile ID
- opaque secret handle
- exact consumer capability IDs that may use the secret
- exact permitted projection targets
- creation and expiry time

A lease is SHA-256 sealed. Revocation creates a one-way revision bound to the predecessor lease SHA.

A saved lease is not authority. Materialization rechecks current P3 authority every time.

## Capability-bound materialization

A materialization request succeeds only when all of the following remain true:

1. `secret:materialize` is currently `ALLOW`
2. the requested consumer capability is currently `ALLOW`
3. that consumer capability was included in the original immutable lease scope
4. owner/provider/profile exactly match the lease
5. the requested projection target is allowlisted by the lease
6. the lease is active and unexpired

A grant is short-lived (60 seconds by default, 5 minutes maximum) and can never outlive its lease.

At actual broker use time, `assertSecretMaterializationGrantUsable()` rechecks the sealed grant, sealed lease, expiry, and both current authority decisions again.

The grant still contains only the opaque handle. The external broker performs secret lookup/injection.

## Projection targets

P11 supports two narrow projection shapes:

- `ENV` — one validated environment variable name
- `FILE` — one portable relative path with mandatory mode `0600`

FILE targets reject absolute paths, drive/colon forms, backslashes, `.` / `..`, empty segments, NULs, and path traversal. `resolveSecretFileProjectionPath()` additionally proves the resolved target remains inside a runtime-owned projection root.

The runtime should create a fresh private projection directory, materialize only for the bounded invocation, and remove the projection immediately afterward.

## Provider/profile separation

Provider/profile are explicit lease dimensions rather than encoded inside a prompt. For example, an agent may hold a lease for:

```text
provider = github
profile = readonly
consumer capability = github:read
```

That lease cannot be materialized for `github:write`, another provider, another profile, or another owner even if the model asks.

## Interaction with P4/P5

P4/P5 may persist the lease ID or opaque secret handle as ordinary bounded data, but saved state never grants secret access. The current `secret:materialize` decision and current consumer-capability decision remain mandatory.

A child can use a secret only if its current P5/P3 authority permits both secret materialization and the exact consumer capability. Delegation therefore continues to narrow.

## Non-authority

P11 does not authenticate users, store secrets, fetch secrets, decrypt secrets, execute shell commands, inject environment variables, write credential files, sign transactions, or grant provider permissions.

It defines and verifies the lease/materialization boundary. The runtime-owned secret broker performs the final injection under the same current-policy checks.
