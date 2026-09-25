# P8 — Scoped Browser Sessions

P8 adds an explicit lease boundary for browser state without changing the P1/P2 default of fresh, non-persistent browser contexts.

## Core rule

A browser session exists only under a current owner-bound, exact-origin-scoped, expiring lease. A serialized lease is evidence of prior allocation; it is never authority by itself.

## Capability identities

P8 installs two separate capabilities under P3, both `BLOCK` by default:

- `browser:session` — create, validate, use, and revoke a scoped session lease
- `browser:session-persist` — permit runtime-owned browser state to survive beyond an ephemeral context

Persistent state requires both current capabilities. `browser:session` never implies `browser:session-persist`.

P8 also does not imply `browser:evidence` or `browser:interaction`; callers still need those existing authorities for actual browser work.

## Lease model

A lease binds:

- session ID
- owner ID
- exact HTTP(S) origins
- creation and expiry timestamps
- `EPHEMERAL` or `PERSISTENT` state policy
- active/revoked lifecycle status

Default TTL is 30 minutes and the hard maximum is 24 hours. Leases are SHA-256 sealed and serialized as bounded plain JSON.

## Ownership and origin isolation

Every use rechecks the current caller owner ID and target URL origin. A lease issued to one owner cannot be reused by another owner, and an allowed origin cannot authorize a sibling/subdomain automatically.

URLs returned in session bindings persist only the origin; query strings and fragments are not retained.

## Persistent state

P8 does not store cookies, local storage, credentials, or Playwright storage-state bytes in the lease. For a persistent lease it emits an opaque `stateRef` derived from the owner/session binding. The embedding runtime owns the actual encrypted/isolated state store.

The opaque reference contains no raw owner identifier and cannot be chosen by the agent.

## Current-authority recheck

Creating a lease requires current `browser:session` authority. Persistent creation additionally requires current `browser:session-persist` authority.

Using a saved lease performs those checks again. Revoked or expired leases fail closed, and a valid old lease cannot resurrect authority revoked by P3 policy.

## Revocation

Revocation is owner-bound and sticky. A revoked lease remains cryptographically sealed as revoked and cannot be used again. Runtime-owned persisted state should be destroyed when the embedding runtime processes revocation or expiry.

## P1/P2 compatibility

P8 is intentionally a lease/state boundary rather than an automatic rewrite of `captureBrowserEvidence()` or `executeBrowserInteraction()`.

Fresh contexts remain the default. An embedding runtime may later opt a P1/P2 invocation into a validated P8 binding, but the session lease never widens the P1/P2 origin or action policies.

## Non-authority

P8 grants no wallet, Git, shell, trade, download, credential-entry, or arbitrary browser-navigation authority. It does not make authenticated browser sharing ambient, and it does not persist raw authentication material inside ToadAid receipts or leases.
