# P1 — Browser Evidence Core

P1 is a read/observe capability. It opens a policy-authorized HTTP(S) page in a fresh Chromium context and returns bounded rendered evidence plus a screenshot receipt.

## Authority split

The agent supplies only `BrowserEvidenceRequest.url`.

The embedding runtime/operator supplies `BrowserEvidencePolicy` and `BrowserEvidenceRuntime`. The policy owns the top-level origin allowlist, optional resource origins, time and evidence bounds, and screenshot behavior. The runtime owns the artifact root.

An agent therefore cannot grant itself another network origin or choose an arbitrary screenshot filesystem path.

## P1 behavior

- HTTP(S) navigation only.
- Exact top-level origin allowlist.
- Resource-origin authority does not grant navigation authority.
- Cross-origin resources require an explicit resource-origin allowlist entry.
- Browser-originated HTTP requests are limited to `GET` and `HEAD`; attempted write methods are blocked and recorded.
- Service workers are blocked so routed requests cannot bypass the HTTP request policy.
- WebSocket connections are blocked and recorded by origin.
- Downloads are disabled.
- Browser context is fresh and non-persistent.
- DOM evidence is bounded by policy.
- Input values are not collected.
- Persisted request/final URLs and anchor hrefs omit query strings and fragments.
- Screenshots are generated under `<artifactRoot>/browser/` with runtime-generated UUID names.
- Receipts include screenshot SHA-256, page status/title, policy, DOM evidence, blocked network origins, and blocked HTTP methods.

## Non-authority

P1 grants no shell execution, repository mutation, wallet signing, transaction execution, arbitrary filesystem target, browser profile reuse, or credential-store access.

## Security boundary / known P1 limit

Exact-origin routing is not DNS pinning. P1 does not yet defend an embedding host against DNS-rebinding behavior from an otherwise operator-approved hostname. Until a later network-hardening cut adds address-resolution policy, run this capability inside the agent sandbox and do not approve untrusted arbitrary origins from a privileged host network.

`GET`/`HEAD` enforcement prevents ordinary browser write methods, but an incorrectly designed remote service can still attach side effects to a `GET`. Origin approval therefore remains an authority decision.
