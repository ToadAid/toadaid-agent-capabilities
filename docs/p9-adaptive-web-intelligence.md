# P9 — Adaptive Web Intelligence

P9 adds deterministic web extraction, change-tolerant element relocation, bounded resumable crawling, and explicit XHR evidence behind the existing ToadAid capability-policy boundary.

The design borrows useful ideas from Scrapling without granting Scrapling MCP, shell, model, or ambient host authority.

## Capability identities

P9 installs five capabilities under P3. All are `BLOCK` by default:

- `web:extract` — deterministic structured extraction
- `web:adaptive-locate` — bounded structural candidate relocation
- `web:crawl` — bounded resumable crawl planning/checkpointing
- `web:xhr-capture` — guarded browser background API evidence
- `web:stealth-fetch` — optional stealth fetch mode; always separate from the base operation

A caller that may extract does not automatically gain crawl, XHR, or stealth authority.

## Scrapling worker boundary

`workers/scrapling_worker.py` is a one-request/one-response JSON worker. The TypeScript host constructs the request only after current capability authorization succeeds.

The worker receives no P3 authority object and cannot widen policy. It receives only the already-normalized request boundary:

- operation
- exact allowed top-level/resource origins
- response/item bounds
- private-network policy
- extraction/candidate/XHR spec

The normal HTTP path performs only GET requests and follows redirects manually so each redirect target is checked before the request is sent.

The browser path installs a pre-navigation Playwright route through Scrapling `page_setup` that:

- allows only GET/HEAD
- refuses unauthorized network origins
- resolves hosts and refuses private/local/reserved addresses unless the runtime policy explicitly permits them
- blocks WebSockets when the installed Playwright surface supports `route_web_socket`

Scrapling's own safe-redirect behavior remains useful defense-in-depth, but ToadAid does not treat it as the authority boundary.

The worker is intended to run in an isolated runtime/container. It does not expose Scrapling MCP or a Python shell to the agent.

### Runtime dependency

The worker requires Python 3.10+ and Scrapling fetcher/browser extras. A runtime should pin a reviewed compatible Scrapling version and install browser dependencies, for example:

```text
pip install "scrapling[fetchers]"
scrapling install
```

P9 was designed against the current Scrapling 0.4.15 interface. The TypeScript side validates its own worker schema and does not consume Scrapling's unversioned CLI/MCP output directly.

## Deterministic extraction

`buildScraplingWorkerRequest()` validates a bounded extraction spec before the worker is invoked:

- named fields
- CSS or XPath selector
- text, HTML, or one attribute value
- per-field item ceilings
- global extracted-item and value-size ceilings

`parseScraplingWorkerResponse()` accepts only declared fields and refuses undeclared output, oversized values, unauthorized final origins, and private/local resolved addresses when private networking is disabled.

Persisted worker URLs omit query strings and fragments.

## Adaptive element relocation

P9 does not allow a model to decide that a visually similar element is "close enough."

The worker returns bounded element fingerprints. The TypeScript host computes a deterministic similarity score over:

- tag
- stable attributes (volatile `href`, `src`, and `style` are ignored)
- normalized text tokens
- parent tag/attributes/text
- sibling tags
- DOM path tags

A candidate must meet the configured minimum confidence. If the top two candidates are inside the ambiguity margin, the result is `AMBIGUOUS` rather than silently choosing one.

The default minimum confidence is 0.65, intentionally stricter than Scrapling's current 40% adaptive default.

## XHR evidence

`web:xhr-capture` is a separate capability.

The default body mode is `HASH_ONLY`; each captured response carries bounded metadata, byte length, content type, and SHA-256. A bounded text excerpt is available only when the caller explicitly requests `BOUNDED_TEXT`.

XHR evidence never grants API execution authority.

## Crawl continuity

`web:crawl` uses a sealed checkpoint instead of treating model context as crawl state.

A checkpoint contains:

- crawl/owner identity
- revision and predecessor SHA-256
- pending and seen URL sets
- per-origin request counts and next delay
- exact P4 run capsule SHA-256 binding
- optional exact P5 child-task SHA-256 binding

Resuming a checkpoint requires the current P4/P5 continuity values to match exactly. The hashes are continuity evidence, not authority tokens; current `web:crawl` authorization is still required on every mutation.

Query-bearing URLs are refused in persisted resumable checkpoints so secrets/tokens are not silently written into crawl state. Such URLs may still be used by non-persistent single fetch operations under policy.

## Crawl budgets and throttling

Crawls have explicit bounds for:

- maximum URLs
- maximum depth
- maximum concurrency
- per-origin request count
- minimum/maximum inter-request delay
- target response latency
- backoff factor

429/503 or explicit block signals increase the per-origin delay. Successful fast responses gradually reduce delay, never below the configured minimum.

Discovered URLs are deduplicated and must remain inside the authorized origin set before they can enter the checkpoint.

## Stealth fetch

Stealth is never implied by extraction, adaptive locating, XHR capture, or crawl authority.

`fetchMode: STEALTH` requires the base operation capability plus current `web:stealth-fetch` authority. This keeps anti-bot behavior an explicit operator decision instead of a default personality trait of the agent.

## Non-authority

P9 does not grant arbitrary HTTP methods, shell execution, Scrapling MCP authority, wallet/trading authority, browser interaction authority, credentials, or host filesystem access.

Web evidence remains evidence. It never becomes economic or mutation authority by itself.
