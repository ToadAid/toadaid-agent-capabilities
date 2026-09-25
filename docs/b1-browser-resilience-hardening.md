# B1 — Browser Resilience Hardening

B1 adds provider-neutral browser recovery state that can wrap P1/P2/P8/P9 without changing their authority model.

It does not add browser authority, retry authority, or a second browser engine.

## Freshness law

Browser DOM is valid only for the exact current navigation epoch and page identity.

`beginBrowserNavigation()` increments the epoch and immediately invalidates any prior fresh-DOM token. A successful capture creates a SHA-256 sealed token bound to:

- navigation epoch
- persisted page identity
- exact bounded DOM hash

`assertFreshBrowserDom()` refuses a token after navigation, URL/page identity change, capture failure, or token tampering.

Stale DOM is never used as fallback evidence.

## Degraded evidence

`recordBrowserCaptureFailure()` invalidates current DOM and emits bounded degraded evidence instead of inventing a page state.

The receipt contains:

- phase
- typed failure reason
- recoverability classification
- sanitized last-known URL
- error fingerprint SHA-256
- prior fresh DOM SHA only, never the prior DOM payload

Recoverable does not mean automatically retryable. H1/Q1/X1 still govern lifecycle, budget, and replay discipline.

## Navigation readiness

B1 distinguishes:

- `NONE`
- `SAME_DOCUMENT`
- `FULL_DOCUMENT`

Same-document navigation is ready without waiting for a new `DOMContentLoaded` event. A full-document readiness timeout becomes `DEGRADED`; page closure becomes `BLOCKED`.

This avoids both fixed sleeps and false timeouts for fragment/history-only navigation.

## Bounded DOM and truncation

`boundBrowserDomEvidence()` applies explicit ceilings for text, headings, and interactive elements.

Truncation is carried as evidence:

- `textTruncated`
- `headingsTruncated`
- `interactiveElementsTruncated`

Truncated output is never silently presented as complete.

## Stable semantic element identity

`stableInteractiveElementIds()` hashes bounded semantic element evidence rather than transient CDP/backend node IDs.

Identity uses normalized:

- tag
- role
- aria label
- visible text
- sanitized href path
- input type
- name

Duplicate semantic elements receive deterministic occurrence ordinals. Query strings and fragments never participate in element identity.

These IDs are evidence/relocation anchors, not permission to click an element. P2/P3 still govern interaction.

## Non-authority

B1 is resilience infrastructure only.

It does not:

- authorize navigation or interaction
- automatically retry a failed action
- reuse old DOM after failure
- widen session/origin scope
- preserve secrets from URLs
- grant X1 replay permission
- create wallet, Git, provider, or economic authority
