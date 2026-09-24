# P2 — Governed Browser Interaction

P2 layers bounded interaction on the P1 browser boundary. The agent can propose navigation, click, and type actions, but the runtime/operator separately decides which action kinds and origins are authorized.

## Authority split

`BrowserInteractionRequest` contains agent intent:

- initial URL
- ordered action plan
- targets and text needed by those actions

`BrowserInteractionPolicy` contains authority:

- exact top-level/resource origins
- explicitly allowed action kinds
- maximum action count
- target/text size limits
- per-action timeout
- P1 evidence bounds

The request cannot widen any of those limits.

## P2 action model

Supported actions are intentionally narrow:

- `navigate` — HTTP(S) navigation to an explicitly authorized top-level origin
- `click` — one unique visible target
- `type` — fill one unique visible text input or textarea

Targets may be identified by CSS, visible text, or form label. A target must resolve to exactly one visible element before the action executes.

P2 refuses typing into password, file, hidden, disabled, read-only, contenteditable, or otherwise non-text-writable elements.

## Network boundary

P2 inherits the hardened P1 network policy:

- only `GET` and `HEAD` are allowed
- all frame navigations require top-level-origin authority
- resource origins cannot silently become navigation origins
- service workers are blocked
- WebSockets are blocked
- downloads are disabled
- popups are immediately closed

A click can still trigger a `GET`, and badly designed remote systems can attach side effects to `GET`. Only authorize click/navigation on origins where that risk is acceptable.

## Receipts and sensitive text

The structured action receipt never copies typed text or raw target descriptions. Targets are represented by locator kind plus SHA-256 fingerprint; typed actions record only character count.

Persisted URLs omit query strings and fragments.

The final screenshot can visually contain text that was typed into the page. P2 is therefore **not a secret-entry capability**. Do not use it for passwords, API keys, seed phrases, signing secrets, or other sensitive values.

## Non-authority

P2 does not grant shell execution, arbitrary JavaScript evaluation, host filesystem access, browser-profile reuse, wallet signing, transaction execution, repository mutation, or unrestricted network access.
