# Contributing

Thank you for helping improve ToadAid Agent Capabilities.

The project is intentionally strict about authority boundaries. Useful capability is welcome; ambient authority is not.

## Before opening a change

Please keep changes narrow and explain:

- what capability or contract changes;
- what authority is required before and after the change;
- whether the change can mutate external state;
- replay/idempotency behavior;
- budget/resource bounds;
- durable-state or resume implications;
- new package/runtime dependencies;
- evidence or receipts produced;
- tests or proofs that demonstrate the intended behavior.

A capability becoming installed, available, or discoverable must not silently become authorized.

## Development

Requirements:

- Node.js 22+
- npm

From a checkout:

```bash
npm ci --include=dev
npm test
npm run package:check
npm run v1:proof
```

Before proposing a change, at minimum run the tests relevant to the edited surface. For changes to package exports, contracts, policy, invocation lifecycle, replay/reconciliation, continuity, or shared governance, run the full verification commands above.

## Pull requests

Prefer one coherent capability or repair per pull request. Keep unrelated cleanup separate.

Please avoid:

- widening default authority;
- embedding credentials or machine-specific secrets;
- shell-string execution where argv or typed requests suffice;
- blind retry of uncertain mutations;
- treating evidence as authorization;
- mixing read-only inspection authority with repair/mutation authority;
- adding provider-specific assumptions to shared governance without a clear boundary.

Repository review, Git mutation, merge authority, wallet authority, trading authority, and other consequential permissions should remain separately governed.

## Security issues

For suspected vulnerabilities, follow `SECURITY.md` rather than opening a public exploit report.
