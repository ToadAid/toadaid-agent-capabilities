# P17B — Prepared Desktop Mutation Dispatch

P17B separates read-only provider preparation from the point where desktop
mutation may actually begin.

## Boundary

```text
P15/P3/C1/H1/X1/P16/Q1 preflight
        |
        v
provider.prepare()              read-only
        |
        v
short-lived host-sealed preparation ticket
        |
        v
provider generation + evidence + budget recheck
        |
        v
claim P16 head + Q1 mutation usage
        |
        v
provider.dispatch()             mutation boundary
        |
        v
success or X1 reconciliation
```

A preparation refusal is typed `REFUSED_BEFORE_DISPATCH`. It does not consume
the mutation budget, invalidate the current P16 observation head, or open X1
reconciliation.

## Preparation ticket

The host-sealed ticket binds:

- exact invocation/run/host/session/window/capability;
- normalized request hash;
- exact target-evidence hash;
- selected provider descriptor + generation;
- provider implementation fingerprint;
- provider nonce;
- provider-resolved target identity hash;
- trusted host preparation time and short expiry.

Dispatch rechecks ticket integrity, provider generation, current P16
observation, exact target evidence, and Q1 availability immediately before the
mutation boundary.

## Reconciliation law

Only failures after `provider.dispatch()` begins are treated as uncertain
external mutation outcomes and open X1 reconciliation.

Preparation throws, typed preparation refusals, provider-generation changes,
stale observations, stale target evidence, exhausted budget, and head-claim
races remain safe pre-dispatch refusals/errors.

## Coordinate targeting

Raw coordinate actions remain bounded by P16B exact-window geometry and
explicit coordinate-space evidence (`DESKTOP_PHYSICAL` or
`WINDOW_CLIENT_PHYSICAL`). The provider preparation ticket binds the exact
provider-resolved target identity so dispatch cannot silently retarget another
window, element, or coordinate target.

## Compatibility

The old single provider `interact()` member is retained structurally during the
alpha transition, but governed P17B execution refuses providers that do not
implement both `prepare()` and `dispatch()`.
