# V1 — Deterministic Agent0 Vertical Proof

V1 is the graduation proof for `@toadaid/agent-capabilities`.

It is intentionally not another capability. It proves that the already-forged capability primitives compose through the package boundary without gaining ambient authority.

## Clean-room boundary

`npm run v1:proof`:

1. builds the consumer distribution,
2. creates an npm tarball,
3. extracts that tarball into a temporary Agent0-style `node_modules/@toadaid/agent-capabilities`,
4. refuses repository `src/`, `test/`, or `scripts/` leakage in that installed package,
5. links only the already-installed declared `playwright-chromium` runtime dependency so the proof performs no registry/network download,
6. copies the deterministic consumer scenario outside the repository,
7. executes the scenario from the temporary consumer.

The consumer asserts that Node resolves `@toadaid/agent-capabilities` from the temporary consumer's `node_modules`, not from repository source paths.

## Vertical scenario

The proof exercises one coherent run:

- P3 current policy allows a bounded set of capabilities.
- C1 validates the exact `browser:evidence` contract.
- W1 compiles a contract-bound recipe and keeps ambient `review:fix` out because the recipe declares it forbidden.
- P4 creates the parent run state.
- P5 creates and starts a child task delegated only `browser:evidence`.
- Q1 reserves a child budget and records the child's actual tool/network/time cost.
- H1 binds the browser request to one invocation identity and rechecks policy before start.
- B1 records fresh DOM, invalidates it on navigation, refuses the stale token, and emits typed `DEGRADED` evidence after a deterministic navigation timeout.
- H1 completes with the degraded evidence hash rather than fabricated browser state.
- P5 completes the child and preserves its continuity.
- X1 creates a separate simulated `review:fix` invocation classified `NON_REPLAYABLE`; reconciliation confirms no mutation occurred, yet the same invocation still cannot be replayed and requires a new identity.
- P10 proves an interrupt cannot be resolved against a changed P4 state, then resolves against the exact bound state and produces a resume proof.
- P11 proves the agent sees only an opaque broker handle and that a saved materialization grant becomes unusable after current materialization authority is blocked.
- P4 checkpoints the parent, serializes it, restarts it, and proves current policy still governs resume.
- W1/C1 plan recheck refuses browser authority revoked after restart.

## Non-authority / non-execution law

V1 performs no wallet action, trading action, Git write, provider mutation, push, merge, secret fetch, raw credential injection, or live browser navigation.

The `review:fix` mutation is lifecycle/reconciliation state only; no review fix adapter is invoked.

The browser path uses B1 deterministic state/evidence functions only; no live browser or external network request is launched.

The secret path uses an opaque `secret-ref:<64 hex>` handle that is intentionally not derived from the raw-secret sentinel.

## Completion law

V1 is complete only when the packed clean-room consumer emits:

```text
V1_AGENT0_VERTICAL_OK {...}
```

Merely landing the harness is not graduation.
