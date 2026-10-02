# SEC3 — Isolated security Hunter children

SEC3 binds the SEC2 coverage planner to the existing P5 child-task lifecycle and
Q1 unified run-budget ledger. It does not create a parallel security scheduler.

## P5 authority boundary

A SEC3 Hunter child has an exact ALLOW allowlist:

- `host:session`
- `host:file-read`

Any additional ALLOW in the child authority snapshot is refused. The child
therefore receives no fix, file-write, command-execute, connector, secret,
browser-interaction, Git, live-economic, or unrelated host authority.

The assignment still binds one repository area and one attack class. The
specialist source-path guard refuses reads outside the assignment's
repository-relative scope. A future host adapter must apply that same scope to
the concrete host-session/file-read lease.

## Q1 budget boundary

Each Hunter gets a real Q1 child allocation from the parent run-budget ledger.
The Q1 token/tool/network/time limits must fit inside the SEC2 assignment budget.

SEC3 additionally requires:

- positive but bounded model-request/token allowance;
- `networkRequests = 0`;
- `retries = 0`;
- `childTasks = 0`.

This makes the first Hunter contract local, non-recursive, and non-networked by
default. Later security lanes may add separately governed capabilities rather
than silently widening this contract.

## Output law

Hunters emit `CANDIDATE` findings only. They may attach a bounded plain-data
proof/reproduction plan, but the plan contains no executable or mutation
authority.

Hunter observations preserve `SUPPORTS_CANDIDATE`, `CHALLENGES_CANDIDATE`, and
`UNCERTAIN` positions as separate evidence records. SEC3 does not collapse
disagreement into a verdict.

Every candidate packet binds:

- exact Hunter identity;
- exact SEC2 assignment SHA and current coverage-ledger predecessor;
- exact P5 child-task SHA;
- exact Q1 parent allocation and child-budget-ledger SHA;
- exact source-tree SHA, attack class, and assignment scope;
- content-addressed evidence references and repository-relative source ranges.

Before packet creation, SEC3 revalidates the spawn receipt against the exact
threat model and coverage ledger. It recomputes the assignment digest, P5 child
digest, Q1 child-budget digest/allocation lineage, Hunter identity, delegated
allowlist, source scope, attack class, source tree, and spawn-time bindings.
A caller cannot widen scope or substitute Hunter/child/budget lineage by
editing receipt fields.

Confirmation remains impossible in SEC3. SEC4 introduces a distinct validation
identity and adversarial confirmation/rejection transitions.
