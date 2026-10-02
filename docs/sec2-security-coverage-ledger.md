# SEC2 — Coverage ledger + attack-class planning

SEC2 adds durable inspection-breadth truth to the security-audit specialist
lane. It does not execute Hunters or grant mutation authority.

## Coverage matrix

Coverage is an exact matrix:

`repository area × threat-model-derived attack class`

Every cell is `UNEXPLORED`, `THIN`, or `COVERED`. `THIN` may accumulate new
evidence across repeated inspections; `COVERED` is terminal for that exact
source lineage. A source change can invalidate a cell back to `UNEXPLORED`.

`inspectionBreadthPercent` is only the fraction of cells with some inspection
evidence. It is not a security score and never means the code is secure.

## Deterministic gap planning

Gap analysis selects `UNEXPLORED` before `THIN`. Among `THIN` cells it prefers
the least-inspected cell before stable area/attack-class ordering, so repeated
audits do not keep selecting the same convenient area while equal gaps remain.

A Hunter assignment is plain data bound to the exact threat model, predecessor
coverage-ledger SHA, repository/source identity, one area scope, one attack
class, predecessor coverage state/count, and an exact budget fingerprint. It
grants no source-read, network, fix, Git, secret, economic, or host authority.
SEC3 will bind these packets to governed child execution.

## Selective source-change invalidation

Rebasing to a later threat model carries prior evidence only when the area
definition is unchanged, the attack class still exists, and no changed path
intersects that area. Affected cells reset to `UNEXPLORED`; unrelated cells
retain their evidence.

A changed source-tree SHA requires a non-empty changed-path manifest. An
unchanged source-tree SHA refuses non-empty changed paths. SEC2 cannot prove
that a caller's manifest is a complete VCS diff, but it fails closed on the
dangerous empty-manifest case rather than silently carrying all prior coverage
across a changed tree.

The rebase records predecessor ledger SHA, a source-change fingerprint, and
the exact invalidated cell IDs so selective invalidation is durable evidence
rather than hidden planner state.
