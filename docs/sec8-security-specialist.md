# SEC8 — Agent0 security specialist + separately governed repair handoff

This first SEC8 cut exposes bounded specialist recipes and a non-authority
repair handoff over the security stack already forged in SEC1–SEC7.

The top-level SEC8 roadmap item intentionally remains open after this cut.
A later SEC8 runtime-binding cut must still close the exact C1/H1/Q1/P5
execution-evidence handoff before SEC8 is marked complete on canonical `main`.

## Five explicit specialist recipes

`securitySpecialistRecipe()` exposes exactly five W1 recipe modes:

- `REPOSITORY_PREFLIGHT`
- `TARGETED_AUDIT`
- `GAP_FILL_AUDIT`
- `VALIDATION_ONLY`
- `REVERIFICATION`

Every mode requires only `host:session` and `host:file-read`. Validation and
re-verification may additionally use `security:sandbox-exec`, but only as an
optional separately governed capability. All recipes use zero automatic
retries.

The inspection recipes explicitly forbid:

- `review:fix`
- `host:file-write`
- `host:command-exec`
- `workspace:snapshot`
- `workspace:diff`
- `workspace:restore`

W1 compilation therefore cannot silently pull ambient mutation authority into
the effective specialist capability set. `assertSecuritySpecialistPlanInspectionOnly`
also refuses any sealed recipe plan whose effective capability set escapes the
inspection allowlist.

## Existing shared spine, not a parallel engine

SEC8 does not reimplement security hunting, validation, sandboxing, audit
state, reporting, child lifecycle, or run budgeting.

The specialist recipes are intended to orchestrate the existing SEC1–SEC7
surfaces. SEC3/SEC4 already create real P5 children, reserve Q1 child budgets,
and restrict child authority to `host:file-read` + `host:session`. SEC5 owns
the separately authorized `security:sandbox-exec` proof boundary.

A later SEC8 cut will bind the recipe plan to exact C1/H1/Q1/P5 runtime
evidence rather than representing those runtime crossings as prose.

## Repair proposal is evidence, never permission

`createSecurityRepairProposal()` accepts only a current-source canonical
`CONFIRMED` SEC7 finding with proof evidence and validator identity provenance.

The proposal binds:

- canonical `findings.json` record SHA;
- finding record SHA;
- affected revision and source tree;
- proof evidence references;
- finder and validator identity hashes;
- the exact independent capability requirements
  `review:fix`, `workspace:snapshot`, and `workspace:diff`.

The proposal always records that file mutation, Git, PR, merge, and generic
authority are absent.

A self-consistent proposal cannot turn an unconfirmed or source-invalidated
finding into repair truth.

## Pre-mutation and post-fix binding

`bindSecurityRepairPreMutationSnapshot()` revalidates the plain-data repair
proposal against the authoritative canonical SEC7 findings envelope supplied by
the governing runtime, then binds the proposal to a P6 before snapshot. A
self-consistent resealed proposal hash is integrity evidence only and cannot
substitute for canonical SEC7 truth. The binding remains evidence only; it does
not create snapshot authority.

`createSecurityRepairVerificationPackage()` requires:

- the authoritative canonical SEC7 findings envelope again;
- the exact proposal revalidated against that canonical truth;
- the exact pre-mutation snapshot binding;
- the actual before snapshot rebound to its P6 snapshot SHA;
- an after snapshot from the same workspace;
- a non-empty P6 diff that exactly matches a deterministic recomputation from
  the before/after snapshot manifests;
- non-empty content-addressed test evidence.

The verification package binds changed paths, snapshot hashes, diff hash, test
evidence, and the originating confirmed finding. It does **not** mutate the
finding to `REJECTED`, claim the fix is merged, or grant Git/PR/merge authority.

## Finder / validator self-merge refusal

`assertSecurityRepairMergeActorSeparated()` refuses a merge actor whose
identity equals either the finder identity or validator identity carried by the
repair proposal.

A successful separation receipt says only that this one identity-separation
check passed. It explicitly carries `mergeAuthorityGranted: false`; actual Git,
PR, review, and merge policy remains outside the proposal.

## Current boundary

This cut deliberately does not claim that a caller-supplied P6 snapshot or
external merge actor is the globally authoritative runtime head. The governing
runtime must supply authoritative P6/H1/C1/Q1/P5 evidence in the later SEC8
runtime-binding cut.
