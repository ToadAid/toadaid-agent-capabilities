# SEC6 — Durable resumable audit state + source-change invalidation

SEC6 persists security-audit truth by composing the existing P4 run-state
capsule and P5 child-task lifecycle. It does not introduce a second persistence
or authority system.

## Durable state

The canonical audit-state envelope contains:

- the complete threat-model history, including reconnaissance and derived attack
  classes;
- the current SEC2 coverage ledger;
- immutable SEC1/SEC4 finding envelopes plus source-disposition metadata;
- full P5 child-task records with role, source-tree binding, and task SHA;
- provider/model identity fingerprints as provenance only;
- the P4 run-state capsule whose evidence references bind the exact current
  threat model, coverage ledger, findings, and child tasks.

State hashes are integrity evidence only. Saved audit state is non-authority
data.

## Exact resume

Ordinary restart requires the same repository identity, source revision/tree,
configuration SHA, and rule-set SHA expected by the current threat model.
Mismatch refuses ordinary resume. Source drift must use the explicit source
rebase path.

P4 restart preserves the saved authority snapshot as continuity/provenance
data only. SEC6 does not use that saved snapshot to calculate effective resume
authority. Resume authority is the fresh current P3 authority projection supplied
by the governed runtime. A revoked capability remains blocked; editing or
resealing durable state cannot grant, restore, or narrow authority.

Provider/model changes are recorded as explicit `PROVIDER_CHANGE` continuity
with a provenance hash. They do not grant capabilities and do not cause
automatic child-task duplication.

## Source rebase

Source rebase requires the same audit id, run id, repository identity,
configuration, rule set, and scope, plus a changed source tree and an explicit
changed-path manifest.

SEC2 performs the coverage rebase: only intersecting area × attack-class cells
return to `UNEXPLORED`; unaffected cells keep their evidence. Findings are never
rewritten. Findings whose source locations intersect changed paths become
`INVALIDATED_SOURCE_CHANGE`; findings outside the changed paths become
`CARRIED_UNCHANGED`, preserving their old affected revision rather than silently
rebinding them to the new tree.

Existing P5 child tasks become historical source lineage after a source rebase.
No child is automatically restarted or duplicated.

The changed-path manifest is structurally validated, source-bound, and hashed,
but SEC6 does not independently prove that the caller supplied the complete VCS
diff between the two source trees. Completeness requires trusted upstream diff
evidence; SEC6 does not overclaim that proof.

## Interrupted and blocked work

Audit state may checkpoint as `BLOCKED`, preserving failed/blocked child-task
lineage and all evidence. Ordinary checkpoints are append/preserve: an existing
finding or P5 child lineage entry cannot disappear, and child role/source
provenance cannot be relabeled. Restart advances P4 continuity but does not
fabricate progress. New hunting, sandbox execution, network access, host access,
or any other capability still requires fresh current P3 authority.
