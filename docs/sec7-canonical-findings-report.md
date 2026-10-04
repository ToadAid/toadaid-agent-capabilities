# SEC7 — Canonical findings + verified report generation

SEC7 is a deterministic presentation layer over validated SEC6 audit state. It
does not add inspection, validation, sandbox, repair, file mutation, Git, or
merge authority.

## Canonical first

`buildCanonicalSecurityFindings()` validates the SEC6 state and emits a sealed,
machine-readable `findings.json` projection. Human-facing Markdown is generated
only after the canonical projection is validated against the authoritative SEC6
state.

Each canonical finding preserves finding identity/revision, exact proof state,
source disposition/change lineage, affected source revision/tree, source
locations, content-addressed evidence references, proof/disproof references,
and validator identity provenance for confirmed findings.

SEC7 v1 deliberately emits `severity: UNASSESSED`. The current canonical audit
state does not contain a governed vulnerability-severity assessment, so SEC7
does not infer CRITICAL/HIGH/MEDIUM/LOW from attack class or model prose.

## Report artifacts

`generateSecurityReportBundle()` mechanically produces canonical pretty-printed
`findings.json`, `REPORT.md`, one Markdown detail view per finding, a
current-source `NEEDS_VALIDATION` queue, and content hashes for JSON/report
artifacts.

Rejected findings remain visible. `CANDIDATE`, `NEEDS_VALIDATION`, `CONFIRMED`,
and `REJECTED` remain distinct. Source-invalidated findings are reported as
`STALE_SOURCE`; stale evidence is never upgraded or presented as current proof.

No raw evidence payloads or secret material are embedded by SEC7. Reports carry
bounded finding metadata, repository-relative source locations, and
content-addressed evidence references.

SEC7 validates canonical output against the SEC6 state envelope supplied by the
caller. It does not independently discover or attest the externally current
SEC6 state head. The governing runtime must supply the authoritative current
state envelope; SEC7 does not overclaim an external head-binding proof.

## Revision comparison

Revision comparison is audit/repository-bound and requires a later SEC6 state.
Durable findings may not disappear.

- `NEW` — first appearance in the later canonical state.
- `FIXED` — a predecessor-bound `CONFIRMED` finding is now `REJECTED`.
- `RESOLVED` — an unconfirmed candidate/needs-validation finding is now
  `REJECTED`.
- `REGRESSED` — a previously rejected finding becomes open again.
- `STILL_OPEN` — open in both revisions.
- `STILL_CLOSED` — rejected in both revisions.
- `STALE_SOURCE` — the later state explicitly invalidated the finding because
  its affected source changed.

`FIXED` is a canonical state-transition label only. It does not by itself prove
which code change caused closure. A source change without new proof truth is
`STALE_SOURCE`, never `FIXED`.

## Reporting law

Reporting is non-authority data. A report cannot confirm a candidate, erase
rejected or uncertain evidence, grant repair authority, execute a fix, or
authorize commit/push/merge. SEC8 owns any separately governed repair handoff.
