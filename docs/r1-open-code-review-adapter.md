# R1 — OpenCodeReview Adapter

R1 integrates Alibaba OpenCodeReview (OCR) Delegation Mode as a governed review capability. OCR owns deterministic review-surface discovery and rule resolution; the ToadAid host agent owns reasoning.

## Integration mode

R1 targets OCR Delegation Mode schema version `1` and only constructs/accepts these argv-safe operations:

- `ocr delegate preview --format json ...`
- `ocr delegate rule --format json -- <path...>`

The adapter does not invoke `ocr review`, configure an OCR LLM, request model credentials, use the OCR MCP server, or expose an arbitrary shell string.

The runtime should preinstall and pin a compatible OCR version. R1 validates the delegation JSON schema instead of assuming any unversioned text output.

## Review authority

R1 installs two capabilities under P3, both `BLOCK` by default:

- `review:inspect` — build and execute a governed review plan
- `review:fix` — apply explicitly selected findings through a separate fix boundary

`review:inspect` never implies `review:fix`.

## Deterministic review surface

`parseOcrDelegatePreviewJson()` accepts OCR's schema-versioned preview and validates:

- review mode and target metadata
- reviewable/excluded counts
- bounded repository-relative paths
- `(path, status)` checklist identity
- bounded insertions/deletions

Workspace mode may legitimately contain the same path twice under different statuses. R1 preserves those as distinct checklist entries.

`parseOcrDelegateRulesJson()` accepts schema-versioned rule groups and refuses duplicate cross-group path assignment.

## Batching and P5 children

`createOpenCodeReviewPlan()` requires current `review:inspect` authority and fails closed unless every reviewable path is accounted for by the resolved rules.

Delegation Mode batches are deterministic by resolved rule group and diff size. They are bounded by maximum files and maximum changed lines. Review correctness does not depend on model-proposed grouping.

The plan emits P5-ready child-task specs:

- one `REVIEWER` child per bounded batch
- one independent `REFLECTION` child over the completed review
- each delegates only `review:inspect`

The embedding runtime remains responsible for materializing those specs through the P5 child-task lifecycle with the parent run state it owns.

## Mandatory coverage

Every reviewable `(path, status)` entry starts `PENDING` and must end as either:

- `REVIEWED`, with zero or more structured findings, or
- `SKIPPED`, with a concrete reason

`finalizeOpenCodeReview()` refuses while any entry is still pending. The receipt records total, reviewed, skipped, coverage rate, findings, and skipped reasons.

A settled checklist entry cannot be silently rewritten.

## Structured findings and reflection

Findings are bounded plain data with deterministic SHA-256 identity. They may include path, line range, category, and severity.

`createReviewReflectionPacket()` gives the independent reflection child the completed findings plus the review-receipt binding. Reflection receives no fix authority.

## Governed fix boundary

`executeGovernedReviewFix()` is intentionally separate from inspection. Before any fix callback runs it requires all three current authorities:

- `review:fix`
- `workspace:snapshot`
- `workspace:diff`

The selected finding IDs must exist in the completed review receipt.

The fix bridge then runs in this order:

1. P6 snapshot before
2. apply only the explicitly selected findings
3. P6 snapshot after
4. P6 deterministic diff
5. emit a fix receipt bound to the original review receipt and exact before/after snapshots

A diff whose snapshot IDs do not match the actual before/after snapshots is refused.

R1 does not grant `workspace:restore`. Rollback remains a separate explicit P6 authority.

## Non-authority

R1 does not grant shell execution, Git push/merge, arbitrary repository mutation, wallet authority, trading authority, model credentials, or OCR-managed LLM authority. OCR is treated as a deterministic external review-surface engine behind ToadAid policy rather than as a sovereign agent.
