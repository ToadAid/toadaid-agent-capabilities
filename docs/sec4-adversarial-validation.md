# SEC4 — Adversarial validation + independent re-verification

SEC4 validates SEC3 Hunter candidates in a fresh P5 child and Q1 budget. The
validator's first objective is to disprove the candidate, not to agree with it.

## Independent identity and context

The validator audit identity must differ from the discovering Hunter identity,
and the validator must run in a different P5 child task. Equality is refused.
The identity digest is provenance supplied by the governing caller; SEC4 binds
and compares it but does not treat provider/model labels as proof of human or
organizational independence.

The validator child has the same narrow read-only ALLOW list as SEC3:

- `host:session`
- `host:file-read`

Network, retries, and nested children are zero. Fix, Git, secret, execution,
live-economic, and unrelated host authority are absent.

## NEEDS_VALIDATION first

Every accepted candidate enters validator state as a new predecessor-bound
`NEEDS_VALIDATION` finding before any final decision. If read-only review cannot
safely or deterministically establish the flaw, the result remains
`NEEDS_VALIDATION`.

SEC4 does not gain active proof-execution authority. Active target execution is
reserved for SEC5's governed sandbox. Therefore a SEC4 `CONFIRMED` result
requires non-empty content-addressed proof evidence and exact candidate source
locations that can be reproduced by read-only adversarial review.

## Outcomes

- `CONFIRMED` requires a distinct validator identity, non-empty proof evidence,
  exact source-tree binding, and exact candidate source locations.
- `REJECTED` preserves the original candidate evidence and adds an explicit
  disproof reason plus non-empty disproof evidence.
- `NEEDS_VALIDATION` remains durable when proof is insufficient or unsafe.

The validation decision binds the exact Hunter identity, validator execution,
candidate packet, predecessor finding, source tree, evidence, source locations,
and result finding.

A decision envelope hash proves integrity only. Authoritative consumption must
also revalidate that envelope against the exact Hunter spawn, candidate packet,
validator spawn, predecessor `NEEDS_VALIDATION` finding, and source tree.
Self-consistent resealing cannot substitute new lineage. Independent
re-verification therefore requires the full authoritative lineage and refuses a
decision that merely recomputes its own SHA.

## Optional independent re-verifier

A confirmed decision may receive a final read-only re-verification receipt.
The re-verifier identity must differ from both Hunter and validator identities,
and it must check exact confirmed source locations with non-empty evidence.
Its result is `VERIFIED` or `NEEDS_REVIEW`; it does not rewrite the confirmed
finding.

Provider/model provenance may be recorded for validator or re-verifier runs,
but diversity is provenance only and never substitutes for evidence.
