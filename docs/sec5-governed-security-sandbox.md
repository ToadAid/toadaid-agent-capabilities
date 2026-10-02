# SEC5 — Governed security execution sandbox

SEC5 is the only security-audit lane that may actively execute a proof command.
It is deliberately separate from SEC3/SEC4 read-only source-review authority.

## Dual authority

Active proof execution requires an explicit `ALLOW` decision for the dedicated
`security:sandbox-exec` capability. `host:file-read`, `host:session`, or
`host:command-exec` authority does not substitute for this capability.

The sandbox gate accepts only an authoritative SEC4 `NEEDS_VALIDATION` decision
bound to the exact Hunter, candidate packet, validator run, predecessor finding,
and source tree.

## Hard sandbox guarantees

The registered sandbox adapter must advertise exactly the required guarantees:

- network disabled;
- source tree mounted read-only;
- scratch is the only writable filesystem;
- all other filesystem roots unmounted;
- empty environment; no inherited variables or secret material;
- home directory unavailable;
- no shell and no stdin;
- contained process tree;
- enforced CPU, memory, process-count, and wall-clock ceilings;
- proof artifacts leave the sandbox only as content-addressed metadata.

If the adapter cannot provide every guarantee, execution is refused before
dispatch. If a dispatched adapter cannot attest the guarantees afterwards, the
receipt remains `NEEDS_VALIDATION` and exposes no proof evidence.

## Structured execution

The execution specification contains only an absolute executable path, exact
executable SHA-256, structured argv, a read-only source root, a disjoint scratch
root, a cwd inside scratch, and explicit resource limits. There is no shell
string, ambient cwd, inherited environment, stdin, host home, or network mode
that an agent can widen.

The execution budget is Q1-accounted as one tool call plus the full reserved
wall-clock limit.

## Unknown outcomes and replay

`TIMED_OUT`, `CRASHED`, `UNKNOWN`, malformed adapter output, failed attestation,
or adapter exceptions never trigger automatic replay. The receipt remains
`NEEDS_VALIDATION` with `NEW_ATTEMPT_REQUIRED`.

A normal `EXITED` result means only that bounded proof evidence was observed. It
does not itself confirm or reject the finding. SEC4 remains responsible for the
adversarial judgment, consuming the SEC5 receipt/result hashes as evidence.

## Evidence boundary

Raw stdout, stderr, files, and artifact bytes are not carried in SEC5 receipts.
Only hashes, bounded byte counts, resource observations, and content-addressed
artifact references cross the sandbox boundary.

A sandbox receipt hash proves integrity only; it is not proof that the governed
sandbox produced the receipt. Proof publication must rebind the receipt to the
authoritative SEC4 `NEEDS_VALIDATION` lineage, the exact registered sandbox
adapter, the exact normalized execution specification, and the exact normalized
adapter result. Self-consistent resealing cannot mint proof evidence.
