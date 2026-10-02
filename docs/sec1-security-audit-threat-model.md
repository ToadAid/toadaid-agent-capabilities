# SEC1 — Security audit evidence + threat-model contract

SEC1 establishes the evidence contract for the security-audit specialist lane.
It does not grant hunting, mutation, Git, secret, network, or fix authority.

## Exact audit binding

Every threat model is sealed to:

- repository identity SHA;
- source revision and exact source tree SHA;
- declared repository-relative scope;
- configuration fingerprint;
- rule-set fingerprint;
- run identity.

Changing any bound truth requires a new threat model.

## Reconnaissance before hunting

A threat model contains a bounded architecture snapshot made of explicit
components and trust boundaries. Components and boundaries carry only observed
risk signals. The runtime derives attack classes deterministically from those
signals.

The derived attack-class list is therefore target-specific evidence, not a
claim that a generic checklist is complete. Attack classes with no supporting
architecture signal are absent and cannot be attached to a candidate finding
under that threat model.

## Finding truth

The canonical finding states are:

- `CANDIDATE`
- `CONFIRMED`
- `NEEDS_VALIDATION`
- `REJECTED`

SEC1 only creates initial `CANDIDATE` findings. An initial finding cannot claim
`CONFIRMED`. Confirmed state data requires explicit validator identity and proof
evidence, while rejected state data requires a reason plus disproof evidence.
SEC4 will add the independent adversarial transition law.

Every finding is bound to the exact threat-model record SHA, one derived attack
class, immutable evidence references, and repository-relative source locations.

## Authority law

Threat models, architecture snapshots, attack classes, evidence references, and
findings are immutable plain data. None of these objects carries mutation,
secret-materialization, Git, merge, economic, or host-execution authority.
