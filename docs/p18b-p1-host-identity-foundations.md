# P18B-P1 — Host-service identity foundations

P18B-P1 hardens identity and lifetime truth underneath P18 host services. The
parent P18B item remains open until execution/content containment lands.

## Governed process references

`host:process-stop` no longer accepts a bare PID plus caller-supplied evidence
hash. It consumes a sealed `toadaid.host-process-reference.v1` derived from a
successful governed `host:process-read` receipt.

The reference binds:

- exact host/session;
- PID and provider `processRef`;
- process-read receipt SHA and result-evidence SHA;
- provider descriptor + generation;
- provider evidence namespace;
- observation time; and
- a tamper-evident reference SHA.

At stop time the host runtime must still resolve that exact reference as
current. Provider restart/generation drift, namespace drift, stale evidence,
or missing current reference fails closed before adapter entry.

## Provider generation in receipts

Every P18 host-service receipt now records the current provider descriptor,
provider generation, and evidence namespace obtained from trusted host runtime
truth. The descriptor must match the current C1 binding.

Provider identity is provenance/current-state evidence only. It grants no P3
authority.

## Explicit Windows registry view

Every registry scope declares exactly one of:

```text
REGISTRY_32
REGISTRY_64
```

The runtime never infers registry view from worker/runtime architecture.

## P15 lifetime containment

Before Q1 spend or adapter entry:

```text
now + maxWallClockMs <= P15 lease.expiresAt
```

must hold. A host operation may not begin when its declared execution window
would outlive its host-session authority.

## Legacy alias conflict law

The structured P18 names:

```text
host:file-read
host:file-write
host:command-exec
```

are not interchangeable with the legacy P15-era aliases:

```text
host:filesystem-read
host:filesystem-write
host:command-execute
```

A structured P18 invocation refuses an active lease that also carries its
corresponding deprecated alias. This prevents one operator policy from
accidentally treating the two capability families as equivalent.

## Still open in P18B-P2

- executable identity/hash or trusted allowlist identity + argv profile;
- bounded child-process policy;
- termination and confirmed timeout quiescence;
- bounded host-side content resolution for content/value/stdin/env refs with no
  ambient content-store/secret authority exposed to adapters.
