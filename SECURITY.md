# Security Policy

ToadAid Agent Capabilities is a governance-oriented capability library. Security reports are welcome, especially where a bug could widen authority, bypass policy, confuse evidence with permission, weaken replay/reconciliation guarantees, or expose secrets.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability that could expose credentials, grant unintended authority, enable unsafe mutation, or reveal a reproducible exploit against a deployed consumer.

Use GitHub's private security reporting for this repository when available. If private reporting is unavailable, contact the repository owner through the ToadAid organization/account before publishing exploit details.

A useful report includes:

- affected commit or release;
- affected capability or package surface;
- expected security boundary;
- observed behavior;
- minimal reproduction;
- whether the issue requires existing authorization;
- whether any external side effect occurred;
- suggested mitigation, if known.

Do not include live credentials, private keys, seed phrases, wallet secrets, personal access tokens, or other sensitive material.

## Security model

The repository's standing security laws include:

- installed does not mean authorized;
- enabled/available does not mean authorized;
- evidence and receipts are not permission tokens;
- saved state does not restore revoked authority;
- delegation can only narrow authority;
- browser observation does not imply interaction authority;
- host attachment does not imply machine authority;
- uncertain mutation outcomes require reconciliation rather than blind retry;
- provider/module discovery never widens policy;
- live economic authority is outside this repository unless introduced through a separate governed boundary.

These are design invariants, not a claim that the software is free of defects.

## Supported versions

During the `0.1.0-alpha.0` phase, security fixes are made against canonical `main`. Consumers should bind to an exact reviewed commit or packaged artifact identity rather than assume that the alpha version string uniquely identifies implementation bytes.
