# Install ToadAid Agent Capabilities for a Generic Agent

ToadAid Agent Capabilities is a provider-neutral TypeScript capability and
governance spine. The generic-agent installer prepares an exact local package
artifact and a host-owned integration manifest. It does **not** redesign the
host agent or grant it new authority.

The installation law is:

```text
code available
    !=
capability authorized
    !=
provider attached
    !=
action permitted
```

In short:

```text
PROFILE != POLICY
INSTALLED != ALLOWED
ADAPTER PRESENT != AUTHORIZED
MODEL REQUEST != APPROVAL
```

## Requirements

- Linux, macOS, or WSL with a POSIX shell, or native Windows (`cmd.exe`;
  no Git Bash, WSL, or PowerShell script execution needed)
- Git
- Node.js 22 or newer
- npm
- a persistent checkout of this repository
- checkout build dependencies installed with `npm ci --include=dev` (from the
  committed `package-lock.json`; `--include=dev` keeps the build toolchain even
  when `NODE_ENV=production`)

The package remains intentionally `"private": true` during alpha. The installer
creates a local `.tgz` package artifact from the exact checkout; it does not
publish anything to npm.

## Quick install

From a clean repository checkout:

```bash
npm ci --include=dev
bin/toadaid-capabilities-install-agent --check-only
bin/toadaid-capabilities-install-agent --profile safe-observe
```

The default state root is:

```text
~/.local/state/toadaid-agent-capabilities/
```

The installer writes:

```text
~/.local/state/toadaid-agent-capabilities/
├── agent-integration.json
└── artifacts/
    └── toadaid-agent-capabilities-<version>-<commit>.tgz
```

`--check-only` performs no installation writes.

### Native Windows

From a clean checkout, in `cmd.exe` (or by calling the same `.cmd` file from
PowerShell — it does not depend on PowerShell execution policy):

```bat
npm ci --include=dev
bin\toadaid-capabilities-install-agent.cmd --check-only
bin\toadaid-capabilities-install-agent.cmd --profile safe-observe
```

The default state root on Windows is:

```text
%LOCALAPPDATA%\toadaid-agent-capabilities\
```

Precedence on Windows: an explicit `--state-root` wins; otherwise
`%LOCALAPPDATA%\toadaid-agent-capabilities`; otherwise the installer refuses
(exit 2). `HOME` is not required, and `XDG_STATE_HOME` is ignored on native
Windows so a value inherited from other tooling cannot redirect installer
state. On Linux/macOS/WSL the default is unchanged.

The `.cmd` file is transport only. On Windows the core discovers `git.exe`
and `npm` through `PATH` + `PATHEXT`, never runs anything through a shell,
runs npm as `node <npm>\node_modules\npm\bin\npm-cli.js`, and runs the
compiler as `node node_modules\typescript\bin\tsc` (as on every platform).
On NTFS the installer does not write ACLs; the state files inherit the ACL of
their parent directory (`%LOCALAPPDATA%` is private to the user by default).

### Pin the exact reviewed commit

When you know the exact commit you reviewed or were told to install, pass it
so the installer fails closed on any other checkout:

```bash
bin/toadaid-capabilities-install-agent --check-only --expect-commit <reviewed-40-hex-commit>
bin/toadaid-capabilities-install-agent --profile safe-observe --expect-commit <reviewed-40-hex-commit>
```

`--expect-commit` accepts only a full 40-character hex commit id (no branch
names, tags, `HEAD`, or abbreviations) and refuses with exit code 2 unless the
checkout `HEAD` is exactly that commit. Take the value from the review or
release note, not from `git rev-parse HEAD` of the checkout being checked.

### One installer core

`bin/toadaid-capabilities-install-agent` (POSIX) and
`bin\toadaid-capabilities-install-agent.cmd` (native Windows) are thin
transport entrypoints. All installer semantics — options, profile policy, checkout pinning, the
dirty-checkout refusal, artifact rules, the manifest, and every refusal — live
in one cross-platform Node core, `bin/toadaid-capabilities-install-agent.mjs`.
There is no platform-specific installer policy.

The package metadata (`package.json`, `README.md`, `LICENSE`) and the
`safe-observe` profile are read from the committed git objects of the exact
checkout `HEAD`, not from mutable working-tree files. The artifact contains no
source maps and every staged file is packed with the canonical mode `0644`
(directories `0755`), so the same commit produces the same artifact sha256
regardless of the checkout path, the process umask, or the platform: Linux and
native Windows produce byte-identical artifacts (enforced in CI).

The result remains:

```text
activation = OFF
capabilityGrants = []
installationGrantsAuthority = false
providerBindings = {}
```

## Install into the host project

The bootstrap deliberately does not mutate an unrelated host repository.
After reviewing the generated manifest, install the exact local artifact from
the host project using that host's package manager, for example:

```bash
npm install --save-exact /absolute/path/to/toadaid-agent-capabilities-<version>-<commit>.tgz
```

Then follow [`docs/GENERIC_AGENT_INTEGRATION.md`](docs/GENERIC_AGENT_INTEGRATION.md).

## Initial profile: `safe-observe`

Generic Install P1 ships one requested integration profile:

```text
browser:evidence
workspace:snapshot
workspace:diff
host:process-read
```

The profile starts `OFF` and grants nothing. `workspace:snapshot` and
`workspace:diff` are observation/history capabilities but are not classified
as replay-safe merely because they do not mutate the project workspace; durable
history validation/maintenance semantics remain separately governed.

See [`docs/CAPABILITY_PROFILES.md`](docs/CAPABILITY_PROFILES.md) and
[`profiles/safe-observe.json`](profiles/safe-observe.json).

## What installation deliberately does not do

The installer does **not**:

- change host identity, memory, prompts, provider/model stack, or lifecycle;
- add capability grants to host policy;
- switch any capability to `ALLOW`;
- attach a browser, desktop, filesystem, process, shell, wallet, or secret
  provider;
- expose command execution, file write, process stop, desktop interaction, or
  economic authority;
- create approval decisions;
- read or copy host secrets;
- modify an unrelated host repository;
- restart a host runtime; or
- publish this package to npm.

Installation is software distribution plus configuration evidence only.

## Custom paths

```bash
bin/toadaid-capabilities-install-agent \
  --profile safe-observe \
  --state-root /var/lib/my-agent/toadaid-capabilities \
  --artifact-root /var/lib/my-agent/toadaid-capabilities/artifacts \
  --manifest /var/lib/my-agent/toadaid-capabilities/integration.json \
  --expect-commit <reviewed-40-hex-commit>
```

The installer is create-once/idempotent for exact generated files. It refuses
to overwrite a different existing artifact or manifest and refuses symlink
targets for persistent installation files/directories.

## Host activation

Activation is host-owned:

1. **OFF** — package may be installed, but the host does not dispatch these
   capabilities.
2. **BLOCK** — the host recognizes the capability but current policy refuses
   authority.
3. **ALLOW** — only after the host has a current policy grant, exact provider
   binding, required contract compatibility, replay/budget law, and tests.

A profile is not an activation state and cannot change host policy.

## Agent-assisted installation

If a coding agent will wire this package into another agent, give it
[`docs/AGENT_INSTALL_PROMPT.md`](docs/AGENT_INSTALL_PROMPT.md).

That prompt requires the coding agent to preserve the host's existing authority
boundaries, begin with `OFF`/`BLOCK`, use the provider-neutral package surfaces,
and stop before any `ALLOW` transition unless the operator separately asks.

## Verification before ALLOW

Before a host enables any requested capability, it should prove at minimum:

- OFF causes no provider entry;
- BLOCK causes no provider entry;
- current policy is re-resolved immediately before provider dispatch;
- provider identity/generation is exactly bound;
- contract compatibility is exact;
- replay classification is explicit;
- budget accounting is explicit;
- model-visible receipts are code-owned rather than model-fabricated;
- a capability cannot widen another capability's authority;
- runtime mode changes fail closed; and
- failure leaves host identity, policy, secrets, and unrelated tools unchanged.

The package being installed successfully is never evidence that those host
integration requirements have been satisfied.
