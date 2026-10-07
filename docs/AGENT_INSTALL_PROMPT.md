# Agent Install Prompt

Use this prompt with a coding agent that is integrating ToadAid Agent
Capabilities into an unrelated host agent.

```text
You are integrating the checked-out ToadAid Agent Capabilities repository into
this host agent.

Goal:
Install the exact package artifact and wire only the operator-requested
capability profile through the host's existing central dispatch and policy
boundaries.

Read first:
- README.md
- INSTALL_AGENT.md
- docs/GENERIC_AGENT_INTEGRATION.md
- docs/CAPABILITY_PROFILES.md
- profiles/safe-observe.json

Non-negotiable boundaries:
- PROFILE != POLICY.
- INSTALLED != ALLOWED.
- ADAPTER PRESENT != AUTHORIZED.
- MODEL REQUEST != APPROVAL.
- Do not redesign the host's identity, memory, prompts, provider/model stack,
  approval system, secret storage, lifecycle, wallet/economic authority, or
  unrelated tool registry.
- Do not treat package installation as a P3 grant.
- Do not infer ALLOW from provider availability.
- Do not expose raw provider entrypoints as parallel model tools that bypass
  central dispatch.
- Do not publish the package to npm.
- Do not add command execution, file write, process stop, desktop interaction,
  secret materialization, wallet, deployment, Git push, merge, or other
  mutation authority while installing safe-observe.
- Do not switch a capability to ALLOW during installation unless the human
  operator separately asks for that activation after the wiring/tests are
  shown.
- Fail closed on unknown modes, stale authority, contract mismatch,
  provider-generation drift, budget exhaustion, and replay uncertainty.

Installation:
1. Confirm the ToadAid Agent Capabilities checkout identity and run:
     bin/toadaid-capabilities-install-agent --check-only
   When the operator gave you an exact reviewed commit, add
   --expect-commit <that full 40-character commit id> to both commands.
   On native Windows use bin\toadaid-capabilities-install-agent.cmd with the
   same options (no Git Bash, WSL, or PowerShell script needed).
2. From a clean checkout run:
     bin/toadaid-capabilities-install-agent --profile safe-observe
3. Read the generated host-owned integration manifest.
4. Install the exact emitted .tgz into the host project using the host's package
   manager.
5. Identify the host's ONE central model-tool dispatch seam.
6. Map the requested capability IDs to provider-neutral package surfaces.
7. Build thin host adapters only where the host already has an appropriate
   underlying provider.
8. Start every new capability OFF or BLOCK.
9. Wire current authority -> contract/provider binding -> invocation lifecycle
   -> replay law -> budget -> provider entry -> code-owned receipt projection.
10. Ensure raw provider entrypoints cannot bypass that path.
11. Run the required tests in docs/GENERIC_AGENT_INTEGRATION.md.
12. Return a verification report and stop before ALLOW unless separately asked.

Initial safe-observe requested capabilities:
- browser:evidence
- workspace:snapshot
- workspace:diff
- host:process-read

Important:
workspace history is observation evidence, but snapshot/diff behavior must keep
its declared replay semantics; do not relabel it SAFE_READ merely because it
does not mutate the project workspace.

Verification report:
Return:
- capability-package checkout HEAD/tree;
- generated artifact path + SHA-256;
- integration manifest path;
- host package-manager change;
- host adapter files changed;
- central dispatch file changed;
- requested capability IDs;
- OFF test result per capability;
- BLOCK test result per capability;
- intended positive-path tests;
- provider-generation mismatch refusal;
- contract mismatch refusal;
- receipt-forgery refusal;
- replay/budget test result;
- activation state after installation;
- capabilityGrants after installation;
- host_authority_changed;
- host_identity_changed;
- host_memory_changed;
- host_secrets_changed;
- npm_publication_performed;
- remaining operator decisions.

Expected stop-state:
activation=OFF or BLOCK
capabilityGrants unchanged unless the operator separately authorized a grant
host_authority_changed=false
host_identity_changed=false
host_memory_changed=false
host_secrets_changed=false
npm_publication_performed=false

Do not commit, push, open a PR, restart the host, or enable ALLOW unless the
human operator separately asks for that action.
```
