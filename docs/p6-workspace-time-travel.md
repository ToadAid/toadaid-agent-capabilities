# P6 — Workspace Time Travel

P6 gives agents a bounded workspace-history layer that is deliberately separate from project Git.

## Core rule

Workspace history must live outside the workspace tree. `workspaceRoot` and `historyRoot` are required to be disjoint, and `.git` is always excluded from snapshots and restore.

P6 therefore does not create commits, move branches, touch the index, or rewrite Git history.

## Capability identities

P6 installs four capabilities, all `BLOCK` by default under P3:

- `workspace:snapshot` — capture a bounded content-addressed snapshot
- `workspace:diff` — compare two immutable snapshots
- `workspace:restore` — restore exact managed workspace state
- `workspace:maintenance` — retention, orphan cleanup, and history repair

Each public operation requires a current matching P3 `ALLOW` decision. Read/diff authority does not imply restore authority.

## Snapshot model

Snapshots are bounded by policy:

- maximum file count
- maximum single-file bytes
- maximum total bytes
- explicit excluded relative paths

Symbolic links and non-regular files are refused instead of followed. Snapshot file paths are normalized relative paths and snapshot IDs are immutable.

File bodies are stored content-addressed under the external history root. Snapshot envelopes contain ordered file metadata and a SHA-256 seal.

## Deterministic diff

`diffWorkspaceSnapshots()` produces a path-sorted list of `ADDED`, `MODIFIED`, and `DELETED` entries. File-mode changes are treated as modifications even when content is unchanged.

## Governed restore

Restore is fail-closed and preflights every target object before mutating the workspace. Missing or corrupt objects abort the restore before any workspace write/delete happens.

A successful restore:

1. verifies target snapshot integrity
2. verifies every referenced content object
3. atomically writes changed/missing files
4. deletes managed files absent from the target snapshot
5. preserves `.git` and any policy-excluded paths
6. emits a structured restore receipt

Restore never gains authority from the snapshot itself; the caller must supply current `workspace:restore` authority.

## Retention and cleanup

`maintainWorkspaceHistory()` keeps a bounded newest-snapshot set, deletes older manifests, and removes content objects no retained snapshot references.

Unexpected object-store entries are quarantined rather than silently trusted.

## Lock recovery and corruption quarantine

History mutation uses an external lock file created with exclusive-create semantics. An active lock is refused. A malformed or stale lock is moved into quarantine before recovery; it is never blindly deleted.

Corrupt snapshot manifests and content objects are likewise moved into quarantine. Object corruption detected during restore aborts before workspace mutation.

## Non-authority

P6 is not a Git replacement and does not provide shell execution, repository push/merge authority, wallet authority, secret access, or arbitrary filesystem restore. It only operates inside the explicitly supplied workspace root and its disjoint external history store.
