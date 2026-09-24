import { randomUUID } from "node:crypto";
import { chmod, mkdir, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import {
  SHA256_PATTERN,
  SNAPSHOT_ID_PATTERN,
  WORKSPACE_ID_PATTERN,
  assertId,
  assertWorkspaceAuthority,
  currentIso,
  exactInteger,
  excluded,
  isWithin,
  normalizeWorkspaceSnapshotPolicy,
  normalizedRoots,
  toPosixPath,
} from "./workspaceHistoryPolicy.js";
import {
  ensureHistoryDirectories,
  freezeSnapshot,
  listObjectFiles,
  listSnapshotFiles,
  loadSnapshot,
  quarantinePath,
  readVerifiedObject,
  scanWorkspace,
  snapshotPath,
  withHistoryLock,
  workspaceSnapshotSha256,
  writeObject,
  writeSnapshotEnvelope,
} from "./workspaceHistoryStore.js";
import type {
  NormalizedWorkspaceSnapshotPolicy,
  WorkspaceDiffEntry,
  WorkspaceDiffReceipt,
  WorkspaceHistoryRuntime,
  WorkspaceMaintenanceOptions,
  WorkspaceMaintenanceReceipt,
  WorkspaceRestoreReceipt,
  WorkspaceSnapshot,
  WorkspaceSnapshotPolicy,
} from "./workspaceHistoryTypes.js";

export { normalizeWorkspaceSnapshotPolicy, workspaceSnapshotSha256 };
export type {
  NormalizedWorkspaceSnapshotPolicy,
  WorkspaceCapabilityId,
  WorkspaceDiffEntry,
  WorkspaceDiffKind,
  WorkspaceDiffReceipt,
  WorkspaceHistoryRuntime,
  WorkspaceMaintenanceOptions,
  WorkspaceMaintenanceReceipt,
  WorkspaceRestoreReceipt,
  WorkspaceSnapshot,
  WorkspaceSnapshotEnvelope,
  WorkspaceSnapshotFile,
  WorkspaceSnapshotPolicy,
} from "./workspaceHistoryTypes.js";

export async function createWorkspaceSnapshot(
  input: { workspaceId: string; snapshotId?: string; policy?: WorkspaceSnapshotPolicy },
  runtime: WorkspaceHistoryRuntime,
  authority: CapabilityAuthorityDecision,
): Promise<WorkspaceSnapshot> {
  assertWorkspaceAuthority(authority, "workspace:snapshot");
  const { workspaceRoot, historyRoot } = normalizedRoots(runtime);
  const workspaceId = assertId(input.workspaceId, WORKSPACE_ID_PATTERN, "workspaceId");
  const snapshotId = assertId(input.snapshotId ?? randomUUID(), SNAPSHOT_ID_PATTERN, "snapshotId");
  const policy = normalizeWorkspaceSnapshotPolicy(input.policy);

  return withHistoryLock(runtime, async () => {
    await ensureHistoryDirectories(historyRoot);
    const createdAt = currentIso(runtime);
    const scan = await scanWorkspace(workspaceRoot, policy);
    for (const file of scan.files) {
      const bytes = scan.bytesByPath.get(file.path);
      if (!bytes) throw new Error(`snapshot scan lost file bytes: ${file.path}`);
      await writeObject(historyRoot, file.sha256, bytes, createdAt);
    }
    const snapshot = freezeSnapshot({
      schemaVersion: "toadaid.workspace-snapshot.v1",
      snapshotId,
      workspaceId,
      createdAt,
      files: scan.files,
      totalBytes: scan.totalBytes,
      policy,
    });
    await writeSnapshotEnvelope(historyRoot, snapshot);
    return snapshot;
  });
}

export async function diffWorkspaceSnapshots(
  fromSnapshotId: string,
  toSnapshotId: string,
  runtime: WorkspaceHistoryRuntime,
  authority: CapabilityAuthorityDecision,
): Promise<WorkspaceDiffReceipt> {
  assertWorkspaceAuthority(authority, "workspace:diff");
  const { historyRoot } = normalizedRoots(runtime);
  const now = currentIso(runtime);
  const from = await loadSnapshot(historyRoot, fromSnapshotId, now);
  const to = await loadSnapshot(historyRoot, toSnapshotId, now);
  if (from.workspaceId !== to.workspaceId) throw new Error("workspace diff requires snapshots from the same workspaceId");

  const fromMap = new Map(from.files.map((file) => [file.path, file]));
  const toMap = new Map(to.files.map((file) => [file.path, file]));
  const paths = [...new Set([...fromMap.keys(), ...toMap.keys()])].sort();
  const entries: WorkspaceDiffEntry[] = [];
  for (const path of paths) {
    const before = fromMap.get(path);
    const after = toMap.get(path);
    if (!before && after) entries.push({ path, kind: "ADDED", fromSha256: null, toSha256: after.sha256 });
    else if (before && !after) entries.push({ path, kind: "DELETED", fromSha256: before.sha256, toSha256: null });
    else if (before && after && (before.sha256 !== after.sha256 || before.mode !== after.mode)) {
      entries.push({ path, kind: "MODIFIED", fromSha256: before.sha256, toSha256: after.sha256 });
    }
  }
  return Object.freeze({
    schemaVersion: "toadaid.workspace-diff.v1",
    fromSnapshotId: from.snapshotId,
    toSnapshotId: to.snapshotId,
    entries: Object.freeze(entries.map((entry) => Object.freeze(entry))),
  });
}

async function atomicWriteFile(path: string, bytes: Uint8Array, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${randomUUID()}.tmp`;
  await writeFile(temp, bytes, { flag: "wx", mode });
  await chmod(temp, mode);
  await rename(temp, path);
}

async function removeEmptyDirectories(
  root: string,
  excludedPaths: readonly string[],
  directory = root,
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const child = join(directory, entry.name);
    const rel = toPosixPath(relative(root, child));
    if (excluded(rel, excludedPaths)) continue;
    await removeEmptyDirectories(root, excludedPaths, child);
    const remaining = await readdir(child);
    if (remaining.length === 0) await rm(child, { recursive: false, force: true });
  }
}

export async function restoreWorkspaceSnapshot(
  snapshotId: string,
  runtime: WorkspaceHistoryRuntime,
  authority: CapabilityAuthorityDecision,
): Promise<WorkspaceRestoreReceipt> {
  assertWorkspaceAuthority(authority, "workspace:restore");
  const { workspaceRoot, historyRoot } = normalizedRoots(runtime);

  return withHistoryLock(runtime, async () => {
    const restoredAt = currentIso(runtime);
    const target = await loadSnapshot(historyRoot, snapshotId, restoredAt);
    const targetMap = new Map(target.files.map((file) => [file.path, file]));

    const verified = new Map<string, Uint8Array>();
    for (const file of target.files) {
      verified.set(file.path, await readVerifiedObject(historyRoot, file.sha256, file.bytes, restoredAt));
    }

    const current = await scanWorkspace(workspaceRoot, target.policy);
    const currentMap = new Map(current.files.map((file) => [file.path, file]));
    const writtenFiles: string[] = [];
    const deletedFiles: string[] = [];
    const unchangedFiles: string[] = [];

    for (const file of target.files) {
      const existing = currentMap.get(file.path);
      if (existing && existing.sha256 === file.sha256 && existing.mode === file.mode) {
        unchangedFiles.push(file.path);
        continue;
      }
      const bytes = verified.get(file.path);
      if (!bytes) throw new Error(`verified object missing from restore preflight: ${file.path}`);
      await atomicWriteFile(join(workspaceRoot, ...file.path.split("/")), bytes, file.mode);
      writtenFiles.push(file.path);
    }

    for (const file of current.files) {
      if (targetMap.has(file.path)) continue;
      const absolute = resolve(workspaceRoot, ...file.path.split("/"));
      if (!isWithin(workspaceRoot, absolute)) throw new Error(`restore path escaped workspace root: ${file.path}`);
      await rm(absolute, { force: true });
      deletedFiles.push(file.path);
    }

    await removeEmptyDirectories(workspaceRoot, target.policy.excludedPaths);
    return Object.freeze({
      schemaVersion: "toadaid.workspace-restore-receipt.v1",
      snapshotId: target.snapshotId,
      restoredAt,
      writtenFiles: Object.freeze(writtenFiles.sort()),
      deletedFiles: Object.freeze(deletedFiles.sort()),
      unchangedFiles: Object.freeze(unchangedFiles.sort()),
      verifiedObjects: verified.size,
    });
  });
}

export async function maintainWorkspaceHistory(
  options: WorkspaceMaintenanceOptions,
  runtime: WorkspaceHistoryRuntime,
  authority: CapabilityAuthorityDecision,
): Promise<WorkspaceMaintenanceReceipt> {
  assertWorkspaceAuthority(authority, "workspace:maintenance");
  const { historyRoot } = normalizedRoots(runtime);
  const retainNewest = exactInteger(options.retainNewest, options.retainNewest, 1, 10_000, "retainNewest");

  return withHistoryLock(runtime, async () => {
    const maintainedAt = currentIso(runtime);
    const quarantinedEntries: string[] = [];
    const snapshots: WorkspaceSnapshot[] = [];
    for (const fileName of await listSnapshotFiles(historyRoot)) {
      const id = fileName.slice(0, -5);
      try {
        snapshots.push(await loadSnapshot(historyRoot, id, maintainedAt));
      } catch (error) {
        const match = /workspace snapshot quarantined: ([^;]+)/.exec((error as Error).message);
        if (match?.[1]) quarantinedEntries.push(match[1]);
      }
    }

    snapshots.sort((a, b) => {
      const time = b.createdAt.localeCompare(a.createdAt);
      return time !== 0 ? time : b.snapshotId.localeCompare(a.snapshotId);
    });
    const retained = snapshots.slice(0, retainNewest);
    const removed = snapshots.slice(retainNewest);
    const deletedSnapshots: string[] = [];
    for (const snapshot of removed) {
      await rm(snapshotPath(historyRoot, snapshot.snapshotId), { force: true });
      deletedSnapshots.push(snapshot.snapshotId);
    }

    const referenced = new Set<string>();
    for (const snapshot of retained) for (const file of snapshot.files) referenced.add(file.sha256);
    const deletedObjects: string[] = [];
    for (const path of await listObjectFiles(historyRoot)) {
      const name = path.split(sep).at(-1) ?? "";
      if (!SHA256_PATTERN.test(name)) {
        quarantinedEntries.push(await quarantinePath(historyRoot, path, "object-unexpected", maintainedAt));
        continue;
      }
      if (!referenced.has(name)) {
        await rm(path, { force: true });
        deletedObjects.push(name);
      }
    }

    return Object.freeze({
      schemaVersion: "toadaid.workspace-maintenance-receipt.v1",
      maintainedAt,
      retainedSnapshots: Object.freeze(retained.map((snapshot) => snapshot.snapshotId).sort()),
      deletedSnapshots: Object.freeze(deletedSnapshots.sort()),
      deletedObjects: Object.freeze(deletedObjects.sort()),
      quarantinedEntries: Object.freeze(quarantinedEntries.sort()),
    });
  });
}
