import { randomUUID } from "node:crypto";
import { lstat, mkdir, open, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";

import {
  DEFAULT_STALE_LOCK_MS,
  MAX_STALE_LOCK_MS,
  SHA256_PATTERN,
  SNAPSHOT_ID_PATTERN,
  assertId,
  canonicalIso,
  canonicalJson,
  currentIso,
  exactInteger,
  excluded,
  normalizeRelativePath,
  normalizeWorkspaceSnapshotPolicy,
  normalizedRoots,
  sha256,
  toPosixPath,
} from "./workspaceHistoryPolicy.js";
import type {
  WorkspaceHistoryLock,
  WorkspaceHistoryRuntime,
  WorkspaceScanResult,
  WorkspaceSnapshot,
  WorkspaceSnapshotEnvelope,
  WorkspaceSnapshotFile,
} from "./workspaceHistoryTypes.js";

export async function scanWorkspace(
  workspaceRoot: string,
  policy: WorkspaceSnapshot["policy"],
): Promise<WorkspaceScanResult> {
  const files: WorkspaceSnapshotFile[] = [];
  const bytesByPath = new Map<string, Uint8Array>();
  let totalBytes = 0;

  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const relativePath = toPosixPath(relative(workspaceRoot, absolute));
      if (excluded(relativePath, policy.excludedPaths)) continue;
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) throw new Error(`workspace snapshot refuses symbolic link: ${relativePath}`);
      if (metadata.isDirectory()) {
        await walk(absolute);
        continue;
      }
      if (!metadata.isFile()) throw new Error(`workspace snapshot refuses non-regular file: ${relativePath}`);
      if (metadata.size > policy.maxFileBytes) throw new RangeError(`workspace file exceeds maxFileBytes: ${relativePath}`);
      if (files.length + 1 > policy.maxFiles) throw new RangeError(`workspace exceeds maxFiles: ${policy.maxFiles}`);
      if (totalBytes + metadata.size > policy.maxTotalBytes) {
        throw new RangeError(`workspace exceeds maxTotalBytes: ${policy.maxTotalBytes}`);
      }
      const bytes = await readFile(absolute);
      const digest = sha256(bytes);
      files.push(Object.freeze({ path: relativePath, sha256: digest, bytes: bytes.byteLength, mode: metadata.mode & 0o777 }));
      bytesByPath.set(relativePath, bytes);
      totalBytes += bytes.byteLength;
    }
  }

  await walk(workspaceRoot);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, totalBytes, bytesByPath };
}

export function objectPath(historyRoot: string, digest: string): string {
  if (!SHA256_PATTERN.test(digest)) throw new TypeError("object digest must be lowercase SHA-256");
  return join(historyRoot, "objects", digest.slice(0, 2), digest);
}

export function snapshotPath(historyRoot: string, snapshotId: string): string {
  assertId(snapshotId, SNAPSHOT_ID_PATTERN, "snapshotId");
  return join(historyRoot, "snapshots", `${snapshotId}.json`);
}

export async function ensureHistoryDirectories(historyRoot: string): Promise<void> {
  await mkdir(join(historyRoot, "objects"), { recursive: true });
  await mkdir(join(historyRoot, "snapshots"), { recursive: true });
  await mkdir(join(historyRoot, "quarantine"), { recursive: true });
}

export async function quarantinePath(
  historyRoot: string,
  path: string,
  prefix: string,
  now: string,
): Promise<string> {
  await mkdir(join(historyRoot, "quarantine"), { recursive: true });
  const target = join(historyRoot, "quarantine", `${prefix}-${now.replace(/[:.]/g, "-")}-${randomUUID()}`);
  await rename(path, target);
  return toPosixPath(relative(historyRoot, target));
}

export async function writeObject(
  historyRoot: string,
  digest: string,
  bytes: Uint8Array,
  now: string,
): Promise<string | null> {
  const path = objectPath(historyRoot, digest);
  await mkdir(dirname(path), { recursive: true });
  try {
    const existing = await readFile(path);
    if (sha256(existing) === digest) return null;
    const quarantined = await quarantinePath(historyRoot, path, `object-corrupt-${digest}`, now);
    const temp = `${path}.${randomUUID()}.tmp`;
    await writeFile(temp, bytes, { flag: "wx" });
    await rename(temp, path);
    return quarantined;
  } catch (error) {
    if ((error as { code?: string }).code !== "ENOENT") throw error;
  }
  const temp = `${path}.${randomUUID()}.tmp`;
  await writeFile(temp, bytes, { flag: "wx" });
  await rename(temp, path);
  return null;
}

export function freezeSnapshot(snapshot: WorkspaceSnapshot): WorkspaceSnapshot {
  return Object.freeze({
    ...snapshot,
    files: Object.freeze(snapshot.files.map((file) => Object.freeze({ ...file }))),
    policy: Object.freeze({ ...snapshot.policy, excludedPaths: Object.freeze([...snapshot.policy.excludedPaths]) }),
  });
}

export function validateSnapshot(snapshot: WorkspaceSnapshot): WorkspaceSnapshot {
  if (snapshot.schemaVersion !== "toadaid.workspace-snapshot.v1") throw new TypeError("invalid workspace snapshot schema");
  assertId(snapshot.snapshotId, SNAPSHOT_ID_PATTERN, "snapshotId");
  canonicalIso(snapshot.createdAt, "snapshot.createdAt");
  const policy = normalizeWorkspaceSnapshotPolicy(snapshot.policy);
  const seen = new Set<string>();
  let total = 0;
  const files = snapshot.files.map((file, index) => {
    const path = normalizeRelativePath(file.path, `snapshot.files[${index}].path`);
    if (path === ".git" || path.startsWith(".git/")) throw new TypeError("snapshot cannot contain .git paths");
    if (seen.has(path)) throw new TypeError(`duplicate workspace snapshot path: ${path}`);
    seen.add(path);
    if (!SHA256_PATTERN.test(file.sha256)) throw new TypeError(`invalid file sha256: ${path}`);
    if (!Number.isInteger(file.bytes) || file.bytes < 0 || file.bytes > policy.maxFileBytes) throw new TypeError(`invalid file byte count: ${path}`);
    if (!Number.isInteger(file.mode) || file.mode < 0 || file.mode > 0o777) throw new TypeError(`invalid file mode: ${path}`);
    total += file.bytes;
    return Object.freeze({ path, sha256: file.sha256, bytes: file.bytes, mode: file.mode });
  });
  files.sort((a, b) => a.path.localeCompare(b.path));
  if (files.length > policy.maxFiles || total > policy.maxTotalBytes || total !== snapshot.totalBytes) {
    throw new TypeError("workspace snapshot bounds/total are inconsistent");
  }
  return freezeSnapshot({ ...snapshot, files, totalBytes: total, policy });
}

export function workspaceSnapshotSha256(snapshot: WorkspaceSnapshot): string {
  return sha256(canonicalJson(validateSnapshot(snapshot)));
}

export async function writeSnapshotEnvelope(historyRoot: string, snapshot: WorkspaceSnapshot): Promise<void> {
  const envelope: WorkspaceSnapshotEnvelope = Object.freeze({
    schemaVersion: "toadaid.workspace-snapshot-envelope.v1",
    snapshot,
    snapshotSha256: workspaceSnapshotSha256(snapshot),
  });
  const target = snapshotPath(historyRoot, snapshot.snapshotId);
  const handle = await open(target, "wx");
  try {
    await handle.writeFile(JSON.stringify(envelope));
  } finally {
    await handle.close();
  }
}

export async function loadSnapshot(historyRoot: string, snapshotId: string, now: string): Promise<WorkspaceSnapshot> {
  const target = snapshotPath(historyRoot, snapshotId);
  let raw: Uint8Array;
  try {
    raw = await readFile(target);
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") throw new Error(`workspace snapshot not found: ${snapshotId}`);
    throw error;
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(raw)) as WorkspaceSnapshotEnvelope;
    if (parsed.schemaVersion !== "toadaid.workspace-snapshot-envelope.v1") throw new TypeError("invalid snapshot envelope schema");
    if (typeof parsed.snapshotSha256 !== "string" || !SHA256_PATTERN.test(parsed.snapshotSha256)) throw new TypeError("invalid snapshot envelope digest");
    const snapshot = validateSnapshot(parsed.snapshot);
    if (workspaceSnapshotSha256(snapshot) !== parsed.snapshotSha256) throw new Error("workspace snapshot integrity mismatch");
    return snapshot;
  } catch (error) {
    const quarantined = await quarantinePath(historyRoot, target, `snapshot-corrupt-${snapshotId}`, now);
    throw new Error(`workspace snapshot quarantined: ${quarantined}; ${(error as Error).message}`);
  }
}

export async function readVerifiedObject(
  historyRoot: string,
  digest: string,
  expectedBytes: number,
  now: string,
): Promise<Uint8Array> {
  const path = objectPath(historyRoot, digest);
  let bytes: Uint8Array;
  try {
    bytes = await readFile(path);
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") throw new Error(`workspace history object missing: ${digest}`);
    throw error;
  }
  if (bytes.byteLength !== expectedBytes || sha256(bytes) !== digest) {
    const quarantined = await quarantinePath(historyRoot, path, `object-corrupt-${digest}`, now);
    throw new Error(`workspace history object quarantined: ${quarantined}`);
  }
  return bytes;
}

async function acquireLock(runtime: WorkspaceHistoryRuntime): Promise<() => Promise<void>> {
  const { historyRoot } = normalizedRoots(runtime);
  await ensureHistoryDirectories(historyRoot);
  const lockPath = join(historyRoot, "lock.json");
  const now = currentIso(runtime);
  const staleLockMs = exactInteger(runtime.staleLockMs, DEFAULT_STALE_LOCK_MS, 1_000, MAX_STALE_LOCK_MS, "runtime.staleLockMs");

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await open(lockPath, "wx");
      const lock: WorkspaceHistoryLock = { schemaVersion: "toadaid.workspace-history-lock.v1", ownerId: runtime.ownerId, acquiredAt: now };
      await handle.writeFile(JSON.stringify(lock));
      await handle.close();
      return async () => {
        try {
          const raw = await readFile(lockPath, "utf8");
          const current = JSON.parse(raw) as WorkspaceHistoryLock;
          if (current.ownerId === runtime.ownerId && current.acquiredAt === now) await rm(lockPath, { force: true });
        } catch {
          // A foreign/recovered lock is never removed blindly.
        }
      };
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") throw error;
      let stale = false;
      let corrupt = false;
      try {
        const raw = await readFile(lockPath, "utf8");
        const lock = JSON.parse(raw) as WorkspaceHistoryLock;
        if (lock.schemaVersion !== "toadaid.workspace-history-lock.v1" || !lock.ownerId || canonicalIso(lock.acquiredAt, "lock.acquiredAt") !== lock.acquiredAt) {
          corrupt = true;
        } else {
          stale = new Date(now).getTime() - new Date(lock.acquiredAt).getTime() > staleLockMs;
        }
      } catch {
        corrupt = true;
      }
      if (!stale && !corrupt) throw new Error("workspace history is locked by an active owner");
      await quarantinePath(historyRoot, lockPath, corrupt ? "lock-corrupt" : "lock-stale", now);
    }
  }
  throw new Error("workspace history lock recovery failed");
}

export async function withHistoryLock<T>(runtime: WorkspaceHistoryRuntime, operation: () => Promise<T>): Promise<T> {
  const release = await acquireLock(runtime);
  try {
    return await operation();
  } finally {
    await release();
  }
}

export async function listSnapshotFiles(historyRoot: string): Promise<string[]> {
  await mkdir(join(historyRoot, "snapshots"), { recursive: true });
  const names = await readdir(join(historyRoot, "snapshots"));
  return names.filter((name: string) => name.endsWith(".json")).sort();
}

export async function listObjectFiles(historyRoot: string): Promise<string[]> {
  const root = join(historyRoot, "objects");
  await mkdir(root, { recursive: true });
  const results: string[] = [];
  const prefixes = await readdir(root, { withFileTypes: true });
  for (const prefix of prefixes) {
    if (!prefix.isDirectory()) continue;
    const directory = join(root, prefix.name);
    const names = await readdir(directory);
    for (const name of names) results.push(join(directory, name));
  }
  return results.sort();
}
