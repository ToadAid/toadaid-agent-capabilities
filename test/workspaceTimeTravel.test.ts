import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CORE_CAPABILITY_MANIFEST, type CapabilityAuthorityDecision } from "../src/capabilityPolicy.js";
import {
  createWorkspaceSnapshot,
  diffWorkspaceSnapshots,
  maintainWorkspaceHistory,
  restoreWorkspaceSnapshot,
} from "../src/workspaceTimeTravel.js";

function authority(capabilityId: string, decision: "ALLOW" | "BLOCK" = "ALLOW"): CapabilityAuthorityDecision {
  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision,
    reason: decision === "ALLOW" ? "AUTHORIZED_BY_POLICY" : "BLOCKED_BY_POLICY",
    trace: [],
  };
}

async function fixture(t: { after: (fn: () => Promise<void>) => void }) {
  const root = await import("node:fs/promises").then(async ({ mkdtemp }) => mkdtemp(join(tmpdir(), "toadaid-p6-")));
  const workspaceRoot = join(root, "workspace");
  const historyRoot = join(root, "history");
  await mkdir(workspaceRoot, { recursive: true });
  await mkdir(historyRoot, { recursive: true });
  t.after(async () => rm(root, { recursive: true, force: true }));
  return {
    workspaceRoot,
    historyRoot,
    runtime: {
      workspaceRoot,
      historyRoot,
      ownerId: "test-owner",
      now: () => new Date("2026-09-24T22:00:00.000Z"),
      staleLockMs: 1_000,
    },
  };
}

test("workspace capabilities are installed but blocked by default", () => {
  const workspace = CORE_CAPABILITY_MANIFEST.capabilities.filter((entry) => entry.id.startsWith("workspace:"));
  assert.deepEqual(workspace.map((entry) => entry.id), [
    "workspace:snapshot",
    "workspace:diff",
    "workspace:restore",
    "workspace:maintenance",
  ]);
  assert.ok(workspace.every((entry) => entry.defaultDecision === "BLOCK"));
});

test("snapshot, deterministic diff, and governed exact restore", async (t: any) => {
  const { workspaceRoot, runtime } = await fixture(t);
  await mkdir(join(workspaceRoot, "sub"), { recursive: true });
  await mkdir(join(workspaceRoot, ".git"), { recursive: true });
  await writeFile(join(workspaceRoot, "a.txt"), "alpha");
  await writeFile(join(workspaceRoot, "sub", "b.txt"), "bravo");
  await writeFile(join(workspaceRoot, ".git", "config"), "keep-me");

  const first = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "s1" },
    runtime,
    authority("workspace:snapshot"),
  );
  assert.deepEqual(first.files.map((file) => file.path), ["a.txt", "sub/b.txt"]);

  await writeFile(join(workspaceRoot, "a.txt"), "alpha-2");
  await rm(join(workspaceRoot, "sub", "b.txt"));
  await writeFile(join(workspaceRoot, "c.txt"), "charlie");
  const second = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "s2" },
    { ...runtime, now: () => new Date("2026-09-24T22:01:00.000Z") },
    authority("workspace:snapshot"),
  );

  const diff = await diffWorkspaceSnapshots("s1", "s2", runtime, authority("workspace:diff"));
  assert.deepEqual(diff.entries.map((entry) => [entry.path, entry.kind]), [
    ["a.txt", "MODIFIED"],
    ["c.txt", "ADDED"],
    ["sub/b.txt", "DELETED"],
  ]);

  const receipt = await restoreWorkspaceSnapshot(
    "s1",
    { ...runtime, now: () => new Date("2026-09-24T22:02:00.000Z") },
    authority("workspace:restore"),
  );
  assert.equal(await readFile(join(workspaceRoot, "a.txt"), "utf8"), "alpha");
  assert.equal(await readFile(join(workspaceRoot, "sub", "b.txt"), "utf8"), "bravo");
  await assert.rejects(readFile(join(workspaceRoot, "c.txt")), /ENOENT/);
  assert.equal(await readFile(join(workspaceRoot, ".git", "config"), "utf8"), "keep-me");
  assert.deepEqual(receipt.deletedFiles, ["c.txt"]);
  assert.ok(receipt.writtenFiles.includes("a.txt"));
  assert.equal(second.snapshotId, "s2");
});

test("restore refuses absent or wrong capability authority", async (t: any) => {
  const { workspaceRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "a.txt"), "alpha");
  await createWorkspaceSnapshot({ workspaceId: "frog", snapshotId: "s1" }, runtime, authority("workspace:snapshot"));

  await assert.rejects(
    restoreWorkspaceSnapshot("s1", runtime, authority("workspace:diff")),
    /not authorized: workspace:restore/,
  );
  await assert.rejects(
    restoreWorkspaceSnapshot("s1", runtime, authority("workspace:restore", "BLOCK")),
    /not authorized: workspace:restore/,
  );
});

test("snapshot refuses symlinks rather than following them", async (t: any) => {
  const { workspaceRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "real.txt"), "real");
  await symlink(join(workspaceRoot, "real.txt"), join(workspaceRoot, "link.txt"));

  await assert.rejects(
    createWorkspaceSnapshot({ workspaceId: "frog", snapshotId: "symlink" }, runtime, authority("workspace:snapshot")),
    /refuses symbolic link/,
  );
});

test("corrupt object is quarantined before restore mutates workspace", async (t: any) => {
  const { workspaceRoot, historyRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "a.txt"), "canonical");
  const snapshot = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "good" },
    runtime,
    authority("workspace:snapshot"),
  );
  await writeFile(join(workspaceRoot, "a.txt"), "current-must-survive-failure");

  const digest = snapshot.files[0]?.sha256;
  if (!digest) throw new Error("expected snapshot digest");
  await writeFile(join(historyRoot, "objects", digest.slice(0, 2), digest), "corrupt");

  await assert.rejects(
    restoreWorkspaceSnapshot(
      "good",
      { ...runtime, now: () => new Date("2026-09-24T22:03:00.000Z") },
      authority("workspace:restore"),
    ),
    /object quarantined/,
  );
  assert.equal(await readFile(join(workspaceRoot, "a.txt"), "utf8"), "current-must-survive-failure");
  const quarantine = await readdir(join(historyRoot, "quarantine"));
  assert.ok(quarantine.some((name: string) => name.startsWith(`object-corrupt-${digest}`)));
});

test("maintenance retains newest snapshots and removes orphan objects", async (t: any) => {
  const { workspaceRoot, historyRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "a.txt"), "one");
  const first = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "s1" },
    runtime,
    authority("workspace:snapshot"),
  );
  await writeFile(join(workspaceRoot, "a.txt"), "two");
  const secondRuntime = { ...runtime, now: () => new Date("2026-09-24T22:05:00.000Z") };
  const second = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "s2" },
    secondRuntime,
    authority("workspace:snapshot"),
  );

  const receipt = await maintainWorkspaceHistory(
    { retainNewest: 1 },
    { ...runtime, now: () => new Date("2026-09-24T22:06:00.000Z") },
    authority("workspace:maintenance"),
  );
  assert.deepEqual(receipt.retainedSnapshots, ["s2"]);
  assert.deepEqual(receipt.deletedSnapshots, ["s1"]);
  assert.ok(receipt.deletedObjects.includes(first.files[0]!.sha256));
  assert.ok(!receipt.deletedObjects.includes(second.files[0]!.sha256));
  await assert.rejects(readFile(join(historyRoot, "snapshots", "s1.json")), /ENOENT/);
});

test("stale lock is quarantined and recovered without blind deletion", async (t: any) => {
  const { workspaceRoot, historyRoot, runtime } = await fixture(t);
  await mkdir(join(historyRoot, "quarantine"), { recursive: true });
  await writeFile(
    join(historyRoot, "lock.json"),
    JSON.stringify({
      schemaVersion: "toadaid.workspace-history-lock.v1",
      ownerId: "dead-owner",
      acquiredAt: "2026-09-24T21:00:00.000Z",
    }),
  );
  await writeFile(join(workspaceRoot, "a.txt"), "alpha");

  const snapshot = await createWorkspaceSnapshot(
    { workspaceId: "frog", snapshotId: "after-stale-lock" },
    runtime,
    authority("workspace:snapshot"),
  );
  assert.equal(snapshot.snapshotId, "after-stale-lock");
  const quarantine = await readdir(join(historyRoot, "quarantine"));
  assert.ok(quarantine.some((name: string) => name.startsWith("lock-stale-")));
});

test("snapshot IDs are immutable and cannot rewrite history", async (t: any) => {
  const { workspaceRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "a.txt"), "one");
  await createWorkspaceSnapshot({ workspaceId: "frog", snapshotId: "same" }, runtime, authority("workspace:snapshot"));
  await writeFile(join(workspaceRoot, "a.txt"), "two");
  await assert.rejects(
    createWorkspaceSnapshot({ workspaceId: "frog", snapshotId: "same" }, runtime, authority("workspace:snapshot")),
    /EEXIST/,
  );
});

test("history root must be disjoint from workspace", async (t: any) => {
  const { workspaceRoot, runtime } = await fixture(t);
  await writeFile(join(workspaceRoot, "a.txt"), "alpha");
  await assert.rejects(
    createWorkspaceSnapshot(
      { workspaceId: "frog", snapshotId: "bad" },
      { ...runtime, historyRoot: join(workspaceRoot, ".history") },
      authority("workspace:snapshot"),
    ),
    /must be disjoint/,
  );
});
