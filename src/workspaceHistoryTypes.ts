export type WorkspaceCapabilityId =
  | "workspace:snapshot"
  | "workspace:diff"
  | "workspace:restore"
  | "workspace:maintenance";

export interface WorkspaceHistoryRuntime {
  workspaceRoot: string;
  historyRoot: string;
  ownerId: string;
  now?: () => Date;
  staleLockMs?: number;
}

export interface WorkspaceSnapshotPolicy {
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  excludedPaths?: readonly string[];
}

export interface NormalizedWorkspaceSnapshotPolicy {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  excludedPaths: readonly string[];
}

export interface WorkspaceSnapshotFile {
  path: string;
  sha256: string;
  bytes: number;
  mode: number;
}

export interface WorkspaceSnapshot {
  schemaVersion: "toadaid.workspace-snapshot.v1";
  snapshotId: string;
  workspaceId: string;
  createdAt: string;
  files: readonly WorkspaceSnapshotFile[];
  totalBytes: number;
  policy: NormalizedWorkspaceSnapshotPolicy;
}

export interface WorkspaceSnapshotEnvelope {
  schemaVersion: "toadaid.workspace-snapshot-envelope.v1";
  snapshot: WorkspaceSnapshot;
  snapshotSha256: string;
}

export type WorkspaceDiffKind = "ADDED" | "MODIFIED" | "DELETED";

export interface WorkspaceDiffEntry {
  path: string;
  kind: WorkspaceDiffKind;
  fromSha256: string | null;
  toSha256: string | null;
}

export interface WorkspaceDiffReceipt {
  schemaVersion: "toadaid.workspace-diff.v1";
  fromSnapshotId: string;
  toSnapshotId: string;
  entries: readonly WorkspaceDiffEntry[];
}

export interface WorkspaceRestoreReceipt {
  schemaVersion: "toadaid.workspace-restore-receipt.v1";
  snapshotId: string;
  restoredAt: string;
  writtenFiles: readonly string[];
  deletedFiles: readonly string[];
  unchangedFiles: readonly string[];
  verifiedObjects: number;
}

export interface WorkspaceMaintenanceOptions {
  retainNewest: number;
}

export interface WorkspaceMaintenanceReceipt {
  schemaVersion: "toadaid.workspace-maintenance-receipt.v1";
  maintainedAt: string;
  retainedSnapshots: readonly string[];
  deletedSnapshots: readonly string[];
  deletedObjects: readonly string[];
  quarantinedEntries: readonly string[];
}

export interface WorkspaceHistoryLock {
  schemaVersion: "toadaid.workspace-history-lock.v1";
  ownerId: string;
  acquiredAt: string;
}

export interface WorkspaceScanResult {
  files: WorkspaceSnapshotFile[];
  totalBytes: number;
  bytesByPath: Map<string, Uint8Array>;
}
