import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";

export type HostConnectorActionCapabilityId =
  | "host:filesystem-read"
  | "host:filesystem-write"
  | "host:command-execute"
  | "host:tool-invoke"
  | "host:connector-use"
  | "host:display-inventory"
  | "host:screenshot"
  | "host:ui-snapshot"
  | "host:wait-for"
  | "host:pointer-click"
  | "host:pointer-move"
  | "host:scroll"
  | "host:text-input"
  | "host:shortcut"
  | "host:app-launch"
  | "host:clipboard-read"
  | "host:clipboard-write"
  | "host:process-read"
  | "host:process-stop"
  | "host:file-read"
  | "host:file-write"
  | "host:notification"
  | "host:registry-read"
  | "host:registry-write"
  | "host:command-exec";

export type HostConnectorSessionLeaseStatus =
  | "ACTIVE"
  | "REVOKED";

export type HostConnectorSessionLeaseTransition =
  | "CREATE"
  | "NARROW"
  | "REVOKE";

export interface HostConnectorSessionLease {
  readonly schemaVersion: "toadaid.host-connector-session-lease.v1";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly revision: number;
  readonly transition: HostConnectorSessionLeaseTransition;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt: string;
  readonly allowedCapabilities: readonly HostConnectorActionCapabilityId[];
  readonly connectionConfigSha256: string | null;
  readonly status: HostConnectorSessionLeaseStatus;
  readonly revokedAt: string | null;
  readonly continuity: {
    readonly previousLeaseSha256: string | null;
  };
}

export interface HostConnectorSessionLeaseEnvelope {
  readonly schemaVersion:
    "toadaid.host-connector-session-lease-envelope.v1";
  readonly lease: HostConnectorSessionLease;
  readonly leaseSha256: string;
}

export interface HostConnectorSessionRuntime {
  readonly now?: () => Date;
}

export interface HostConnectorSessionUseRuntime
  extends HostConnectorSessionRuntime {
  readonly resolveCurrentLeaseSha256: (
    identity: Readonly<{
      hostId: string;
      sessionId: string;
      ownerId: string;
    }>,
  ) => string | null;
}

export interface CreateHostConnectorSessionLeaseInput {
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly allowedCapabilities:
    readonly HostConnectorActionCapabilityId[];
  readonly connectionConfigSha256?: string;
  readonly ttlMs?: number;
  readonly createdAt?: string;
}

export interface NarrowHostConnectorSessionLeaseInput {
  readonly ownerId: string;
  readonly allowedCapabilities:
    readonly HostConnectorActionCapabilityId[];
  readonly updatedAt?: string;
}

export interface RevokeHostConnectorSessionLeaseInput {
  readonly ownerId: string;
  readonly revokedAt?: string;
}

export interface HostConnectorSessionUseRequest {
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly capabilityId: HostConnectorActionCapabilityId;
}

export interface HostConnectorSessionAuthorityBundle {
  readonly session: CapabilityAuthorityDecision;
  readonly action: CapabilityAuthorityDecision;
}

export interface HostConnectorSessionUseBinding {
  readonly schemaVersion:
    "toadaid.host-connector-session-use-binding.v1";
  readonly hostId: string;
  readonly sessionId: string;
  readonly ownerId: string;
  readonly capabilityId: HostConnectorActionCapabilityId;
  readonly leaseSha256: string;
  readonly connectionConfigSha256: string | null;
  readonly expiresAt: string;
}
