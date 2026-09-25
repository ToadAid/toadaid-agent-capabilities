import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";

export type SecretLeaseStatus = "ACTIVE" | "REVOKED";
export type SecretProjectionTarget = SecretEnvironmentProjection | SecretFileProjection;

export interface SecretEnvironmentProjection {
  kind: "ENV";
  name: string;
}

export interface SecretFileProjection {
  kind: "FILE";
  relativePath: string;
  mode: 384;
}

export interface SecretLeaseContinuity {
  revision: number;
  previousLeaseSha256: string | null;
}

export interface SecretLease {
  schemaVersion: "toadaid.secret-lease.v1";
  leaseId: string;
  ownerId: string;
  providerId: string;
  profileId: string;
  secretHandle: string;
  allowedCapabilities: readonly string[];
  allowedTargets: readonly SecretProjectionTarget[];
  createdAt: string;
  expiresAt: string;
  status: SecretLeaseStatus;
  revokedAt: string | null;
  revokedBy: string | null;
  continuity: SecretLeaseContinuity;
}

export interface SecretLeaseEnvelope {
  schemaVersion: "toadaid.secret-lease-envelope.v1";
  lease: SecretLease;
  leaseSha256: string;
}

export interface CreateSecretLeaseInput {
  leaseId?: string;
  ownerId: string;
  providerId: string;
  profileId: string;
  secretHandle: string;
  allowedCapabilities: readonly string[];
  allowedTargets: readonly SecretProjectionTarget[];
  createdAt: string;
  ttlMs?: number;
}

export interface SecretMaterializationRequest {
  ownerId: string;
  providerId: string;
  profileId: string;
  forCapabilityId: string;
  target: SecretProjectionTarget;
  issuedAt: string;
  ttlMs?: number;
  materializationId?: string;
}

export interface SecretMaterializationAuthorityBundle {
  materialize: CapabilityAuthorityDecision;
  consumer: CapabilityAuthorityDecision;
}

export interface SecretMaterializationGrant {
  schemaVersion: "toadaid.secret-materialization-grant.v1";
  materializationId: string;
  leaseId: string;
  leaseSha256: string;
  ownerId: string;
  providerId: string;
  profileId: string;
  secretHandle: string;
  forCapabilityId: string;
  target: SecretProjectionTarget;
  issuedAt: string;
  expiresAt: string;
}

export interface SecretMaterializationGrantEnvelope {
  schemaVersion: "toadaid.secret-materialization-grant-envelope.v1";
  grant: SecretMaterializationGrant;
  grantSha256: string;
}

export interface SecretLeaseRuntime {
  now?: () => Date;
}
