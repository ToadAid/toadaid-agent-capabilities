import { randomUUID } from "node:crypto";

import type { CapabilityAuthorityDecision } from "./capabilityPolicy.js";
import {
  DEFAULT_LEASE_TTL_MS,
  DEFAULT_MATERIALIZATION_TTL_MS,
  MAX_LEASE_TTL_MS,
  MAX_MATERIALIZATION_TTL_MS,
  SHA256_PATTERN,
  assertAuthority,
  assertCapabilityId,
  assertId,
  assertProviderProfileId,
  assertSecretHandle,
  boundedTtl,
  canonicalIso,
  currentDate,
  normalizeAllowedCapabilities,
  normalizeAllowedTargets,
  normalizeSecretProjectionTarget,
  resolveSecretFileProjectionPath,
  secretProjectionTargetEquals,
  sha256,
} from "./secretLeaseSchema.js";
import type {
  CreateSecretLeaseInput,
  SecretLease,
  SecretLeaseEnvelope,
  SecretLeaseRuntime,
  SecretMaterializationAuthorityBundle,
  SecretMaterializationGrant,
  SecretMaterializationGrantEnvelope,
  SecretMaterializationRequest,
  SecretProjectionTarget,
} from "./secretLeaseTypes.js";

export { resolveSecretFileProjectionPath } from "./secretLeaseSchema.js";
export type {
  CreateSecretLeaseInput,
  SecretEnvironmentProjection,
  SecretFileProjection,
  SecretLease,
  SecretLeaseContinuity,
  SecretLeaseEnvelope,
  SecretLeaseRuntime,
  SecretLeaseStatus,
  SecretMaterializationAuthorityBundle,
  SecretMaterializationGrant,
  SecretMaterializationGrantEnvelope,
  SecretMaterializationRequest,
  SecretProjectionTarget,
} from "./secretLeaseTypes.js";

function freezeLease(lease: SecretLease): SecretLease {
  return Object.freeze({
    ...lease,
    allowedCapabilities: Object.freeze([...lease.allowedCapabilities]),
    allowedTargets: Object.freeze(lease.allowedTargets.map((target) => normalizeSecretProjectionTarget(target))),
    continuity: Object.freeze({ ...lease.continuity }),
  });
}

export function secretLeaseSha256(lease: SecretLease): string {
  return sha256(lease);
}

export function sealSecretLease(lease: SecretLease): SecretLeaseEnvelope {
  const normalized = validateSecretLease(lease);
  return Object.freeze({
    schemaVersion: "toadaid.secret-lease-envelope.v1",
    lease: normalized,
    leaseSha256: secretLeaseSha256(normalized),
  });
}

export function createSecretLease(
  input: CreateSecretLeaseInput,
  authority: CapabilityAuthorityDecision,
): SecretLeaseEnvelope {
  assertAuthority(authority, "secret:lease");
  const createdAt = canonicalIso(input.createdAt, "createdAt");
  const ttlMs = boundedTtl(input.ttlMs, DEFAULT_LEASE_TTL_MS, MAX_LEASE_TTL_MS, "ttlMs");
  const lease: SecretLease = {
    schemaVersion: "toadaid.secret-lease.v1",
    leaseId: assertId(input.leaseId ?? randomUUID(), "leaseId"),
    ownerId: assertId(input.ownerId, "ownerId"),
    providerId: assertProviderProfileId(input.providerId, "providerId"),
    profileId: assertProviderProfileId(input.profileId, "profileId"),
    secretHandle: assertSecretHandle(input.secretHandle),
    allowedCapabilities: normalizeAllowedCapabilities(input.allowedCapabilities),
    allowedTargets: normalizeAllowedTargets(input.allowedTargets),
    createdAt,
    expiresAt: new Date(Date.parse(createdAt) + ttlMs).toISOString(),
    status: "ACTIVE",
    revokedAt: null,
    revokedBy: null,
    continuity: Object.freeze({ revision: 0, previousLeaseSha256: null }),
  };
  return sealSecretLease(lease);
}

export function validateSecretLease(lease: SecretLease): SecretLease {
  if (lease.schemaVersion !== "toadaid.secret-lease.v1") throw new TypeError("unsupported secret lease schemaVersion");
  const createdAt = canonicalIso(lease.createdAt, "createdAt");
  const expiresAt = canonicalIso(lease.expiresAt, "expiresAt");
  const duration = Date.parse(expiresAt) - Date.parse(createdAt);
  if (duration < 1_000 || duration > MAX_LEASE_TTL_MS) throw new RangeError("secret lease lifetime is invalid");
  if (lease.status !== "ACTIVE" && lease.status !== "REVOKED") throw new TypeError("secret lease status is invalid");
  if (lease.continuity.revision !== 0 && lease.continuity.revision !== 1) throw new TypeError("secret lease revision is invalid");
  if (lease.status === "ACTIVE") {
    if (lease.revokedAt !== null || lease.revokedBy !== null || lease.continuity.revision !== 0 || lease.continuity.previousLeaseSha256 !== null) {
      throw new TypeError("ACTIVE secret lease continuity is invalid");
    }
  } else {
    if (lease.revokedAt === null || lease.revokedBy === null || lease.continuity.revision !== 1) throw new TypeError("REVOKED secret lease state is incomplete");
    canonicalIso(lease.revokedAt, "revokedAt");
    assertId(lease.revokedBy, "revokedBy");
    if (!lease.continuity.previousLeaseSha256 || !SHA256_PATTERN.test(lease.continuity.previousLeaseSha256)) {
      throw new TypeError("REVOKED secret lease predecessor is invalid");
    }
  }
  return freezeLease({
    ...lease,
    leaseId: assertId(lease.leaseId, "leaseId"),
    ownerId: assertId(lease.ownerId, "ownerId"),
    providerId: assertProviderProfileId(lease.providerId, "providerId"),
    profileId: assertProviderProfileId(lease.profileId, "profileId"),
    secretHandle: assertSecretHandle(lease.secretHandle),
    allowedCapabilities: normalizeAllowedCapabilities(lease.allowedCapabilities),
    allowedTargets: normalizeAllowedTargets(lease.allowedTargets),
    createdAt,
    expiresAt,
  });
}

export function validateSecretLeaseEnvelope(value: SecretLeaseEnvelope): SecretLeaseEnvelope {
  if (value.schemaVersion !== "toadaid.secret-lease-envelope.v1") throw new TypeError("unsupported secret lease envelope schemaVersion");
  if (!SHA256_PATTERN.test(value.leaseSha256)) throw new TypeError("secret lease envelope SHA-256 is invalid");
  const lease = validateSecretLease(value.lease);
  if (secretLeaseSha256(lease) !== value.leaseSha256) throw new Error("secret lease integrity mismatch");
  return Object.freeze({ schemaVersion: "toadaid.secret-lease-envelope.v1", lease, leaseSha256: value.leaseSha256 });
}

export function serializeSecretLease(envelope: SecretLeaseEnvelope): string {
  return JSON.stringify(validateSecretLeaseEnvelope(envelope));
}

export function parseSecretLease(serialized: string): SecretLeaseEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new TypeError("secret lease envelope must be valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("secret lease envelope must be an object");
  return validateSecretLeaseEnvelope(parsed as SecretLeaseEnvelope);
}

export function assertSecretLeasePredecessor(
  previousEnvelope: SecretLeaseEnvelope,
  nextEnvelope: SecretLeaseEnvelope,
): void {
  const previous = validateSecretLeaseEnvelope(previousEnvelope);
  const next = validateSecretLeaseEnvelope(nextEnvelope);
  if (previous.lease.leaseId !== next.lease.leaseId) throw new Error("secret lease predecessor leaseId mismatch");
  if (previous.lease.continuity.revision !== 0 || previous.lease.status !== "ACTIVE") {
    throw new Error("secret lease predecessor must be the ACTIVE revision");
  }
  if (next.lease.continuity.revision !== 1 || next.lease.status !== "REVOKED") {
    throw new Error("secret lease successor must be the REVOKED revision");
  }
  if (next.lease.continuity.previousLeaseSha256 !== previous.leaseSha256) {
    throw new Error("secret lease predecessor SHA-256 mismatch");
  }
}

export function revokeSecretLease(
  envelope: SecretLeaseEnvelope,
  revokedBy: string,
  revokedAt: string,
): SecretLeaseEnvelope {
  const current = validateSecretLeaseEnvelope(envelope);
  if (current.lease.status === "REVOKED") return current;
  const at = canonicalIso(revokedAt, "revokedAt");
  if (Date.parse(at) < Date.parse(current.lease.createdAt)) throw new RangeError("revokedAt cannot be before createdAt");
  return sealSecretLease({
    ...current.lease,
    status: "REVOKED",
    revokedAt: at,
    revokedBy: assertId(revokedBy, "revokedBy"),
    continuity: Object.freeze({ revision: 1, previousLeaseSha256: current.leaseSha256 }),
  });
}

function assertLeaseUsable(
  envelope: SecretLeaseEnvelope,
  ownerId: string,
  providerId: string,
  profileId: string,
  forCapabilityId: string,
  target: SecretProjectionTarget,
  runtime: SecretLeaseRuntime,
): SecretLeaseEnvelope {
  const validated = validateSecretLeaseEnvelope(envelope);
  const lease = validated.lease;
  if (lease.status !== "ACTIVE") throw new Error("secret lease is revoked");
  const now = currentDate(runtime);
  if (now.getTime() >= Date.parse(lease.expiresAt)) throw new Error("secret lease is expired");
  if (lease.ownerId !== assertId(ownerId, "ownerId")) throw new Error("secret lease owner mismatch");
  if (lease.providerId !== assertProviderProfileId(providerId, "providerId")) throw new Error("secret lease provider mismatch");
  if (lease.profileId !== assertProviderProfileId(profileId, "profileId")) throw new Error("secret lease profile mismatch");
  const consumerId = assertCapabilityId(forCapabilityId, "forCapabilityId");
  if (!lease.allowedCapabilities.includes(consumerId)) throw new Error(`secret lease does not allow capability: ${consumerId}`);
  const normalizedTarget = normalizeSecretProjectionTarget(target);
  if (!lease.allowedTargets.some((candidate) => secretProjectionTargetEquals(candidate, normalizedTarget))) {
    throw new Error("secret lease does not allow requested projection target");
  }
  return validated;
}

function freezeGrant(grant: SecretMaterializationGrant): SecretMaterializationGrant {
  return Object.freeze({ ...grant, target: normalizeSecretProjectionTarget(grant.target) });
}

export function secretMaterializationGrantSha256(grant: SecretMaterializationGrant): string {
  return sha256(grant);
}

export function sealSecretMaterializationGrant(grant: SecretMaterializationGrant): SecretMaterializationGrantEnvelope {
  const normalized = validateSecretMaterializationGrant(grant);
  return Object.freeze({
    schemaVersion: "toadaid.secret-materialization-grant-envelope.v1",
    grant: normalized,
    grantSha256: secretMaterializationGrantSha256(normalized),
  });
}

export function createSecretMaterializationGrant(
  leaseEnvelope: SecretLeaseEnvelope,
  request: SecretMaterializationRequest,
  authority: SecretMaterializationAuthorityBundle,
  runtime: SecretLeaseRuntime = {},
): SecretMaterializationGrantEnvelope {
  assertAuthority(authority.materialize, "secret:materialize");
  assertAuthority(authority.consumer, request.forCapabilityId, "consumer capability");
  const leaseEnvelopeValidated = assertLeaseUsable(
    leaseEnvelope,
    request.ownerId,
    request.providerId,
    request.profileId,
    request.forCapabilityId,
    request.target,
    runtime,
  );
  const issuedAt = canonicalIso(request.issuedAt, "issuedAt");
  const now = currentDate(runtime);
  if (Date.parse(issuedAt) > now.getTime() + 5_000 || Date.parse(issuedAt) < now.getTime() - 60_000) {
    throw new RangeError("issuedAt is outside the bounded current-time window");
  }
  const ttlMs = boundedTtl(request.ttlMs, DEFAULT_MATERIALIZATION_TTL_MS, MAX_MATERIALIZATION_TTL_MS, "materialization ttlMs");
  const expiresAtMs = Math.min(Date.parse(issuedAt) + ttlMs, Date.parse(leaseEnvelopeValidated.lease.expiresAt));
  if (expiresAtMs <= Date.parse(issuedAt)) throw new Error("secret lease expires before materialization grant can be used");
  const lease = leaseEnvelopeValidated.lease;
  return sealSecretMaterializationGrant({
    schemaVersion: "toadaid.secret-materialization-grant.v1",
    materializationId: assertId(request.materializationId ?? randomUUID(), "materializationId"),
    leaseId: lease.leaseId,
    leaseSha256: leaseEnvelopeValidated.leaseSha256,
    ownerId: lease.ownerId,
    providerId: lease.providerId,
    profileId: lease.profileId,
    secretHandle: lease.secretHandle,
    forCapabilityId: assertCapabilityId(request.forCapabilityId, "forCapabilityId"),
    target: normalizeSecretProjectionTarget(request.target),
    issuedAt,
    expiresAt: new Date(expiresAtMs).toISOString(),
  });
}

export function validateSecretMaterializationGrant(grant: SecretMaterializationGrant): SecretMaterializationGrant {
  if (grant.schemaVersion !== "toadaid.secret-materialization-grant.v1") throw new TypeError("unsupported materialization grant schemaVersion");
  if (!SHA256_PATTERN.test(grant.leaseSha256)) throw new TypeError("materialization leaseSha256 is invalid");
  const issuedAt = canonicalIso(grant.issuedAt, "issuedAt");
  const expiresAt = canonicalIso(grant.expiresAt, "expiresAt");
  const duration = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (duration < 1 || duration > MAX_MATERIALIZATION_TTL_MS) throw new RangeError("materialization grant lifetime is invalid");
  return freezeGrant({
    ...grant,
    materializationId: assertId(grant.materializationId, "materializationId"),
    leaseId: assertId(grant.leaseId, "leaseId"),
    ownerId: assertId(grant.ownerId, "ownerId"),
    providerId: assertProviderProfileId(grant.providerId, "providerId"),
    profileId: assertProviderProfileId(grant.profileId, "profileId"),
    secretHandle: assertSecretHandle(grant.secretHandle),
    forCapabilityId: assertCapabilityId(grant.forCapabilityId, "forCapabilityId"),
    target: normalizeSecretProjectionTarget(grant.target),
    issuedAt,
    expiresAt,
  });
}

export function validateSecretMaterializationGrantEnvelope(value: SecretMaterializationGrantEnvelope): SecretMaterializationGrantEnvelope {
  if (value.schemaVersion !== "toadaid.secret-materialization-grant-envelope.v1") throw new TypeError("unsupported materialization grant envelope schemaVersion");
  if (!SHA256_PATTERN.test(value.grantSha256)) throw new TypeError("materialization grant SHA-256 is invalid");
  const grant = validateSecretMaterializationGrant(value.grant);
  if (secretMaterializationGrantSha256(grant) !== value.grantSha256) throw new Error("secret materialization grant integrity mismatch");
  return Object.freeze({ schemaVersion: "toadaid.secret-materialization-grant-envelope.v1", grant, grantSha256: value.grantSha256 });
}

export function assertSecretMaterializationGrantUsable(
  grantEnvelope: SecretMaterializationGrantEnvelope,
  leaseEnvelope: SecretLeaseEnvelope,
  authority: SecretMaterializationAuthorityBundle,
  runtime: SecretLeaseRuntime = {},
): SecretMaterializationGrant {
  const grantValidated = validateSecretMaterializationGrantEnvelope(grantEnvelope).grant;
  assertAuthority(authority.materialize, "secret:materialize");
  assertAuthority(authority.consumer, grantValidated.forCapabilityId, "consumer capability");
  const leaseValidated = assertLeaseUsable(
    leaseEnvelope,
    grantValidated.ownerId,
    grantValidated.providerId,
    grantValidated.profileId,
    grantValidated.forCapabilityId,
    grantValidated.target,
    runtime,
  );
  if (leaseValidated.leaseSha256 !== grantValidated.leaseSha256 || leaseValidated.lease.leaseId !== grantValidated.leaseId) {
    throw new Error("materialization grant is not bound to the current secret lease");
  }
  const now = currentDate(runtime);
  if (now.getTime() >= Date.parse(grantValidated.expiresAt)) throw new Error("secret materialization grant is expired");
  return grantValidated;
}

export function serializeSecretMaterializationGrant(envelope: SecretMaterializationGrantEnvelope): string {
  return JSON.stringify(validateSecretMaterializationGrantEnvelope(envelope));
}

export function parseSecretMaterializationGrant(serialized: string): SecretMaterializationGrantEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new TypeError("materialization grant envelope must be valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("materialization grant envelope must be an object");
  return validateSecretMaterializationGrantEnvelope(parsed as SecretMaterializationGrantEnvelope);
}
