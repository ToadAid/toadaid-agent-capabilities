import type {
  CapabilityAuthorityDecision,
} from "./capabilityPolicy.js";
import {
  boundedId,
  canonicalIso,
  capabilityId,
  sha,
  sha256,
} from "./invocationSchema.js";
import type {
  CreateHostConnectorSessionLeaseInput,
  HostConnectorActionCapabilityId,
  HostConnectorSessionAuthorityBundle,
  HostConnectorSessionLease,
  HostConnectorSessionLeaseEnvelope,
  HostConnectorSessionRuntime,
  HostConnectorSessionUseBinding,
  HostConnectorSessionUseRuntime,
  HostConnectorSessionUseRequest,
  NarrowHostConnectorSessionLeaseInput,
  RevokeHostConnectorSessionLeaseInput,
} from "./hostConnectorSessionLeaseTypes.js";

export type * from "./hostConnectorSessionLeaseTypes.js";

export const HOST_CONNECTOR_ACTION_CAPABILITIES:
  readonly HostConnectorActionCapabilityId[] = Object.freeze([
    "host:filesystem-read",
    "host:filesystem-write",
    "host:command-execute",
    "host:tool-invoke",
    "host:connector-use",
  ]);

const HOST_ACTION_CAPABILITY_SET = new Set<string>(
  HOST_CONNECTOR_ACTION_CAPABILITIES,
);

const DEFAULT_TTL_MS = 30 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ALLOWED_CAPABILITIES =
  HOST_CONNECTOR_ACTION_CAPABILITIES.length;
const MAX_REVISION = 1_000_000;
const MAX_SERIALIZED_BYTES = 64 * 1024;

function objectValue(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertAuthority(
  authority: CapabilityAuthorityDecision | undefined,
  expectedCapabilityId: string,
): void {
  if (
    !authority ||
    authority.schemaVersion !==
      "toadaid.capability-authority-decision.v1" ||
    authority.capabilityId !== expectedCapabilityId ||
    authority.installed !== true ||
    authority.decision !== "ALLOW"
  ) {
    throw new Error(
      `host connector capability is not authorized: ${expectedCapabilityId}`,
    );
  }
}

function normalizeHostActionCapability(
  value: string,
): HostConnectorActionCapabilityId {
  const normalized = capabilityId(value);
  if (!HOST_ACTION_CAPABILITY_SET.has(normalized)) {
    throw new TypeError(
      `unsupported host connector action capability: ${normalized}`,
    );
  }
  return normalized as HostConnectorActionCapabilityId;
}

function normalizeAllowedCapabilities(
  values: readonly HostConnectorActionCapabilityId[],
  allowEmpty: boolean,
): readonly HostConnectorActionCapabilityId[] {
  if (!Array.isArray(values)) {
    throw new TypeError("allowedCapabilities must be an array");
  }
  if (!allowEmpty && values.length === 0) {
    throw new TypeError(
      "allowedCapabilities must contain at least one host action capability",
    );
  }
  if (values.length > MAX_ALLOWED_CAPABILITIES) {
    throw new RangeError(
      `allowedCapabilities exceeds ${MAX_ALLOWED_CAPABILITIES} entries`,
    );
  }

  const seen = new Set<string>();
  const normalized = values.map((value, index) => {
    const item = normalizeHostActionCapability(value);
    if (seen.has(item)) {
      throw new TypeError(
        `duplicate allowedCapabilities entry at index ${index}: ${item}`,
      );
    }
    seen.add(item);
    return item;
  });
  normalized.sort();
  return Object.freeze(normalized);
}

function ttlMs(value: number | undefined): number {
  const resolved = value ?? DEFAULT_TTL_MS;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < 1_000 ||
    resolved > MAX_TTL_MS
  ) {
    throw new RangeError(
      `ttlMs must be an integer between 1000 and ${MAX_TTL_MS}`,
    );
  }
  return resolved;
}

function nowIso(
  value: string | undefined,
  label: string,
  runtime: HostConnectorSessionRuntime,
): string {
  return canonicalIso(
    value,
    label,
    runtime.now ?? (() => new Date()),
  );
}

function normalizeConfigSha(
  value: string | null | undefined,
): string | null {
  return value == null
    ? null
    : sha(value, "connectionConfigSha256")!;
}

export function validateHostConnectorSessionLease(
  value: unknown,
): HostConnectorSessionLease {
  const raw = objectValue(value, "host connector session lease");
  if (
    raw.schemaVersion !==
    "toadaid.host-connector-session-lease.v1"
  ) {
    throw new TypeError(
      "unsupported host connector session lease schemaVersion",
    );
  }

  const hostId = boundedId(raw.hostId as string, "hostId");
  const sessionId = boundedId(raw.sessionId as string, "sessionId");
  const ownerId = boundedId(raw.ownerId as string, "ownerId");

  const revision = raw.revision;
  if (
    !Number.isSafeInteger(revision) ||
    (revision as number) < 0 ||
    (revision as number) > MAX_REVISION
  ) {
    throw new RangeError("host connector lease revision is invalid");
  }

  const transition = raw.transition;
  if (
    transition !== "CREATE" &&
    transition !== "NARROW" &&
    transition !== "REVOKE"
  ) {
    throw new TypeError("host connector lease transition is invalid");
  }

  const createdAt = canonicalIso(
    raw.createdAt as string,
    "createdAt",
  );
  const updatedAt = canonicalIso(
    raw.updatedAt as string,
    "updatedAt",
  );
  const expiresAt = canonicalIso(
    raw.expiresAt as string,
    "expiresAt",
  );

  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new RangeError(
      "host connector lease updatedAt is earlier than createdAt",
    );
  }
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) {
    throw new RangeError(
      "host connector lease expiresAt must be after createdAt",
    );
  }
  if (
    Date.parse(expiresAt) - Date.parse(createdAt) >
    MAX_TTL_MS
  ) {
    throw new RangeError(
      "host connector lease exceeds maximum TTL",
    );
  }

  if (!Array.isArray(raw.allowedCapabilities)) {
    throw new TypeError(
      "host connector lease allowedCapabilities must be an array",
    );
  }
  const allowedCapabilities = normalizeAllowedCapabilities(
    raw.allowedCapabilities as HostConnectorActionCapabilityId[],
    transition !== "CREATE",
  );

  const connectionConfigSha256 = normalizeConfigSha(
    raw.connectionConfigSha256 as string | null,
  );

  const status = raw.status;
  if (status !== "ACTIVE" && status !== "REVOKED") {
    throw new TypeError("host connector lease status is invalid");
  }

  const revokedAt =
    raw.revokedAt === null
      ? null
      : canonicalIso(raw.revokedAt as string, "revokedAt");

  const continuity = objectValue(
    raw.continuity,
    "host connector lease continuity",
  );
  const previousLeaseSha256 =
    continuity.previousLeaseSha256 === null
      ? null
      : sha(
          continuity.previousLeaseSha256 as string,
          "continuity.previousLeaseSha256",
        )!;

  if (revision === 0) {
    if (
      transition !== "CREATE" ||
      status !== "ACTIVE" ||
      revokedAt !== null ||
      previousLeaseSha256 !== null
    ) {
      throw new Error(
        "initial host connector session lease is invalid",
      );
    }
  } else if (
    transition === "CREATE" ||
    previousLeaseSha256 === null
  ) {
    throw new Error(
      "non-initial host connector session lease is invalid",
    );
  }

  if (
    transition === "NARROW" &&
    (status !== "ACTIVE" || revokedAt !== null)
  ) {
    throw new Error(
      "NARROW transition must preserve ACTIVE status",
    );
  }

  if (
    transition === "REVOKE" &&
    (
      status !== "REVOKED" ||
      revokedAt !== updatedAt ||
      allowedCapabilities.length !== 0
    )
  ) {
    throw new Error(
      "REVOKE transition must clear capabilities and bind revokedAt",
    );
  }

  return Object.freeze({
    schemaVersion: "toadaid.host-connector-session-lease.v1",
    hostId,
    sessionId,
    ownerId,
    revision: revision as number,
    transition,
    createdAt,
    updatedAt,
    expiresAt,
    allowedCapabilities,
    connectionConfigSha256,
    status,
    revokedAt,
    continuity: Object.freeze({ previousLeaseSha256 }),
  });
}

export function hostConnectorSessionLeaseSha256(
  lease: HostConnectorSessionLease,
): string {
  return sha256(validateHostConnectorSessionLease(lease));
}

export function sealHostConnectorSessionLease(
  lease: HostConnectorSessionLease,
): HostConnectorSessionLeaseEnvelope {
  const normalized = validateHostConnectorSessionLease(lease);
  return Object.freeze({
    schemaVersion:
      "toadaid.host-connector-session-lease-envelope.v1",
    lease: normalized,
    leaseSha256: sha256(normalized),
  });
}

export function validateHostConnectorSessionLeaseEnvelope(
  value: unknown,
): HostConnectorSessionLeaseEnvelope {
  const raw = objectValue(
    value,
    "host connector session lease envelope",
  );
  if (
    raw.schemaVersion !==
    "toadaid.host-connector-session-lease-envelope.v1"
  ) {
    throw new TypeError(
      "unsupported host connector session lease envelope schemaVersion",
    );
  }

  const lease = validateHostConnectorSessionLease(raw.lease);
  const leaseSha256 = sha(
    raw.leaseSha256 as string,
    "leaseSha256",
  )!;
  if (leaseSha256 !== sha256(lease)) {
    throw new Error(
      "host connector session lease integrity mismatch",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.host-connector-session-lease-envelope.v1",
    lease,
    leaseSha256,
  });
}

export function assertHostConnectorSessionLeasePredecessor(
  previousInput: HostConnectorSessionLeaseEnvelope,
  nextInput: HostConnectorSessionLeaseEnvelope,
): void {
  const previous =
    validateHostConnectorSessionLeaseEnvelope(previousInput);
  const next =
    validateHostConnectorSessionLeaseEnvelope(nextInput);

  if (previous.lease.status === "REVOKED") {
    throw new Error(
      "revoked host connector session lease cannot transition",
    );
  }

  if (
    next.lease.hostId !== previous.lease.hostId ||
    next.lease.sessionId !== previous.lease.sessionId ||
    next.lease.ownerId !== previous.lease.ownerId
  ) {
    throw new Error(
      "host connector lease predecessor identity mismatch",
    );
  }

  if (
    next.lease.createdAt !== previous.lease.createdAt ||
    next.lease.expiresAt !== previous.lease.expiresAt ||
    next.lease.connectionConfigSha256 !==
      previous.lease.connectionConfigSha256
  ) {
    throw new Error(
      "host connector lease immutable evidence changed",
    );
  }

  if (next.lease.revision !== previous.lease.revision + 1) {
    throw new Error(
      "host connector lease revision is not contiguous",
    );
  }
  if (
    next.lease.continuity.previousLeaseSha256 !==
    previous.leaseSha256
  ) {
    throw new Error(
      "host connector lease predecessor digest mismatch",
    );
  }
  if (
    Date.parse(next.lease.updatedAt) <
    Date.parse(previous.lease.updatedAt)
  ) {
    throw new RangeError(
      "host connector lease time moved backwards",
    );
  }

  const previousCapabilities = new Set(
    previous.lease.allowedCapabilities,
  );
  for (const item of next.lease.allowedCapabilities) {
    if (!previousCapabilities.has(item)) {
      throw new Error(
        `host connector lease cannot widen capability scope: ${item}`,
      );
    }
  }

  if (next.lease.transition === "NARROW") {
    if (
      next.lease.allowedCapabilities.length >=
      previous.lease.allowedCapabilities.length
    ) {
      throw new Error(
        "NARROW transition must strictly reduce capability scope",
      );
    }
  } else if (next.lease.transition === "REVOKE") {
    if (next.lease.allowedCapabilities.length !== 0) {
      throw new Error(
        "REVOKE transition must remove all capability scope",
      );
    }
  } else {
    throw new Error(
      "non-initial host connector transition cannot be CREATE",
    );
  }
}

export function createHostConnectorSessionLease(
  input: CreateHostConnectorSessionLeaseInput,
  sessionAuthority: CapabilityAuthorityDecision,
  runtime: HostConnectorSessionRuntime = {},
): HostConnectorSessionLeaseEnvelope {
  assertAuthority(sessionAuthority, "host:session");

  const createdAt = nowIso(
    input.createdAt,
    "createdAt",
    runtime,
  );
  const allowedCapabilities = normalizeAllowedCapabilities(
    input.allowedCapabilities,
    false,
  );

  return sealHostConnectorSessionLease({
    schemaVersion: "toadaid.host-connector-session-lease.v1",
    hostId: boundedId(input.hostId, "hostId"),
    sessionId: boundedId(input.sessionId, "sessionId"),
    ownerId: boundedId(input.ownerId, "ownerId"),
    revision: 0,
    transition: "CREATE",
    createdAt,
    updatedAt: createdAt,
    expiresAt: new Date(
      Date.parse(createdAt) + ttlMs(input.ttlMs),
    ).toISOString(),
    allowedCapabilities,
    connectionConfigSha256: normalizeConfigSha(
      input.connectionConfigSha256,
    ),
    status: "ACTIVE",
    revokedAt: null,
    continuity: Object.freeze({
      previousLeaseSha256: null,
    }),
  });
}

export function narrowHostConnectorSessionLease(
  envelopeInput: HostConnectorSessionLeaseEnvelope,
  input: NarrowHostConnectorSessionLeaseInput,
  sessionAuthority: CapabilityAuthorityDecision,
  runtime: HostConnectorSessionRuntime = {},
): HostConnectorSessionLeaseEnvelope {
  assertAuthority(sessionAuthority, "host:session");
  const current =
    validateHostConnectorSessionLeaseEnvelope(envelopeInput);

  if (
    boundedId(input.ownerId, "ownerId") !==
    current.lease.ownerId
  ) {
    throw new Error("host connector session owner mismatch");
  }
  if (current.lease.status !== "ACTIVE") {
    throw new Error(
      "host connector session lease is revoked",
    );
  }

  const updatedAt = nowIso(
    input.updatedAt,
    "updatedAt",
    runtime,
  );
  if (
    Date.parse(updatedAt) >=
    Date.parse(current.lease.expiresAt)
  ) {
    throw new Error(
      "expired host connector session lease cannot be narrowed",
    );
  }

  const next = sealHostConnectorSessionLease({
    ...current.lease,
    revision: current.lease.revision + 1,
    transition: "NARROW",
    updatedAt,
    allowedCapabilities: normalizeAllowedCapabilities(
      input.allowedCapabilities,
      true,
    ),
    continuity: Object.freeze({
      previousLeaseSha256: current.leaseSha256,
    }),
  });

  assertHostConnectorSessionLeasePredecessor(current, next);
  return next;
}

export function revokeHostConnectorSessionLease(
  envelopeInput: HostConnectorSessionLeaseEnvelope,
  input: RevokeHostConnectorSessionLeaseInput,
  sessionAuthority: CapabilityAuthorityDecision,
  runtime: HostConnectorSessionRuntime = {},
): HostConnectorSessionLeaseEnvelope {
  assertAuthority(sessionAuthority, "host:session");
  const current =
    validateHostConnectorSessionLeaseEnvelope(envelopeInput);

  if (
    boundedId(input.ownerId, "ownerId") !==
    current.lease.ownerId
  ) {
    throw new Error("host connector session owner mismatch");
  }
  if (current.lease.status === "REVOKED") {
    return current;
  }

  const revokedAt = nowIso(
    input.revokedAt,
    "revokedAt",
    runtime,
  );
  const next = sealHostConnectorSessionLease({
    ...current.lease,
    revision: current.lease.revision + 1,
    transition: "REVOKE",
    updatedAt: revokedAt,
    allowedCapabilities: Object.freeze([]),
    status: "REVOKED",
    revokedAt,
    continuity: Object.freeze({
      previousLeaseSha256: current.leaseSha256,
    }),
  });

  assertHostConnectorSessionLeasePredecessor(current, next);
  return next;
}

export function assertHostConnectorSessionLeaseUsable(
  envelopeInput: HostConnectorSessionLeaseEnvelope,
  request: HostConnectorSessionUseRequest,
  authority: HostConnectorSessionAuthorityBundle,
  runtime: HostConnectorSessionUseRuntime,
): HostConnectorSessionUseBinding {
  assertAuthority(authority.session, "host:session");
  const lease =
    validateHostConnectorSessionLeaseEnvelope(envelopeInput);

  const capability = normalizeHostActionCapability(
    request.capabilityId,
  );
  assertAuthority(authority.action, capability);

  if (
    boundedId(request.hostId, "hostId") !==
    lease.lease.hostId ||
    boundedId(request.sessionId, "sessionId") !==
    lease.lease.sessionId ||
    boundedId(request.ownerId, "ownerId") !==
    lease.lease.ownerId
  ) {
    throw new Error(
      "host connector session identity mismatch",
    );
  }

  if (
    !runtime ||
    typeof runtime.resolveCurrentLeaseSha256 !== "function"
  ) {
    throw new Error(
      "host connector current lease resolver is required",
    );
  }
  const currentLeaseSha256 = runtime.resolveCurrentLeaseSha256(
    Object.freeze({
      hostId: lease.lease.hostId,
      sessionId: lease.lease.sessionId,
      ownerId: lease.lease.ownerId,
    }),
  );
  if (currentLeaseSha256 === null) {
    throw new Error(
      "host connector current lease is unavailable",
    );
  }
  const normalizedCurrentLeaseSha256 = sha(
    currentLeaseSha256,
    "currentLeaseSha256",
  )!;
  if (normalizedCurrentLeaseSha256 !== lease.leaseSha256) {
    throw new Error(
      "host connector session lease is stale",
    );
  }

  if (lease.lease.status !== "ACTIVE") {
    throw new Error(
      "host connector session lease is revoked",
    );
  }

  const now = (
    runtime.now ?? (() => new Date())
  )();
  if (
    !(now instanceof Date) ||
    Number.isNaN(now.getTime())
  ) {
    throw new TypeError(
      "runtime.now must return a valid Date",
    );
  }
  if (now.getTime() >= Date.parse(lease.lease.expiresAt)) {
    throw new Error(
      "host connector session lease is expired",
    );
  }

  if (
    !lease.lease.allowedCapabilities.includes(capability)
  ) {
    throw new Error(
      `host connector lease does not permit capability: ${capability}`,
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.host-connector-session-use-binding.v1",
    hostId: lease.lease.hostId,
    sessionId: lease.lease.sessionId,
    ownerId: lease.lease.ownerId,
    capabilityId: capability,
    leaseSha256: lease.leaseSha256,
    connectionConfigSha256:
      lease.lease.connectionConfigSha256,
    expiresAt: lease.lease.expiresAt,
  });
}

export function serializeHostConnectorSessionLease(
  envelope: HostConnectorSessionLeaseEnvelope,
): string {
  return JSON.stringify(
    validateHostConnectorSessionLeaseEnvelope(envelope),
  );
}

export function parseHostConnectorSessionLease(
  serialized: string,
): HostConnectorSessionLeaseEnvelope {
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized, "utf8") >
      MAX_SERIALIZED_BYTES
  ) {
    throw new RangeError(
      "host connector session lease payload exceeds bound",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new TypeError(
      "host connector session lease payload must be valid JSON",
    );
  }

  return validateHostConnectorSessionLeaseEnvelope(parsed);
}
