import {
  assertBrowserSessionLeaseUsable,
  validateBrowserSessionLeaseEnvelope,
} from "./browserSessionLease.js";
import {
  SHA256_PATTERN,
  exactOrigin,
  sha256,
} from "./adaptiveWebPolicy.js";
import type {
  BrowserSessionBinding,
  BrowserSessionLeaseEnvelope,
} from "./browserSessionLease.js";
import type {
  FinalizeReusableBrowserRequestInput,
  NormalizedReusableBrowserRequestPolicy,
  PrepareReusableBrowserRequestInput,
  ReusableBrowserDispositionReason,
  ReusableBrowserDispositionReceipt,
  ReusableBrowserExecutionOutcome,
  ReusableBrowserHeader,
  ReusableBrowserPoolCandidate,
  ReusableBrowserPreparationReceipt,
  ReusableBrowserRequestPolicy,
  ReusableBrowserResourceType,
  ReusableBrowserRuntime,
  ReusableBrowserRuntimeAdapter,
  ReusableBrowserRuntimeIdentity,
  ReusableBrowserSessionMode,
} from "./browserSessionReuseTypes.js";

export type * from "./browserSessionReuseTypes.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 120_000;
const MAX_HEADERS = 64;
const MAX_HEADER_VALUE_CHARS = 8_192;
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORBIDDEN_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "set-cookie",
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
]);

const RESOURCE_TYPES: readonly ReusableBrowserResourceType[] = [
  "document",
  "stylesheet",
  "image",
  "font",
  "script",
  "xhr",
  "fetch",
  "media",
];

const DEFAULT_RESOURCE_TYPES: readonly ReusableBrowserResourceType[] =
  Object.freeze([...RESOURCE_TYPES]);

function currentIso(runtime: ReusableBrowserRuntime): string {
  const value = (runtime.now ?? (() => new Date()))();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new TypeError("runtime.now must return a valid Date");
  }
  return value.toISOString();
}

function canonicalIso(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new TypeError(`${label} must be canonical ISO-8601`);
  }
  return value;
}

function exactTimeout(value: number | undefined): number {
  const resolved = value ?? DEFAULT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < MIN_TIMEOUT_MS ||
    resolved > MAX_TIMEOUT_MS
  ) {
    throw new RangeError(
      `timeoutMs must be an integer between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
    );
  }
  return resolved;
}

function normalizeHeaders(
  input: Readonly<Record<string, string>> | undefined,
): readonly ReusableBrowserHeader[] {
  const headers = input ?? {};
  if (
    typeof headers !== "object" ||
    headers === null ||
    Array.isArray(headers)
  ) {
    throw new TypeError("headers must be an object");
  }

  const entries = Object.entries(headers);
  if (entries.length > MAX_HEADERS) {
    throw new RangeError(`headers exceeds ${MAX_HEADERS} entries`);
  }

  const seen = new Set<string>();
  const normalized = entries.map(([nameInput, value], index) => {
    if (!HEADER_NAME_PATTERN.test(nameInput)) {
      throw new TypeError(`headers[${index}] name is invalid`);
    }
    const name = nameInput.toLowerCase();
    if (seen.has(name)) {
      throw new TypeError(`duplicate header after normalization: ${name}`);
    }
    seen.add(name);

    if (FORBIDDEN_HEADERS.has(name)) {
      throw new Error(`reusable browser policy forbids sensitive/runtime header: ${name}`);
    }
    if (
      typeof value !== "string" ||
      value.length > MAX_HEADER_VALUE_CHARS ||
      /[\u0000-\u001f\u007f]/.test(value)
    ) {
      throw new TypeError(`header value is invalid: ${name}`);
    }

    return Object.freeze({ name, value });
  });

  normalized.sort((a, b) => a.name.localeCompare(b.name));
  return Object.freeze(normalized);
}

function normalizeResourceTypes(
  values: readonly ReusableBrowserResourceType[] | undefined,
): readonly ReusableBrowserResourceType[] {
  if (values === undefined) {
    return DEFAULT_RESOURCE_TYPES;
  }
  if (!Array.isArray(values) || values.length === 0) {
    throw new TypeError("allowedResourceTypes must contain at least one entry");
  }

  const allowed = new Set<ReusableBrowserResourceType>(RESOURCE_TYPES);
  const seen = new Set<ReusableBrowserResourceType>();
  const normalized: ReusableBrowserResourceType[] = [];

  for (const value of values) {
    if (!allowed.has(value)) {
      throw new TypeError(`unsupported reusable browser resource type: ${String(value)}`);
    }
    if (!seen.has(value)) {
      seen.add(value);
      normalized.push(value);
    }
  }

  normalized.sort();
  return Object.freeze(normalized);
}

function assertModeMatchesBinding(
  mode: ReusableBrowserSessionMode,
  binding: BrowserSessionBinding,
): void {
  if (mode === "ONE_SHOT_ANONYMOUS") {
    if (binding.persistence !== "EPHEMERAL" || binding.stateRef !== null) {
      throw new Error(
        "ONE_SHOT_ANONYMOUS requires an EPHEMERAL P8 browser session",
      );
    }
    return;
  }

  if (mode === "PERSISTENT_AUTHENTICATED") {
    if (binding.persistence !== "PERSISTENT" || binding.stateRef === null) {
      throw new Error(
        "PERSISTENT_AUTHENTICATED requires a PERSISTENT P8 browser session",
      );
    }
    return;
  }

  throw new TypeError("reusable browser session mode is invalid");
}

function normalizeResourceOrigins(
  input: readonly string[] | undefined,
  binding: BrowserSessionBinding,
  lease: BrowserSessionLeaseEnvelope,
): readonly string[] {
  const values = input ?? [];
  if (!Array.isArray(values) || values.length > 64) {
    throw new RangeError("allowedResourceOrigins exceeds 64 entries");
  }

  const normalized = new Set<string>([binding.origin]);
  for (const value of values) {
    const origin = exactOrigin(value, "allowedResourceOrigins entry");
    if (!lease.lease.allowedOrigins.includes(origin)) {
      throw new Error(
        `resource origin is outside P8 lease authority: ${origin}`,
      );
    }
    normalized.add(origin);
  }

  return Object.freeze([...normalized].sort());
}

export function normalizeReusableBrowserRequestPolicy(
  policyInput: ReusableBrowserRequestPolicy,
  binding: BrowserSessionBinding,
  leaseInput: BrowserSessionLeaseEnvelope,
): NormalizedReusableBrowserRequestPolicy {
  const lease = validateBrowserSessionLeaseEnvelope(leaseInput);
  if (
    binding.sessionId !== lease.lease.sessionId ||
    binding.ownerId !== lease.lease.ownerId ||
    !lease.lease.allowedOrigins.includes(binding.origin)
  ) {
    throw new Error("browser session binding does not match P8 lease");
  }

  if (
    policyInput.allowPrivateNetwork !== undefined &&
    typeof policyInput.allowPrivateNetwork !== "boolean"
  ) {
    throw new TypeError("allowPrivateNetwork must be boolean");
  }
  if (policyInput.allowPrivateNetwork === true) {
    throw new Error(
      "P9B v1 does not grant private-network authority",
    );
  }

  return Object.freeze({
    timeoutMs: exactTimeout(policyInput.timeoutMs),
    headers: normalizeHeaders(policyInput.headers),
    allowedTopLevelOrigins: Object.freeze([binding.origin]),
    allowedResourceOrigins: normalizeResourceOrigins(
      policyInput.allowedResourceOrigins,
      binding,
      lease,
    ),
    allowedResourceTypes: normalizeResourceTypes(
      policyInput.allowedResourceTypes,
    ),
    allowPrivateNetwork: false,
    allowedHttpMethods: Object.freeze(["GET", "HEAD"] as const),
    allowWebSockets: false as const,
  });
}

function reuseKeyFor(
  lease: BrowserSessionLeaseEnvelope,
  binding: BrowserSessionBinding,
): string {
  if (binding.stateRef === null) {
    throw new Error("persistent reusable browser session requires stateRef");
  }
  return sha256({
    schemaVersion: "toadaid.reusable-browser-reuse-key.v1",
    sessionId: binding.sessionId,
    origin: binding.origin,
    leaseSha256: lease.leaseSha256,
    stateRef: binding.stateRef,
  });
}

function preparationCore(
  receipt: Omit<ReusableBrowserPreparationReceipt, "receiptSha256">,
): Omit<ReusableBrowserPreparationReceipt, "receiptSha256"> {
  return Object.freeze({
    schemaVersion: "toadaid.reusable-browser-preparation-receipt.v1" as const,
    sessionId: receipt.sessionId,
    origin: exactOrigin(receipt.origin, "preparation origin"),
    mode: receipt.mode,
    leaseSha256: receipt.leaseSha256,
    reuseKey: receipt.reuseKey,
    sourceCandidateSha256: receipt.sourceCandidateSha256,
    settingsSha256: receipt.settingsSha256,
    checkout: receipt.checkout,
    preparedAt: canonicalIso(receipt.preparedAt, "preparedAt"),
  });
}

export function validateReusableBrowserPreparationReceipt(
  receipt: ReusableBrowserPreparationReceipt,
): ReusableBrowserPreparationReceipt {
  if (
    receipt.schemaVersion !==
    "toadaid.reusable-browser-preparation-receipt.v1"
  ) {
    throw new TypeError(
      "unsupported reusable browser preparation receipt schemaVersion",
    );
  }
  if (
    receipt.mode !== "ONE_SHOT_ANONYMOUS" &&
    receipt.mode !== "PERSISTENT_AUTHENTICATED"
  ) {
    throw new TypeError("reusable browser preparation mode is invalid");
  }
  if (receipt.checkout !== "FRESH" && receipt.checkout !== "REUSED") {
    throw new TypeError("reusable browser checkout state is invalid");
  }
  if (!SHA256_PATTERN.test(receipt.leaseSha256)) {
    throw new TypeError("preparation leaseSha256 is invalid");
  }
  if (!SHA256_PATTERN.test(receipt.settingsSha256)) {
    throw new TypeError("preparation settingsSha256 is invalid");
  }
  if (
    receipt.reuseKey !== null &&
    !SHA256_PATTERN.test(receipt.reuseKey)
  ) {
    throw new TypeError("preparation reuseKey is invalid");
  }
  if (
    receipt.sourceCandidateSha256 !== null &&
    !SHA256_PATTERN.test(receipt.sourceCandidateSha256)
  ) {
    throw new TypeError("preparation sourceCandidateSha256 is invalid");
  }
  if (!SHA256_PATTERN.test(receipt.receiptSha256)) {
    throw new TypeError("preparation receiptSha256 is invalid");
  }
  if (
    (receipt.mode === "ONE_SHOT_ANONYMOUS" && receipt.reuseKey !== null) ||
    (receipt.mode === "PERSISTENT_AUTHENTICATED" && receipt.reuseKey === null)
  ) {
    throw new Error("preparation reuse key does not match session mode");
  }
  if (
    receipt.mode === "ONE_SHOT_ANONYMOUS" &&
    receipt.checkout === "REUSED"
  ) {
    throw new Error("one-shot anonymous request cannot be reused");
  }
  if (
    (receipt.checkout === "FRESH" &&
      receipt.sourceCandidateSha256 !== null) ||
    (receipt.checkout === "REUSED" &&
      receipt.sourceCandidateSha256 === null)
  ) {
    throw new Error(
      "preparation source candidate does not match checkout state",
    );
  }

  const core = preparationCore(receipt);
  if (sha256(core) !== receipt.receiptSha256) {
    throw new Error("reusable browser preparation receipt integrity mismatch");
  }
  return Object.freeze({ ...core, receiptSha256: receipt.receiptSha256 });
}

function candidateCore(
  candidate: Omit<ReusableBrowserPoolCandidate, "candidateSha256">,
): Omit<ReusableBrowserPoolCandidate, "candidateSha256"> {
  return Object.freeze({
    schemaVersion: "toadaid.reusable-browser-pool-candidate.v1" as const,
    sessionId: candidate.sessionId,
    origin: exactOrigin(candidate.origin, "pool candidate origin"),
    leaseSha256: candidate.leaseSha256,
    reuseKey: candidate.reuseKey,
    lastSettingsSha256: candidate.lastSettingsSha256,
    sourcePreparationReceiptSha256:
      candidate.sourcePreparationReceiptSha256,
    status: "READY" as const,
  });
}

export function validateReusableBrowserPoolCandidate(
  candidate: ReusableBrowserPoolCandidate,
): ReusableBrowserPoolCandidate {
  if (
    candidate.schemaVersion !==
    "toadaid.reusable-browser-pool-candidate.v1" ||
    candidate.status !== "READY"
  ) {
    throw new TypeError("reusable browser pool candidate is invalid");
  }

  for (const [label, value] of [
    ["leaseSha256", candidate.leaseSha256],
    ["reuseKey", candidate.reuseKey],
    ["lastSettingsSha256", candidate.lastSettingsSha256],
    [
      "sourcePreparationReceiptSha256",
      candidate.sourcePreparationReceiptSha256,
    ],
    ["candidateSha256", candidate.candidateSha256],
  ] as const) {
    if (!SHA256_PATTERN.test(value)) {
      throw new TypeError(`pool candidate ${label} is invalid`);
    }
  }

  const core = candidateCore(candidate);
  if (sha256(core) !== candidate.candidateSha256) {
    throw new Error("reusable browser pool candidate integrity mismatch");
  }
  return Object.freeze({
    ...core,
    candidateSha256: candidate.candidateSha256,
  });
}

function assertCandidateMatches(
  candidateInput: ReusableBrowserPoolCandidate,
  sessionId: string,
  origin: string,
  leaseSha256: string,
  reuseKey: string,
): ReusableBrowserPoolCandidate {
  const candidate = validateReusableBrowserPoolCandidate(candidateInput);
  if (
    candidate.sessionId !== sessionId ||
    candidate.origin !== origin ||
    candidate.leaseSha256 !== leaseSha256 ||
    candidate.reuseKey !== reuseKey
  ) {
    throw new Error(
      "reusable browser pool candidate does not match current P8 session",
    );
  }
  return candidate;
}

function runtimeIdentity(
  sessionId: string,
  origin: string,
  leaseSha256: string,
  mode: ReusableBrowserSessionMode,
  reuseKey: string | null,
  sourceCandidateSha256: string | null,
): ReusableBrowserRuntimeIdentity {
  return Object.freeze({
    sessionId,
    origin,
    leaseSha256,
    mode,
    reuseKey,
    sourceCandidateSha256,
  });
}

async function cleanupPreparationFailure(
  adapter: ReusableBrowserRuntimeAdapter,
  identity: ReusableBrowserRuntimeIdentity,
  error: unknown,
): Promise<never> {
  try {
    if (identity.mode === "PERSISTENT_AUTHENTICATED") {
      await adapter.quarantineAndEvict({
        identity,
        reason: "PREPARATION_FAILED",
      });
    } else {
      await adapter.disposeOneShot({
        identity,
        reason: "PREPARATION_FAILED",
      });
    }
  } catch (cleanupError) {
    throw new AggregateError(
      [error, cleanupError],
      "reusable browser preparation and cleanup both failed",
    );
  }
  throw error;
}

export async function prepareReusableBrowserRequest(
  input: PrepareReusableBrowserRequestInput,
  adapter: ReusableBrowserRuntimeAdapter,
  runtime: ReusableBrowserRuntime = {},
): Promise<ReusableBrowserPreparationReceipt> {
  const lease = validateBrowserSessionLeaseEnvelope(input.lease);
  const binding = assertBrowserSessionLeaseUsable(
    lease,
    input.use,
    input.authority,
    runtime,
  );
  assertModeMatchesBinding(input.mode, binding);

  const settings = normalizeReusableBrowserRequestPolicy(
    input.policy ?? {},
    binding,
    lease,
  );
  const settingsSha256 = sha256(settings);
  const reuseKey =
    input.mode === "PERSISTENT_AUTHENTICATED"
      ? reuseKeyFor(lease, binding)
      : null;

  if (input.mode === "ONE_SHOT_ANONYMOUS" && input.candidate !== undefined) {
    throw new Error("one-shot anonymous request cannot accept a pool candidate");
  }

  let checkout: "FRESH" | "REUSED" = "FRESH";
  let sourceCandidateSha256: string | null = null;
  if (input.candidate !== undefined) {
    if (reuseKey === null) {
      throw new Error("pool candidate requires persistent reusable session");
    }
    const candidate = assertCandidateMatches(
      input.candidate,
      binding.sessionId,
      binding.origin,
      lease.leaseSha256,
      reuseKey,
    );
    sourceCandidateSha256 = candidate.candidateSha256;
    checkout = "REUSED";
  }

  const identity = runtimeIdentity(
    binding.sessionId,
    binding.origin,
    lease.leaseSha256,
    input.mode,
    reuseKey,
    sourceCandidateSha256,
  );

  if (sourceCandidateSha256 !== null) {
    let claim;
    try {
      claim = await adapter.claimPoolCandidate({
        identity,
        candidateSha256: sourceCandidateSha256,
      });
    } catch (error) {
      return cleanupPreparationFailure(adapter, identity, error);
    }

    if (
      claim.schemaVersion !==
        "toadaid.reusable-browser-candidate-claim-receipt.v1" ||
      claim.candidateSha256 !== sourceCandidateSha256 ||
      (claim.disposition !== "CLAIMED" &&
        claim.disposition !== "ALREADY_CLAIMED")
    ) {
      return cleanupPreparationFailure(
        adapter,
        identity,
        new Error(
          "reusable browser runtime returned an invalid candidate claim receipt",
        ),
      );
    }
    if (claim.disposition === "ALREADY_CLAIMED") {
      throw new Error("reusable browser pool candidate is already claimed");
    }
  }

  try {
    const reset = await adapter.resetRequestState(identity);
    if (
      reset.schemaVersion !==
        "toadaid.reusable-browser-reset-receipt.v1" ||
      reset.resetComplete !== true
    ) {
      throw new Error("reusable browser runtime did not prove request-state reset");
    }

    const applied = await adapter.applyRequestState({
      identity,
      settings,
      settingsSha256,
    });
    if (
      applied.schemaVersion !==
        "toadaid.reusable-browser-policy-apply-receipt.v1" ||
      applied.appliedSettingsSha256 !== settingsSha256
    ) {
      throw new Error(
        "reusable browser runtime did not apply the exact request settings",
      );
    }
  } catch (error) {
    return cleanupPreparationFailure(adapter, identity, error);
  }

  const core = preparationCore({
    schemaVersion: "toadaid.reusable-browser-preparation-receipt.v1",
    sessionId: binding.sessionId,
    origin: binding.origin,
    mode: input.mode,
    leaseSha256: lease.leaseSha256,
    reuseKey,
    sourceCandidateSha256,
    settingsSha256,
    checkout,
    preparedAt: currentIso(runtime),
  });

  return Object.freeze({
    ...core,
    receiptSha256: sha256(core),
  });
}

function normalizeOutcome(
  outcome: ReusableBrowserExecutionOutcome,
): ReusableBrowserExecutionOutcome {
  if (outcome.status !== "SUCCESS" && outcome.status !== "ERROR") {
    throw new TypeError("reusable browser execution status is invalid");
  }
  if (
    outcome.pageHealth !== "HEALTHY" &&
    outcome.pageHealth !== "POISONED"
  ) {
    throw new TypeError("reusable browser page health is invalid");
  }
  return Object.freeze({
    status: outcome.status,
    pageHealth: outcome.pageHealth,
  });
}

function makeCandidate(
  preparation: ReusableBrowserPreparationReceipt,
): ReusableBrowserPoolCandidate {
  if (preparation.reuseKey === null) {
    throw new Error("one-shot preparation cannot become a pool candidate");
  }
  const core = candidateCore({
    schemaVersion: "toadaid.reusable-browser-pool-candidate.v1",
    sessionId: preparation.sessionId,
    origin: preparation.origin,
    leaseSha256: preparation.leaseSha256,
    reuseKey: preparation.reuseKey,
    lastSettingsSha256: preparation.settingsSha256,
    sourcePreparationReceiptSha256: preparation.receiptSha256,
    status: "READY",
  });
  return Object.freeze({ ...core, candidateSha256: sha256(core) });
}

function dispositionReceipt(
  preparation: ReusableBrowserPreparationReceipt,
  disposition: ReusableBrowserDispositionReceipt["disposition"],
  reason: ReusableBrowserDispositionReason,
  candidate: ReusableBrowserPoolCandidate | null,
  runtime: ReusableBrowserRuntime,
): ReusableBrowserDispositionReceipt {
  return Object.freeze({
    schemaVersion: "toadaid.reusable-browser-disposition-receipt.v1",
    preparationReceiptSha256: preparation.receiptSha256,
    disposition,
    reason,
    candidate,
    finalizedAt: currentIso(runtime),
  });
}

export async function finalizeReusableBrowserRequest(
  input: FinalizeReusableBrowserRequestInput,
  adapter: ReusableBrowserRuntimeAdapter,
  runtime: ReusableBrowserRuntime = {},
): Promise<ReusableBrowserDispositionReceipt> {
  const preparation = validateReusableBrowserPreparationReceipt(
    input.preparation,
  );
  const outcome = normalizeOutcome(input.outcome);
  const identity = runtimeIdentity(
    preparation.sessionId,
    preparation.origin,
    preparation.leaseSha256,
    preparation.mode,
    preparation.reuseKey,
    preparation.sourceCandidateSha256,
  );

  if (preparation.mode === "ONE_SHOT_ANONYMOUS") {
    await adapter.disposeOneShot({
      identity,
      reason: "ONE_SHOT_COMPLETE",
    });
    return dispositionReceipt(
      preparation,
      "DISPOSE",
      "ONE_SHOT_COMPLETE",
      null,
      runtime,
    );
  }

  if (outcome.status === "ERROR") {
    await adapter.quarantineAndEvict({
      identity,
      reason: "EXECUTION_ERROR",
    });
    return dispositionReceipt(
      preparation,
      "QUARANTINE_EVICT",
      "EXECUTION_ERROR",
      null,
      runtime,
    );
  }

  if (outcome.pageHealth === "POISONED") {
    await adapter.quarantineAndEvict({
      identity,
      reason: "POISONED_PAGE",
    });
    return dispositionReceipt(
      preparation,
      "QUARANTINE_EVICT",
      "POISONED_PAGE",
      null,
      runtime,
    );
  }

  try {
    const currentLease = validateBrowserSessionLeaseEnvelope(input.lease);
    const binding = assertBrowserSessionLeaseUsable(
      currentLease,
      input.use,
      input.authority,
      runtime,
    );
    assertModeMatchesBinding(preparation.mode, binding);

    const reuseKey = reuseKeyFor(currentLease, binding);
    if (
      currentLease.leaseSha256 !== preparation.leaseSha256 ||
      binding.sessionId !== preparation.sessionId ||
      binding.origin !== preparation.origin ||
      reuseKey !== preparation.reuseKey
    ) {
      throw new Error("P8 session changed since reusable browser preparation");
    }
  } catch {
    await adapter.quarantineAndEvict({
      identity,
      reason: "AUTHORITY_OR_LEASE_CHANGED",
    });
    return dispositionReceipt(
      preparation,
      "QUARANTINE_EVICT",
      "AUTHORITY_OR_LEASE_CHANGED",
      null,
      runtime,
    );
  }

  const candidate = makeCandidate(preparation);
  return dispositionReceipt(
    preparation,
    "RETURN_TO_POOL",
    "SUCCESS_HEALTHY",
    candidate,
    runtime,
  );
}
