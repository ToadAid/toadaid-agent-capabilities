import { createHash } from "node:crypto";
import type { IdempotencyGuarantee, IdempotencyMechanism, ReplayEvidenceReference, ReplayFenceBinding } from "./replayFenceTypes.js";
import type { CapabilityInvocationContractReadyReceipt } from "./capabilityContractTypes.js";

export const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAPABILITY_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const FEATURE_PATTERN = /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*$/;
const MECHANISM_FEATURE: Readonly<Record<IdempotencyMechanism, string>> = Object.freeze({
  PROVIDER_KEY: "idempotency.provider-key",
  COMPARE_AND_SET: "idempotency.compare-and-set",
  EXTERNAL_DEDUPLICATION: "idempotency.external-deduplication",
});

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const r = value as Record<string, unknown>;
    return `{${Object.keys(r).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(r[k])}`).join(",")}}`;
  }
  throw new TypeError("replay state contains a non-serializable value");
}

export function sha256(value: unknown): string { return createHash("sha256").update(canonicalJson(value)).digest("hex"); }
export function sha(value: string | null | undefined, label: string, nullable = false): string | null {
  if (value == null && nullable) return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be lowercase SHA-256`);
  return value;
}
export function boundedId(value: string, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}
export function capabilityId(value: string): string {
  if (typeof value !== "string" || !CAPABILITY_PATTERN.test(value)) throw new TypeError("capabilityId is invalid");
  return value;
}
export function canonicalIso(value: string | undefined, label: string, now = () => new Date()): string {
  const v = value ?? now().toISOString(); const d = new Date(v);
  if (typeof v !== "string" || Number.isNaN(d.getTime()) || d.toISOString() !== v) throw new TypeError(`${label} must be canonical ISO-8601`);
  return v;
}
export function reasonCode(value: string): string {
  if (typeof value !== "string" || !REASON_PATTERN.test(value)) throw new TypeError("reasonCode is invalid");
  return value;
}
export function normalizeEvidenceRefs(input?: readonly ReplayEvidenceReference[]): readonly ReplayEvidenceReference[] {
  const values = input ?? [];
  if (values.length > 32) throw new RangeError("evidenceRefs exceeds 32");
  const seen = new Set<string>();
  const out = values.map((ref, i) => {
    const id = boundedId(ref.id, `evidenceRefs[${i}].id`);
    if (seen.has(id)) throw new TypeError(`duplicate evidence ref: ${id}`);
    seen.add(id);
    const digest = ref.sha256 == null ? undefined : sha(ref.sha256, `evidenceRefs[${i}].sha256`)!;
    return Object.freeze({ id, ...(digest ? { sha256: digest } : {}) });
  }).sort((a, b) => a.id.localeCompare(b.id));
  return Object.freeze(out);
}
export function normalizeGuarantee(input: IdempotencyGuarantee | null | undefined): IdempotencyGuarantee | null {
  if (input == null) return null;
  if (!(input.mechanism in MECHANISM_FEATURE)) throw new TypeError("idempotency guarantee mechanism is invalid");
  if (input.feature !== MECHANISM_FEATURE[input.mechanism]) throw new TypeError("idempotency guarantee feature does not match mechanism");
  if (!FEATURE_PATTERN.test(input.feature)) throw new TypeError("idempotency guarantee feature is invalid");
  const core = Object.freeze({
    mechanism: input.mechanism,
    feature: input.feature,
    invocationId: boundedId(input.invocationId, "guarantee.invocationId"),
    capabilityId: capabilityId(input.capabilityId),
    contractBindingSha256: sha(input.contractBindingSha256, "guarantee.contractBindingSha256")!,
    contractDescriptorSha256: sha(input.contractDescriptorSha256, "guarantee.contractDescriptorSha256")!,
    implementationFingerprintSha256: sha(input.implementationFingerprintSha256, "guarantee.implementationFingerprintSha256")!,
  });
  const digest = sha(input.guaranteeSha256, "guarantee.guaranteeSha256")!;
  if (digest !== sha256(core)) throw new Error("idempotency guarantee integrity mismatch");
  return Object.freeze({ ...core, guaranteeSha256: digest });
}

export function createContractBoundIdempotencyGuarantee(
  ready: CapabilityInvocationContractReadyReceipt,
  mechanism: IdempotencyMechanism,
): IdempotencyGuarantee {
  if (ready.schemaVersion !== "toadaid.capability-invocation-contract-ready.v1") throw new TypeError("unsupported contract-ready receipt schemaVersion");
  const feature = MECHANISM_FEATURE[mechanism];
  if (!feature) throw new TypeError("idempotency mechanism is invalid");
  if (!ready.compatibility.features.includes(feature)) throw new Error(`capability contract does not advertise required idempotency feature: ${feature}`);
  const core = Object.freeze({
    mechanism,
    feature,
    invocationId: boundedId(ready.invocationId, "contractReady.invocationId"),
    capabilityId: capabilityId(ready.capabilityId),
    contractBindingSha256: sha(ready.bindingSha256, "contractReady.bindingSha256")!,
    contractDescriptorSha256: sha(ready.compatibility.descriptorSha256, "contractReady.descriptorSha256")!,
    implementationFingerprintSha256: sha(ready.provider.implementationFingerprintSha256, "contractReady.implementationFingerprintSha256")!,
  });
  return Object.freeze({ ...core, guaranteeSha256: sha256(core) });
}

export function normalizeBinding(input: ReplayFenceBinding): ReplayFenceBinding {
  return Object.freeze({
    runId: boundedId(input.runId, "runId"),
    invocationId: boundedId(input.invocationId, "invocationId"),
    capabilityId: capabilityId(input.capabilityId),
    intentSha256: sha(input.intentSha256, "intentSha256")!,
  });
}
export function deterministicIdempotencyKey(binding: ReplayFenceBinding): string {
  return sha256({ schemaVersion: "toadaid.idempotency-key.v1", ...normalizeBinding(binding) });
}
