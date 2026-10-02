import { createHash } from "node:crypto";

import type {
  CapabilityInvocationEvidenceReference,
  CapabilityInvocationRecord,
} from "./invocationTypes.js";

export const SHA256_PATTERN = /^[0-9a-f]{64}$/;
export const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_EVIDENCE_REFS = 64;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("invocation state contains non-serializable data");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function canonicalIso(value: string | undefined, label: string, now: () => Date = () => new Date()): string {
  const resolved = value ?? now().toISOString();
  const parsed = new Date(resolved);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== resolved) throw new TypeError(`${label} must be canonical ISO-8601`);
  return resolved;
}

export function boundedId(value: string, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

export function capabilityId(value: string): string {
  if (typeof value !== "string" || !CAPABILITY_ID_PATTERN.test(value)) throw new TypeError("capabilityId is invalid");
  return value;
}

export function toolName(value: string): string {
  if (typeof value !== "string" || !TOOL_PATTERN.test(value)) throw new TypeError("toolName is invalid");
  return value;
}

export function sha(value: string | null | undefined, label: string, allowNull = false): string | null {
  if (value == null) {
    if (allowNull) return null;
    throw new TypeError(`${label} is required`);
  }
  if (!SHA256_PATTERN.test(value)) throw new TypeError(`${label} must be lowercase SHA-256`);
  return value;
}

export function managerId(value: string): string {
  return boundedId(value, "managerId");
}

export function reasonCode(value: string): string {
  if (!REASON_PATTERN.test(value)) throw new TypeError("reasonCode is invalid");
  return value;
}

export function phaseName(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128 || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError("phase is invalid");
  }
  return value;
}

export function normalizeEvidenceRefs(refs: readonly CapabilityInvocationEvidenceReference[] | undefined): readonly CapabilityInvocationEvidenceReference[] {
  const values = refs ?? [];
  if (values.length > MAX_EVIDENCE_REFS) throw new RangeError(`evidenceRefs exceeds ${MAX_EVIDENCE_REFS}`);
  const seen = new Set<string>();
  return Object.freeze(values.map((ref, index) => {
    const id = boundedId(ref.id, `evidenceRefs[${index}].id`);
    if (seen.has(id)) throw new TypeError(`duplicate evidence ref: ${id}`);
    seen.add(id);
    const digest = ref.sha256 === undefined ? undefined : sha(ref.sha256, `evidenceRefs[${index}].sha256`) ?? undefined;
    return Object.freeze({ id, ...(digest ? { sha256: digest } : {}) });
  }).sort((a, b) => a.id.localeCompare(b.id)));
}

export function freezeInvocationRecord(record: CapabilityInvocationRecord): CapabilityInvocationRecord {
  return Object.freeze({
    ...record,
    request: Object.freeze({ ...record.request }),
    authorization: record.authorization ? Object.freeze({ ...record.authorization }) : null,
    start: record.start ? Object.freeze({ ...record.start }) : null,
    cancellation: record.cancellation ? Object.freeze({ ...record.cancellation }) : null,
    ...(record.reconciliation === undefined
      ? {}
      : {
          reconciliation: record.reconciliation
            ? Object.freeze({ ...record.reconciliation })
            : null,
        }),
    outcome: record.outcome ? Object.freeze({ ...record.outcome, evidenceRefs: Object.freeze([...record.outcome.evidenceRefs]) }) : null,
    continuity: Object.freeze({ ...record.continuity }),
  });
}
