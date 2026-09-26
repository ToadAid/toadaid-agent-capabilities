export type * from "./connectorAdapterTypes.js";

import {
  assertCapabilityContractCompatible,
} from "./capabilityContract.js";
import {
  validateCapabilityInvocationContractBinding,
} from "./capabilityContractSchema.js";
import { validateCapabilityInvocationEnvelope } from "./capabilityInvocationRecord.js";
import {
  boundedId,
  capabilityId,
  sha,
  sha256,
  toolName,
} from "./invocationSchema.js";
import type {
  ConnectorAdapterInvocationRequest,
  ConnectorAdapterInvocationResult,
  ConnectorAdapterRegistration,
  ConnectorJsonValue,
  GovernedConnectorAdapter,
  GovernedConnectorInvocationInput,
} from "./connectorAdapterTypes.js";

const CONTRACT_ID_PATTERN = /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/;
const MAX_DEPTH = 16;
const MAX_NODES = 4096;
const MAX_ARRAY_ITEMS = 512;
const MAX_OBJECT_KEYS = 256;
const MAX_KEY_LENGTH = 128;
const MAX_STRING_LENGTH = 65_536;

function normalizeConnectorJson(
  value: unknown,
  depth = 0,
  counter: { count: number } = { count: 0 },
): ConnectorJsonValue {
  if (depth > MAX_DEPTH) throw new RangeError(`connector JSON exceeds depth ${MAX_DEPTH}`);
  counter.count += 1;
  if (counter.count > MAX_NODES) throw new RangeError(`connector JSON exceeds ${MAX_NODES} nodes`);

  if (value === null || typeof value === "boolean") return value;

  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("connector JSON numbers must be finite");
    return value;
  }

  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new RangeError(`connector JSON string exceeds ${MAX_STRING_LENGTH} characters`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) {
      throw new RangeError(`connector JSON array exceeds ${MAX_ARRAY_ITEMS} items`);
    }
    return Object.freeze(
      value.map((item) => normalizeConnectorJson(item, depth + 1, counter)),
    );
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("connector JSON objects must be plain objects");
    }
    const input = value as Record<string, unknown>;
    const keys = Object.keys(input).sort();
    if (keys.length > MAX_OBJECT_KEYS) {
      throw new RangeError(`connector JSON object exceeds ${MAX_OBJECT_KEYS} keys`);
    }
    const entries: Array<readonly [string, ConnectorJsonValue]> = [];
    for (const key of keys) {
      if (
        key.length < 1 ||
        key.length > MAX_KEY_LENGTH ||
        /[\u0000-\u001f]/.test(key)
      ) {
        throw new TypeError("connector JSON object key is invalid");
      }
      entries.push([key, normalizeConnectorJson(input[key], depth + 1, counter)]);
    }
    // Object.fromEntries creates own data properties, so JSON keys such as
    // "__proto__" remain inert data instead of invoking the legacy prototype setter.
    return Object.freeze(Object.fromEntries(entries));
  }

  throw new TypeError("connector payload must be bounded plain JSON");
}

function normalizeContractId(value: string): string {
  if (!CONTRACT_ID_PATTERN.test(value)) {
    throw new TypeError("connector contractId is invalid");
  }
  return value;
}

export function normalizeConnectorAdapterRegistration(
  input: ConnectorAdapterRegistration,
): ConnectorAdapterRegistration {
  if (input.schemaVersion !== "toadaid.connector-adapter-registration.v1") {
    throw new TypeError("unsupported connector adapter registration schemaVersion");
  }
  return Object.freeze({
    schemaVersion: "toadaid.connector-adapter-registration.v1",
    adapterId: boundedId(input.adapterId, "adapterId"),
    capabilityId: capabilityId(input.capabilityId),
    toolName: toolName(input.toolName),
    contractId: normalizeContractId(input.contractId),
    descriptorSha256: sha(input.descriptorSha256, "descriptorSha256")!,
    implementationFingerprintSha256: sha(
      input.implementationFingerprintSha256,
      "implementationFingerprintSha256",
    )!,
  });
}

export function connectorAdapterRegistrationSha256(
  input: ConnectorAdapterRegistration,
): string {
  return sha256(normalizeConnectorAdapterRegistration(input));
}

function assertGovernedBinding(
  input: GovernedConnectorInvocationInput,
  registration: ConnectorAdapterRegistration,
): void {
  const invocation = validateCapabilityInvocationEnvelope(input.invocation);
  if (invocation.record.status !== "STARTED") {
    throw new Error("connector invocation requires STARTED H1 invocation");
  }

  const binding = validateCapabilityInvocationContractBinding(input.contractBinding);
  const compatibility = assertCapabilityContractCompatible(
    input.contractRegistry,
    input.contractRequirement,
  );
  const ready = input.contractReady;

  if (ready.schemaVersion !== "toadaid.capability-invocation-contract-ready.v1") {
    throw new TypeError("unsupported connector contract-ready receipt schemaVersion");
  }

  if (
    binding.invocationId !== invocation.record.invocationId ||
    binding.runId !== invocation.record.runId ||
    binding.capabilityId !== invocation.record.capabilityId ||
    binding.intentSha256 !== invocation.record.request.intentSha256
  ) {
    throw new Error("connector binding does not match STARTED H1 invocation identity");
  }

  if (
    binding.requirementSha256 !== compatibility.requirementSha256 ||
    binding.descriptorSha256 !== compatibility.descriptorSha256 ||
    binding.contractId !== compatibility.contractId
  ) {
    throw new Error("connector C1 binding is stale or does not match current contract compatibility");
  }

  if (
    ready.invocationId !== invocation.record.invocationId ||
    ready.capabilityId !== invocation.record.capabilityId ||
    ready.bindingSha256 !== binding.bindingSha256 ||
    ready.compatibility.requirementSha256 !== compatibility.requirementSha256 ||
    ready.compatibility.descriptorSha256 !== compatibility.descriptorSha256 ||
    ready.compatibility.implementationFingerprintSha256 !==
      compatibility.implementationFingerprintSha256
  ) {
    throw new Error("connector contract-ready receipt is stale or does not match current C1 truth");
  }

  if (
    registration.capabilityId !== invocation.record.capabilityId ||
    registration.toolName !== invocation.record.toolName
  ) {
    throw new Error("connector registration does not match H1 capability/tool identity");
  }

  if (
    registration.contractId !== compatibility.contractId ||
    registration.descriptorSha256 !== compatibility.descriptorSha256
  ) {
    throw new Error("connector registration does not match current C1 descriptor");
  }

  if (
    registration.implementationFingerprintSha256 !==
    compatibility.implementationFingerprintSha256
  ) {
    throw new Error(
      "connector implementation fingerprint changed or does not match current C1 truth",
    );
  }
}

export async function invokeGovernedConnectorAdapter(
  adapter: GovernedConnectorAdapter,
  input: GovernedConnectorInvocationInput,
): Promise<ConnectorAdapterInvocationResult> {
  const registration = normalizeConnectorAdapterRegistration(adapter.registration);
  assertGovernedBinding(input, registration);

  const invocation = validateCapabilityInvocationEnvelope(input.invocation);
  const binding = validateCapabilityInvocationContractBinding(input.contractBinding);
  const expectedArgumentsSha256 = invocation.record.request.argumentsSha256;
  if (expectedArgumentsSha256 === null) {
    throw new Error("connector invocation requires H1 argumentsSha256 binding");
  }

  const normalizedArguments = normalizeConnectorJson(input.arguments);
  const argumentsSha256 = sha256(normalizedArguments);
  if (argumentsSha256 !== expectedArgumentsSha256) {
    throw new Error("connector arguments do not match H1 argumentsSha256");
  }

  const registrationSha256 = connectorAdapterRegistrationSha256(registration);
  const request: ConnectorAdapterInvocationRequest = Object.freeze({
    schemaVersion: "toadaid.connector-adapter-invocation.v1",
    invocationId: invocation.record.invocationId,
    runId: invocation.record.runId,
    capabilityId: invocation.record.capabilityId,
    toolName: invocation.record.toolName,
    intentSha256: invocation.record.request.intentSha256,
    argumentsSha256,
    descriptorSha256: registration.descriptorSha256,
    implementationFingerprintSha256: registration.implementationFingerprintSha256,
    registrationSha256,
    arguments: normalizedArguments,
  });

  const result = normalizeConnectorJson(await adapter.invoke(request));
  const receipt = Object.freeze({
    schemaVersion: "toadaid.connector-adapter-receipt.v1" as const,
    invocationId: request.invocationId,
    runId: request.runId,
    capabilityId: request.capabilityId,
    toolName: request.toolName,
    adapterId: registration.adapterId,
    bindingSha256: binding.bindingSha256,
    descriptorSha256: registration.descriptorSha256,
    implementationFingerprintSha256: registration.implementationFingerprintSha256,
    registrationSha256,
    requestSha256: sha256(request),
    resultSha256: sha256(result),
  });

  return Object.freeze({ result, receipt });
}
