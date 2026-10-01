import path from "node:path";
import { randomUUID } from "node:crypto";

import {
  assertCapabilityContractCompatible,
} from "./capabilityContract.js";
import {
  validateCapabilityInvocationContractBinding,
} from "./capabilityContractSchema.js";
import {
  validateCapabilityInvocationEnvelope,
} from "./capabilityInvocationRecord.js";
import {
  assertHostConnectorSessionLeaseUsable,
} from "./hostConnectorSessionLease.js";
import {
  boundedId,
  canonicalIso,
  capabilityId,
  sha,
  sha256,
  toolName,
} from "./invocationSchema.js";
import {
  openReplayReconciliation,
  validateReplayFenceEnvelope,
} from "./replayFence.js";
import {
  evaluateRunBudgetAvailability,
  recordRunBudgetUsage,
  validateRunBudgetLedgerEnvelope,
} from "./runBudgetLedger.js";
import type {
  GovernedHostServiceAdapter,
  GovernedHostServiceInput,
  GovernedHostServiceOutcome,
  HostEnvironmentBinding,
  HostPathScope,
  HostRegistryScope,
  HostServiceAdapterRegistration,
  HostServiceAdapterRequest,
  HostServiceAdapterResult,
  HostServiceArtifactReference,
  HostServiceCapabilityId,
  HostServiceJsonValue,
  HostServiceKind,
  HostServiceReceipt,
  HostServiceRequest,
  HostServiceRuntime,
  NormalizedHostServiceRequest,
} from "./hostServiceTypes.js";
import type { CapabilityInvocationEnvelope } from "./invocationTypes.js";
import type { ReplayFenceEnvelope } from "./replayFenceTypes.js";
import type { RunBudgetVector } from "./runBudgetTypes.js";

export type * from "./hostServiceTypes.js";

export const HOST_SERVICE_CAPABILITIES:
  readonly HostServiceCapabilityId[] = Object.freeze([
    "host:app-launch",
    "host:clipboard-read",
    "host:clipboard-write",
    "host:process-read",
    "host:process-stop",
    "host:file-read",
    "host:file-write",
    "host:notification",
    "host:registry-read",
    "host:registry-write",
    "host:command-exec",
  ]);

export const HOST_SERVICE_CONTRACT_IDS:
  Readonly<Record<HostServiceCapabilityId, string>> =
  Object.freeze({
    "host:app-launch": "toadaid.host.app-launch",
    "host:clipboard-read": "toadaid.host.clipboard-read",
    "host:clipboard-write": "toadaid.host.clipboard-write",
    "host:process-read": "toadaid.host.process-read",
    "host:process-stop": "toadaid.host.process-stop",
    "host:file-read": "toadaid.host.file-read",
    "host:file-write": "toadaid.host.file-write",
    "host:notification": "toadaid.host.notification",
    "host:registry-read": "toadaid.host.registry-read",
    "host:registry-write": "toadaid.host.registry-write",
    "host:command-exec": "toadaid.host.command-exec",
  });

export const HOST_SERVICE_TOOL_NAMES:
  Readonly<Record<HostServiceCapabilityId, string>> =
  Object.freeze({
    "host:app-launch": "host.app-launch",
    "host:clipboard-read": "host.clipboard-read",
    "host:clipboard-write": "host.clipboard-write",
    "host:process-read": "host.process-read",
    "host:process-stop": "host.process-stop",
    "host:file-read": "host.file-read",
    "host:file-write": "host.file-write",
    "host:notification": "host.notification",
    "host:registry-read": "host.registry-read",
    "host:registry-write": "host.registry-write",
    "host:command-exec": "host.command-exec",
  });

const MUTATIONS = new Set<HostServiceCapabilityId>([
  "host:app-launch",
  "host:clipboard-write",
  "host:process-stop",
  "host:file-write",
  "host:notification",
  "host:registry-write",
  "host:command-exec",
]);

const CONTRACT_ID_PATTERN =
  /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/;
const MAX_WALL_MS = 120_000;
const MAX_REF = 512;
const MAX_PATH = 4_096;
const MAX_ARGV = 64;
const MAX_ARG = 4_096;
const MAX_ENV = 32;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_ARTIFACTS = 32;

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function boundedPositive(
  value: number | undefined,
  fallback: number,
  max: number,
  label: string,
): number {
  const v = value ?? fallback;
  if (!Number.isSafeInteger(v) || v < 1 || v > max) {
    throw new RangeError(`${label} must be an integer in [1, ${max}]`);
  }
  return v;
}

function text(value: string, max: number, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > max ||
    value.includes("\u0000")
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function ref(value: string, label: string): string {
  return text(value, MAX_REF, label);
}

function normalizedCapability(value: string): HostServiceCapabilityId {
  const id = capabilityId(value);
  if (!HOST_SERVICE_CAPABILITIES.includes(id as HostServiceCapabilityId)) {
    throw new TypeError(`unsupported host service capability: ${id}`);
  }
  return id as HostServiceCapabilityId;
}

function capabilityForKind(kind: HostServiceKind): HostServiceCapabilityId {
  switch (kind) {
    case "APP_LAUNCH": return "host:app-launch";
    case "CLIPBOARD_READ": return "host:clipboard-read";
    case "CLIPBOARD_WRITE": return "host:clipboard-write";
    case "PROCESS_READ": return "host:process-read";
    case "PROCESS_STOP": return "host:process-stop";
    case "FILE_READ": return "host:file-read";
    case "FILE_WRITE": return "host:file-write";
    case "NOTIFICATION": return "host:notification";
    case "REGISTRY_READ": return "host:registry-read";
    case "REGISTRY_WRITE": return "host:registry-write";
    case "COMMAND_EXEC": return "host:command-exec";
    default: throw new TypeError("unsupported host service kind");
  }
}

function windowsAbsolute(value: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(value);
}

function windowsNetworkOrDevicePath(value: string): boolean {
  return value.startsWith("\\\\");
}

export function normalizeHostPathScope(
  scope: HostPathScope,
): HostServiceJsonValue {
  const raw = objectValue(scope, "path scope");
  const rootRaw = text(raw.root as string, MAX_PATH, "path scope root");
  const targetRaw = text(raw.path as string, MAX_PATH, "path scope path");

  if (
    windowsNetworkOrDevicePath(rootRaw) ||
    windowsNetworkOrDevicePath(targetRaw)
  ) {
    throw new Error(
      "P18 v1 refuses Windows UNC/device paths without separate network/device authority",
    );
  }

  const win = windowsAbsolute(rootRaw);
  const posix = path.posix.isAbsolute(rootRaw);
  if (!win && !posix) {
    throw new Error("path scope root must be absolute");
  }
  if (
    (win && !windowsAbsolute(targetRaw)) ||
    (posix && !path.posix.isAbsolute(targetRaw))
  ) {
    throw new Error("path scope root/path style mismatch");
  }

  const api = win ? path.win32 : path.posix;
  const root = api.normalize(rootRaw);
  const target = api.normalize(targetRaw);
  const relative = api.relative(root, target);
  const rootCmp = win ? root.toLowerCase() : root;
  const targetCmp = win ? target.toLowerCase() : target;
  const prefix = rootCmp.endsWith(api.sep) ? rootCmp : `${rootCmp}${api.sep}`;

  if (
    relative === "" ||
    relative === "." ||
    api.isAbsolute(relative) ||
    relative === ".." ||
    relative.startsWith(`..${api.sep}`) ||
    !targetCmp.startsWith(prefix)
  ) {
    throw new Error("path scope target escapes the authorized root");
  }

  return Object.freeze({
    style: win ? "WINDOWS" : "POSIX",
    root,
    path: target,
    relativePath: relative,
    symlinkPolicy: "REFUSE_ESCAPE",
  });
}

function normalizeExecutable(value: string): string {
  const v = text(value, MAX_PATH, "executable");
  if (windowsNetworkOrDevicePath(v)) {
    throw new Error(
      "P18 v1 refuses UNC/device executable paths without separate network/device authority",
    );
  }
  if (!path.posix.isAbsolute(v) && !windowsAbsolute(v)) {
    throw new Error("host executable must be an explicit absolute path");
  }
  return windowsAbsolute(v) ? path.win32.normalize(v) : path.posix.normalize(v);
}

function normalizeArgv(values: readonly string[] | undefined): readonly string[] {
  const input = values ?? [];
  if (!Array.isArray(input) || input.length > MAX_ARGV) {
    throw new RangeError(`argv exceeds ${MAX_ARGV} entries`);
  }
  return Object.freeze(
    input.map((value, index) => text(value, MAX_ARG, `argv[${index}]`)),
  );
}

function normalizeEnv(
  values: readonly HostEnvironmentBinding[] | undefined,
): HostServiceJsonValue {
  const input = values ?? [];
  if (!Array.isArray(input) || input.length > MAX_ENV) {
    throw new RangeError(`env exceeds ${MAX_ENV} entries`);
  }
  const seen = new Set<string>();
  const out = input.map((value, index) => {
    const raw = objectValue(value, `env[${index}]`);
    const name = raw.name;
    if (
      typeof name !== "string" ||
      !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)
    ) {
      throw new TypeError(`env[${index}].name is invalid`);
    }
    const normalizedName = name.toUpperCase();
    if (seen.has(normalizedName)) {
      throw new TypeError(`duplicate environment binding: ${normalizedName}`);
    }
    seen.add(normalizedName);
    return Object.freeze({
      name: normalizedName,
      valueRef: ref(raw.valueRef as string, `env[${index}].valueRef`),
      valueSha256: sha(raw.valueSha256 as string, `env[${index}].valueSha256`)!,
    });
  });
  out.sort((a, b) => a.name.localeCompare(b.name));
  return Object.freeze(out);
}

export function normalizeHostRegistryScope(
  scope: HostRegistryScope,
): HostServiceJsonValue {
  const raw = objectValue(scope, "registry scope");
  if (raw.hive !== "HKCU" && raw.hive !== "HKLM") {
    throw new TypeError("registry scope hive must be HKCU or HKLM");
  }
  const clean = (value: string, label: string) => {
    const parts = text(value, 2_048, label)
      .replace(/\//g, "\\")
      .split("\\")
      .filter(Boolean);
    if (
      parts.length < 1 ||
      parts.some((part) => part === "." || part === "..")
    ) {
      throw new Error(`${label} contains invalid traversal`);
    }
    return parts.join("\\");
  };
  const rootKeyPath = clean(raw.rootKeyPath as string, "registry rootKeyPath");
  const keyPath = clean(raw.keyPath as string, "registry keyPath");
  const rootLower = rootKeyPath.toLowerCase();
  const keyLower = keyPath.toLowerCase();
  if (
    keyLower !== rootLower &&
    !keyLower.startsWith(`${rootLower}\\`)
  ) {
    throw new Error("registry keyPath escapes authorized rootKeyPath");
  }
  return Object.freeze({
    hive: raw.hive,
    rootKeyPath,
    keyPath,
    relativeKeyPath:
      keyLower === rootLower ? "" : keyPath.slice(rootKeyPath.length + 1),
  });
}

function detailsFor(request: HostServiceRequest): HostServiceJsonValue {
  switch (request.kind) {
    case "APP_LAUNCH":
      if (request.cwd === undefined) {
        throw new Error("app launch requires explicit bounded cwd");
      }
      return Object.freeze({
        executable: normalizeExecutable(request.executable),
        argv: normalizeArgv(request.argv),
        cwd: normalizeHostPathScope(request.cwd),
        env: normalizeEnv(request.env),
        inheritEnv: false,
        shell: false,
        elevation: "NONE",
      });
    case "CLIPBOARD_READ":
      if (request.format !== "text/plain") {
        throw new Error("clipboard read v1 supports text/plain only");
      }
      return Object.freeze({
        format: "text/plain",
        maxBytes: boundedPositive(request.maxBytes, 65_536, 65_536, "maxBytes"),
      });
    case "CLIPBOARD_WRITE":
      if (
        request.format !== "text/plain" ||
        request.contentClass !== "ORDINARY_TEXT"
      ) {
        throw new Error("clipboard write v1 accepts ordinary text/plain only");
      }
      const clipboardContentRef = ref(request.contentRef, "contentRef");
      return Object.freeze({
        format: "text/plain",
        contentRef: clipboardContentRef,
        contentRefSha256: sha256(clipboardContentRef),
        contentSha256: sha(request.contentSha256, "contentSha256")!,
        byteLength: boundedPositive(request.byteLength, 1, 65_536, "byteLength"),
        contentClass: "ORDINARY_TEXT",
      });
    case "PROCESS_READ":
      return Object.freeze({
        pid:
          request.pid === undefined
            ? null
            : boundedPositive(request.pid, 1, 2_147_483_647, "pid"),
        name:
          request.name === undefined
            ? null
            : text(request.name, 512, "process name"),
        maxResults: boundedPositive(request.maxResults, 100, 100, "maxResults"),
      });
    case "PROCESS_STOP":
      return Object.freeze({
        pid: boundedPositive(request.pid, 1, 2_147_483_647, "pid"),
        processEvidenceSha256:
          sha(request.processEvidenceSha256, "processEvidenceSha256")!,
        processObservedAt: canonicalIso(
          request.processObservedAt,
          "processObservedAt",
        ),
        maxEvidenceAgeMs: boundedPositive(
          request.maxEvidenceAgeMs,
          5_000,
          30_000,
          "maxEvidenceAgeMs",
        ),
      });
    case "FILE_READ":
      return Object.freeze({
        scope: normalizeHostPathScope(request.scope),
        maxBytes:
          boundedPositive(request.maxBytes, 1024 * 1024, 16 * 1024 * 1024, "maxBytes"),
      });
    case "FILE_WRITE":
      if (
        request.mode !== "CREATE_NEW" &&
        request.mode !== "REPLACE_EXISTING"
      ) {
        throw new TypeError("file write mode is invalid");
      }
      const fileContentRef = ref(request.contentRef, "contentRef");
      return Object.freeze({
        scope: normalizeHostPathScope(request.scope),
        contentRef: fileContentRef,
        contentRefSha256: sha256(fileContentRef),
        contentSha256: sha(request.contentSha256, "contentSha256")!,
        byteLength:
          boundedPositive(request.byteLength, 1, 16 * 1024 * 1024, "byteLength"),
        mode: request.mode,
      });
    case "NOTIFICATION": {
      const title = text(request.title, 256, "notification title");
      const body = text(request.body, 2_048, "notification body");
      return Object.freeze({
        title,
        body,
        titleSha256: sha256(title),
        bodySha256: sha256(body),
        urgency: request.urgency ?? "NORMAL",
      });
    }
    case "REGISTRY_READ":
      return Object.freeze({
        scope: normalizeHostRegistryScope(request.scope),
        valueName:
          request.valueName === undefined
            ? null
            : text(request.valueName, 512, "registry valueName"),
      });
    case "REGISTRY_WRITE":
      if (
        request.valueType !== "STRING" &&
        request.valueType !== "DWORD" &&
        request.valueType !== "QWORD" &&
        request.valueType !== "BINARY"
      ) {
        throw new TypeError("registry valueType is invalid");
      }
      const valueRef = ref(request.valueRef, "registry valueRef");
      return Object.freeze({
        scope: normalizeHostRegistryScope(request.scope),
        valueName: text(request.valueName, 512, "registry valueName"),
        valueType: request.valueType,
        valueRef,
        valueRefSha256: sha256(valueRef),
        valueSha256: sha(request.valueSha256, "registry valueSha256")!,
        byteLength:
          boundedPositive(request.byteLength, 1, 16 * 1024 * 1024, "byteLength"),
      });
    case "COMMAND_EXEC":
      if (request.cwd === undefined) {
        throw new Error("command execution requires explicit bounded cwd");
      }
      if (
        (request.stdinRef === undefined) !==
        (request.stdinSha256 === undefined)
      ) {
        throw new Error("command stdinRef and stdinSha256 must be provided together");
      }
      {
        const stdinRef =
          request.stdinRef === undefined
            ? null
            : ref(request.stdinRef, "stdinRef");
        return Object.freeze({
          executable: normalizeExecutable(request.executable),
          argv: normalizeArgv(request.argv),
          cwd: normalizeHostPathScope(request.cwd),
          env: normalizeEnv(request.env),
          inheritEnv: false,
          stdinRef,
          stdinRefSha256:
            stdinRef === null ? null : sha256(stdinRef),
          stdinSha256:
            request.stdinSha256 === undefined
              ? null
              : sha(request.stdinSha256, "stdinSha256")!,
          maxOutputBytes:
            boundedPositive(
              request.maxOutputBytes,
              1024 * 1024,
              4 * 1024 * 1024,
              "maxOutputBytes",
            ),
          shell: false,
          elevation: "NONE",
        });
      }
  }
}

export function normalizeHostServiceRequest(
  request: HostServiceRequest,
): NormalizedHostServiceRequest {
  const capability = capabilityForKind(request.kind);
  return Object.freeze({
    kind: request.kind,
    capabilityId: capability,
    toolName: HOST_SERVICE_TOOL_NAMES[capability],
    mutation: MUTATIONS.has(capability),
    hostId: boundedId(request.hostId, "hostId"),
    sessionId: boundedId(request.sessionId, "sessionId"),
    ownerId: boundedId(request.ownerId, "ownerId"),
    details: detailsFor(request),
    maxWallClockMs:
      boundedPositive(request.maxWallClockMs, 10_000, MAX_WALL_MS, "maxWallClockMs"),
  });
}

export function hostServiceParametersSha256(request: HostServiceRequest): string {
  return sha256(normalizeHostServiceRequest(request));
}

function mandatoryFeatures(
  request: NormalizedHostServiceRequest,
): readonly string[] {
  const features = [
    "least-privilege-host-service",
    "bounded-result-evidence",
  ];
  if (request.mutation) features.push("x1-reconciled-mutation");
  if (request.kind === "FILE_READ" || request.kind === "FILE_WRITE") {
    features.push("realpath-scope-enforced");
  }
  if (request.kind === "APP_LAUNCH" || request.kind === "COMMAND_EXEC") {
    features.push(
      "structured-exec-no-shell",
      "structured-exec-explicit-context",
    );
  }
  if (request.kind === "PROCESS_STOP") {
    features.push("process-identity-evidence-enforced");
  }
  return Object.freeze(features);
}

export function normalizeHostServiceAdapterRegistration(
  value: HostServiceAdapterRegistration,
): HostServiceAdapterRegistration {
  if (
    value.schemaVersion !==
    "toadaid.host-service-adapter-registration.v1"
  ) {
    throw new TypeError("unsupported host service adapter registration schemaVersion");
  }
  const capability = normalizedCapability(value.capabilityId);
  const normalizedTool = toolName(value.toolName);
  if (normalizedTool !== HOST_SERVICE_TOOL_NAMES[capability]) {
    throw new Error("host service adapter toolName does not match capability");
  }
  if (
    typeof value.contractId !== "string" ||
    !CONTRACT_ID_PATTERN.test(value.contractId) ||
    value.contractId !== HOST_SERVICE_CONTRACT_IDS[capability]
  ) {
    throw new TypeError("host service adapter contractId is invalid or mismatched");
  }
  return Object.freeze({
    schemaVersion: "toadaid.host-service-adapter-registration.v1",
    adapterId: boundedId(value.adapterId, "adapterId"),
    capabilityId: capability,
    toolName: normalizedTool,
    contractId: value.contractId,
    descriptorSha256: sha(value.descriptorSha256, "descriptorSha256")!,
    implementationFingerprintSha256:
      sha(value.implementationFingerprintSha256, "implementationFingerprintSha256")!,
  });
}

export function hostServiceAdapterRegistrationSha256(
  value: HostServiceAdapterRegistration,
): string {
  return sha256(normalizeHostServiceAdapterRegistration(value));
}

function assertC1H1(
  input: GovernedHostServiceInput,
  normalized: NormalizedHostServiceRequest,
  registration: HostServiceAdapterRegistration,
) {
  const invocation = validateCapabilityInvocationEnvelope(input.invocation);
  if (
    invocation.record.status !== "STARTED" ||
    invocation.record.capabilityId !== normalized.capabilityId ||
    invocation.record.toolName !== normalized.toolName ||
    invocation.record.request.argumentsSha256 !== sha256(normalized)
  ) {
    throw new Error("host service H1 identity/arguments mismatch");
  }

  const binding =
    validateCapabilityInvocationContractBinding(input.contractBinding);
  const compatibility =
    assertCapabilityContractCompatible(
      input.contractRegistry,
      input.contractRequirement,
    );

  if (
    input.contractRequirement.capabilityId !== normalized.capabilityId ||
    compatibility.capabilityId !== normalized.capabilityId
  ) {
    throw new Error("host service C1 capability mismatch");
  }

  const declared = new Set(input.contractRequirement.requiredFeatures);
  for (const feature of mandatoryFeatures(normalized)) {
    if (!declared.has(feature)) {
      throw new Error(
        `host service C1 requirement missing mandatory feature: ${feature}`,
      );
    }
  }

  if (
    binding.invocationId !== invocation.record.invocationId ||
    binding.runId !== invocation.record.runId ||
    binding.capabilityId !== invocation.record.capabilityId ||
    binding.intentSha256 !== invocation.record.request.intentSha256 ||
    binding.requirementSha256 !== compatibility.requirementSha256 ||
    binding.descriptorSha256 !== compatibility.descriptorSha256 ||
    binding.contractId !== compatibility.contractId
  ) {
    throw new Error("host service C1 binding is stale or mismatched");
  }

  const ready = input.contractReady;
  if (
    ready.schemaVersion !== "toadaid.capability-invocation-contract-ready.v1" ||
    ready.invocationId !== invocation.record.invocationId ||
    ready.capabilityId !== normalized.capabilityId ||
    ready.bindingSha256 !== binding.bindingSha256 ||
    ready.compatibility.requirementSha256 !== compatibility.requirementSha256 ||
    ready.compatibility.descriptorSha256 !== compatibility.descriptorSha256 ||
    ready.provider.providerDescriptorSha256 !== binding.providerDescriptorSha256 ||
    ready.provider.adapterRegistrationSha256 !== binding.adapterRegistrationSha256 ||
    ready.provider.implementationFingerprintSha256 !== binding.implementationFingerprintSha256
  ) {
    throw new Error("host service contract-ready receipt is stale or mismatched");
  }

  if (
    registration.capabilityId !== normalized.capabilityId ||
    registration.toolName !== normalized.toolName ||
    registration.contractId !== compatibility.contractId ||
    registration.descriptorSha256 !== compatibility.descriptorSha256 ||
    hostServiceAdapterRegistrationSha256(registration) !== binding.adapterRegistrationSha256 ||
    registration.implementationFingerprintSha256 !==
      binding.implementationFingerprintSha256
  ) {
    throw new Error(
      "host service adapter registration does not match current C1 truth",
    );
  }

  return { invocation, binding, compatibility };
}

function assertReplayFence(
  input: GovernedHostServiceInput,
  invocation: CapabilityInvocationEnvelope,
  mutation: boolean,
): ReplayFenceEnvelope | null {
  if (input.replayFence === undefined) {
    if (mutation) {
      throw new Error(
        "mutating host service requires X1 replay fence before dispatch",
      );
    }
    return null;
  }

  const fence = validateReplayFenceEnvelope(input.replayFence);
  const current = validateCapabilityInvocationEnvelope(invocation);
  if (
    fence.record.binding.runId !== current.record.runId ||
    fence.record.binding.invocationId !== current.record.invocationId ||
    fence.record.binding.capabilityId !== current.record.capabilityId ||
    fence.record.binding.intentSha256 !== current.record.request.intentSha256
  ) {
    throw new Error("host service X1 replay fence does not match H1 invocation");
  }

  if (!mutation) {
    if (fence.record.replayClass !== "SAFE_READ") {
      throw new Error(
        "read-only host service accepts only SAFE_READ X1 classification",
      );
    }
    return fence;
  }

  if (fence.record.replayClass !== "NON_REPLAYABLE") {
    throw new Error(
      "P18 v1 mutations require NON_REPLAYABLE X1 classification",
    );
  }
  return fence;
}

function assertProcessEvidenceFresh(
  request: NormalizedHostServiceRequest,
  now: Date,
): void {
  if (request.kind !== "PROCESS_STOP") return;
  const details = objectValue(
    request.details,
    "process stop details",
  );
  const observedAt = details.processObservedAt;
  const maxEvidenceAgeMs = details.maxEvidenceAgeMs;
  if (
    typeof observedAt !== "string" ||
    typeof maxEvidenceAgeMs !== "number"
  ) {
    throw new TypeError(
      "process stop evidence freshness fields are missing",
    );
  }
  const ageMs = now.getTime() - Date.parse(observedAt);
  if (
    !Number.isFinite(ageMs) ||
    ageMs < 0 ||
    ageMs > maxEvidenceAgeMs
  ) {
    throw new Error(
      "process stop evidence is stale or from the future",
    );
  }
}

function zeroCost(): RunBudgetVector {
  return {
    modelRequests: 0,
    inputTokens: 0,
    outputTokens: 0,
    toolCalls: 0,
    networkRequests: 0,
    retries: 0,
    wallClockMs: 0,
    childTasks: 0,
  };
}

function normalizeJson(value: unknown, depth = 0): HostServiceJsonValue {
  if (depth > 16) throw new RangeError("host service payload nesting too deep");
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (value.length > 4_096) {
      throw new RangeError("host service payload array is too large");
    }
    return Object.freeze(value.map((v) => normalizeJson(v, depth + 1)));
  }
  if (typeof value === "object" && value !== null) {
    const source = value as Record<string, unknown>;
    const keys = Object.keys(source).sort();
    if (keys.length > 256) throw new RangeError("host service payload has too many keys");
    const out: Record<string, HostServiceJsonValue> = {};
    for (const key of keys) {
      if (
        !key ||
        key.length > 256 ||
        key.includes("\u0000") ||
        key === "__proto__" ||
        key === "constructor" ||
        key === "prototype"
      ) {
        throw new TypeError("host service payload key is invalid");
      }
      out[key] = normalizeJson(source[key], depth + 1);
    }
    return Object.freeze(out);
  }
  throw new TypeError("host service payload must be bounded plain JSON");
}

function normalizeArtifacts(
  value: readonly HostServiceArtifactReference[] | undefined,
): readonly HostServiceArtifactReference[] {
  const input = value ?? [];
  if (!Array.isArray(input) || input.length > MAX_ARTIFACTS) {
    throw new RangeError(`host service artifacts exceed ${MAX_ARTIFACTS}`);
  }
  const seen = new Set<string>();
  const out = input.map((item, index) => {
    const raw = objectValue(item, `artifacts[${index}]`);
    const id = boundedId(raw.id as string, `artifacts[${index}].id`);
    if (seen.has(id)) throw new TypeError(`duplicate host service artifact: ${id}`);
    seen.add(id);
    return Object.freeze({
      id,
      kind: text(raw.kind as string, 128, `artifacts[${index}].kind`),
      sha256: sha(raw.sha256 as string, `artifacts[${index}].sha256`)!,
    });
  });
  out.sort((a, b) => a.id.localeCompare(b.id));
  return Object.freeze(out);
}

function normalizeResult(
  value: HostServiceAdapterResult,
  request: HostServiceAdapterRequest,
): HostServiceAdapterResult {
  const raw = objectValue(value, "host service adapter result");
  if (raw.schemaVersion !== "toadaid.host-service-adapter-result.v1") {
    throw new TypeError("unsupported host service adapter result schemaVersion");
  }
  if (
    boundedId(raw.operationId as string, "operationId") !== request.operationId ||
    boundedId(raw.hostId as string, "hostId") !== request.hostId ||
    boundedId(raw.sessionId as string, "sessionId") !== request.sessionId ||
    normalizedCapability(raw.capabilityId as string) !== request.capabilityId
  ) {
    throw new Error("host service adapter result identity mismatch");
  }
  if (raw.payload !== undefined && raw.payloadRef !== undefined) {
    throw new Error("host service adapter result must use payload or payloadRef, not both");
  }

  const payload =
    raw.payload === undefined ? undefined : normalizeJson(raw.payload);
  if (
    payload !== undefined &&
    Buffer.byteLength(JSON.stringify(payload), "utf8") > MAX_JSON_BYTES
  ) {
    throw new RangeError("host service JSON payload exceeds result bound");
  }
  const payloadRef =
    raw.payloadRef === undefined
      ? undefined
      : ref(raw.payloadRef as string, "payloadRef");
  const artifacts = normalizeArtifacts(
    raw.artifacts as readonly HostServiceArtifactReference[] | undefined,
  );
  const adapterEvidence = sha(raw.evidenceSha256 as string, "evidenceSha256")!;
  const evidenceSha256 = sha256({
    adapterEvidence,
    operationId: request.operationId,
    parametersSha256: request.parametersSha256,
    actionParametersSha256: request.actionParametersSha256,
    hostId: request.hostId,
    sessionId: request.sessionId,
    capabilityId: request.capabilityId,
    payloadSha256: payload === undefined ? null : sha256(payload),
    payloadRefSha256: payloadRef === undefined ? null : sha256(payloadRef),
    artifacts,
  });

  return Object.freeze({
    schemaVersion: "toadaid.host-service-adapter-result.v1",
    operationId: request.operationId,
    hostId: request.hostId,
    sessionId: request.sessionId,
    capabilityId: request.capabilityId,
    evidenceSha256,
    ...(payload === undefined ? {} : { payload }),
    ...(payloadRef === undefined ? {} : { payloadRef }),
    ...(artifacts.length === 0 ? {} : { artifacts }),
  });
}

function receiptSha256(
  receipt: Omit<HostServiceReceipt, "receiptSha256">,
): string {
  return sha256(receipt);
}

function errorClass(error: unknown): string {
  return error instanceof Error && error.name
    ? error.name.slice(0, 128)
    : "HostServiceError";
}

function errorFingerprint(error: unknown): string {
  return sha256({
    errorClass: errorClass(error),
    message:
      error instanceof Error
        ? error.message.slice(0, 1_024)
        : String(error).slice(0, 1_024),
  });
}

export async function invokeGovernedHostService(
  adapter: GovernedHostServiceAdapter,
  input: GovernedHostServiceInput,
  runtime: HostServiceRuntime = {},
): Promise<GovernedHostServiceOutcome> {
  const normalized = normalizeHostServiceRequest(input.request);
  const parametersSha256 = sha256(normalized);
  const actionParametersSha256 = sha256(normalized.details);
  const registration = normalizeHostServiceAdapterRegistration(adapter.registration);

  const leaseBinding = assertHostConnectorSessionLeaseUsable(
    input.lease,
    {
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      capabilityId: normalized.capabilityId,
    },
    {
      session: input.sessionAuthority,
      action: input.actionAuthority,
    },
    input.leaseRuntime,
  );

  const { invocation, binding, compatibility } =
    assertC1H1(input, normalized, registration);
  const replayFence = assertReplayFence(
    input,
    invocation,
    normalized.mutation,
  );

  const now = (runtime.now ?? (() => new Date()))();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new TypeError("host service runtime now is invalid");
  }
  assertProcessEvidenceFresh(normalized, now);

  const budgetBefore = validateRunBudgetLedgerEnvelope(input.budget);
  if (budgetBefore.record.runId !== invocation.record.runId) {
    throw new Error("host service Q1 budget runId mismatch");
  }
  const cost = Object.freeze({
    ...zeroCost(),
    toolCalls: 1,
    wallClockMs: normalized.maxWallClockMs,
  });
  const availability = evaluateRunBudgetAvailability(budgetBefore, cost);
  if (!availability.allowed) {
    throw new RangeError(
      `host service run budget exceeded: ${availability.exceededMetrics.join(",")}`,
    );
  }

  const operationId = boundedId(
    (runtime.randomId ?? randomUUID)(),
    "operationId",
  );
  const invokedAt = canonicalIso(
    now.toISOString(),
    "invokedAt",
  );
  const budgetAfter = recordRunBudgetUsage(
    budgetBefore,
    {
      receiptId: boundedId(
        `host-service-${sha256({
          invocationId: invocation.record.invocationId,
          operationId,
        }).slice(0, 32)}`,
        "receiptId",
      ),
      kind: "TOOL",
      occurredAt: invokedAt,
      invocationId: invocation.record.invocationId,
      sourceSha256: parametersSha256,
      delta: cost,
    },
    {
      ...(runtime.now ? { now: runtime.now } : {}),
      ...(runtime.randomId ? { randomId: runtime.randomId } : {}),
    },
  );

  const adapterRequest: HostServiceAdapterRequest = Object.freeze({
    schemaVersion: "toadaid.host-service-adapter-request.v1",
    invocationId: invocation.record.invocationId,
    runId: invocation.record.runId,
    operationId,
    hostId: normalized.hostId,
    sessionId: normalized.sessionId,
    ownerId: normalized.ownerId,
    capabilityId: normalized.capabilityId,
    toolName: normalized.toolName,
    parametersSha256,
    actionParametersSha256,
    maxWallClockMs: normalized.maxWallClockMs,
    parameters: normalized,
  });

  const adapterRegistrationSha256 =
    hostServiceAdapterRegistrationSha256(registration);

  try {
    const result = normalizeResult(
      await adapter.invoke(adapterRequest),
      adapterRequest,
    );
    const core = Object.freeze({
      schemaVersion: "toadaid.host-service-receipt.v1" as const,
      status: "OK" as const,
      capabilityId: normalized.capabilityId,
      invocationId: invocation.record.invocationId,
      intentSha256: invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256,
      replayFenceSha256: replayFence?.recordSha256 ?? null,
      operationId,
      parametersSha256,
      actionParametersSha256,
      invokedAt,
      resultEvidenceSha256: result.evidenceSha256,
      payloadSha256:
        result.payload === undefined ? null : sha256(result.payload),
      payloadRefSha256:
        result.payloadRef === undefined ? null : sha256(result.payloadRef),
      artifactSetSha256:
        result.artifacts === undefined ? null : sha256(result.artifacts),
      reconciliationSha256: null,
      budget: Object.freeze({
        ledgerSha256Before: budgetBefore.recordSha256,
        ledgerSha256After: budgetAfter.recordSha256,
        reservedCost: cost,
      }),
      errorClass: null,
      errorFingerprint: null,
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256: receiptSha256(core),
    });
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result,
      reconciliation: null,
    });
  } catch (error) {
    if (normalized.mutation) {
      if (replayFence === null) {
        throw new Error("mutating host service lost X1 replay fence");
      }
      const reconciliation = openReplayReconciliation(
        replayFence,
        invocation,
        {
          reasonCode: "HOST_SERVICE_OUTCOME_UNCERTAIN",
          evidenceRefs: [
            {
              id: "host-service-action",
              sha256: actionParametersSha256,
            },
          ],
          openedAt: invokedAt,
        },
        {
          ...(runtime.now ? { now: runtime.now } : {}),
          ...(runtime.randomId ? { randomId: runtime.randomId } : {}),
        },
      );
      const core = Object.freeze({
        schemaVersion: "toadaid.host-service-receipt.v1" as const,
        status: "RECONCILIATION_REQUIRED" as const,
        capabilityId: normalized.capabilityId,
        invocationId: invocation.record.invocationId,
        intentSha256: invocation.record.request.intentSha256,
        runId: invocation.record.runId,
        hostId: normalized.hostId,
        sessionId: normalized.sessionId,
        ownerId: normalized.ownerId,
        leaseSha256: leaseBinding.leaseSha256,
        contractBindingSha256: binding.bindingSha256,
        descriptorSha256: compatibility.descriptorSha256,
        adapterRegistrationSha256,
        replayFenceSha256: replayFence.recordSha256,
        operationId,
        parametersSha256,
        actionParametersSha256,
        invokedAt,
        resultEvidenceSha256: null,
        payloadSha256: null,
        payloadRefSha256: null,
        artifactSetSha256: null,
        reconciliationSha256: reconciliation.recordSha256,
        budget: Object.freeze({
          ledgerSha256Before: budgetBefore.recordSha256,
          ledgerSha256After: budgetAfter.recordSha256,
          reservedCost: cost,
        }),
        errorClass: errorClass(error),
        errorFingerprint: errorFingerprint(error),
      });
      const receipt = Object.freeze({
        ...core,
        receiptSha256: receiptSha256(core),
      });
      return Object.freeze({
        receipt,
        budget: budgetAfter,
        result: null,
        reconciliation,
      });
    }

    const core = Object.freeze({
      schemaVersion: "toadaid.host-service-receipt.v1" as const,
      status: "DEGRADED" as const,
      capabilityId: normalized.capabilityId,
      invocationId: invocation.record.invocationId,
      intentSha256: invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256,
      replayFenceSha256: replayFence?.recordSha256 ?? null,
      operationId,
      parametersSha256,
      actionParametersSha256,
      invokedAt,
      resultEvidenceSha256: null,
      payloadSha256: null,
      payloadRefSha256: null,
      artifactSetSha256: null,
      reconciliationSha256: null,
      budget: Object.freeze({
        ledgerSha256Before: budgetBefore.recordSha256,
        ledgerSha256After: budgetAfter.recordSha256,
        reservedCost: cost,
      }),
      errorClass: errorClass(error),
      errorFingerprint: errorFingerprint(error),
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256: receiptSha256(core),
    });
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result: null,
      reconciliation: null,
    });
  }
}
