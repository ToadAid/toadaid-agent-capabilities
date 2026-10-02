import path from "node:path";
import { createHash, randomUUID } from "node:crypto";

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
  assertCurrentCapabilityInvocationHead,
  beginCapabilityInvocationReconciliation,
  publishCapabilityInvocationReconciliationHead,
} from "./invocationReconciliation.js";
import {
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
  HostArgvProfile,
  HostCommandExecutionEvidence,
  HostCommandProcessPolicy,
  HostEnvironmentBinding,
  HostExecutableBinding,
  HostExecutableCapabilityId,
  HostExecutionBinding,
  HostPathScope,
  HostProcessReference,
  HostRegistryScope,
  HostResolvedContent,
  HostResolvedContentPurpose,
  HostServiceContentRuntime,
  HostServiceEvidenceRuntime,
  HostServiceExecutionRuntime,
  HostServiceProviderIdentity,
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

export const LEGACY_HOST_CAPABILITY_ALIASES = Object.freeze({
  "host:file-read": "host:filesystem-read",
  "host:file-write": "host:filesystem-write",
  "host:command-exec": "host:command-execute",
} as const);

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function boundedNonNegative(
  value: number,
  max: number,
  label: string,
): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new RangeError(
      `${label} must be an integer in [0, ${max}]`,
    );
  }
  return value;
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
    const valueRef = ref(
      raw.valueRef as string,
      `env[${index}].valueRef`,
    );
    return Object.freeze({
      name: normalizedName,
      valueRef,
      valueRefSha256: sha256(valueRef),
      valueSha256: sha(
        raw.valueSha256 as string,
        `env[${index}].valueSha256`,
      )!,
      byteLength: boundedPositive(
        raw.byteLength as number,
        1,
        65_536,
        `env[${index}].byteLength`,
      ),
    });
  });
  out.sort((a, b) => a.name.localeCompare(b.name));
  return Object.freeze(out);
}

function executableCapability(
  value: string,
): HostExecutableCapabilityId {
  const capability = normalizedCapability(value);
  if (
    capability !== "host:app-launch" &&
    capability !== "host:command-exec"
  ) {
    throw new TypeError(
      "executable binding capability must be host:app-launch or host:command-exec",
    );
  }
  return capability;
}

export function createHostExecutableBinding(
  input: Readonly<{
    capabilityId: HostExecutableCapabilityId;
    executable: string;
    identityKind:
      | "EXACT_SHA256"
      | "TRUSTED_ALLOWLIST";
    executableSha256?: string;
    allowlistIdentity?: string;
    argvProfileId: string;
  }>,
): HostExecutableBinding {
  const capabilityId = executableCapability(input.capabilityId);
  const executable = normalizeExecutable(input.executable);
  const argvProfileId = boundedId(input.argvProfileId, "argvProfileId");
  let executableSha256: string | null = null;
  let allowlistIdentity: string | null = null;
  if (input.identityKind === "EXACT_SHA256") {
    executableSha256 = sha(input.executableSha256, "executableSha256")!;
    if (input.allowlistIdentity !== undefined) {
      throw new Error("exact executable binding cannot also carry allowlist identity");
    }
  } else if (input.identityKind === "TRUSTED_ALLOWLIST") {
    allowlistIdentity = boundedId(
      input.allowlistIdentity as string,
      "allowlistIdentity",
    );
    if (input.executableSha256 !== undefined) {
      throw new Error("allowlisted executable binding cannot also carry exact hash");
    }
  } else {
    throw new TypeError("unsupported executable identity kind");
  }
  const core = Object.freeze({
    schemaVersion: "toadaid.host-executable-binding.v1" as const,
    capabilityId,
    executable,
    identityKind: input.identityKind,
    executableSha256,
    allowlistIdentity,
    argvProfileId,
  });
  return Object.freeze({ ...core, bindingSha256: sha256(core) });
}

export function normalizeHostExecutableBinding(
  value: HostExecutableBinding,
): HostExecutableBinding {
  const raw = objectValue(value, "host executable binding");
  if (raw.schemaVersion !== "toadaid.host-executable-binding.v1") {
    throw new TypeError("unsupported host executable binding schemaVersion");
  }
  const capabilityId = executableCapability(raw.capabilityId as string);
  const executable = normalizeExecutable(raw.executable as string);
  const identityKind = raw.identityKind;
  let executableSha256: string | null = null;
  let allowlistIdentity: string | null = null;
  if (identityKind === "EXACT_SHA256") {
    executableSha256 = sha(raw.executableSha256 as string, "executableSha256")!;
    if (raw.allowlistIdentity !== null) {
      throw new Error("exact executable binding allowlistIdentity must be null");
    }
  } else if (identityKind === "TRUSTED_ALLOWLIST") {
    allowlistIdentity = boundedId(raw.allowlistIdentity as string, "allowlistIdentity");
    if (raw.executableSha256 !== null) {
      throw new Error("allowlisted executable binding executableSha256 must be null");
    }
  } else {
    throw new TypeError("unsupported executable identity kind");
  }
  const core = Object.freeze({
    schemaVersion: "toadaid.host-executable-binding.v1" as const,
    capabilityId,
    executable,
    identityKind,
    executableSha256,
    allowlistIdentity,
    argvProfileId: boundedId(raw.argvProfileId as string, "argvProfileId"),
  });
  const bindingSha256 = sha(raw.bindingSha256 as string, "bindingSha256")!;
  if (bindingSha256 !== sha256(core)) {
    throw new Error("host executable binding integrity mismatch");
  }
  return Object.freeze({ ...core, bindingSha256 });
}

export function createHostArgvProfile(
  input: Readonly<{
    profileId: string;
    capabilityId: HostExecutableCapabilityId;
    executableBindingSha256: string;
    minArgs: number;
    maxArgs: number;
    requiredPrefix?: readonly string[];
    forbiddenExactArgs?: readonly string[];
  }>,
): HostArgvProfile {
  const capabilityId = executableCapability(input.capabilityId);
  const minArgs = boundedNonNegative(input.minArgs, MAX_ARGV, "argv profile minArgs");
  const maxArgs = boundedNonNegative(input.maxArgs, MAX_ARGV, "argv profile maxArgs");
  if (minArgs > maxArgs) {
    throw new RangeError("argv profile minArgs cannot exceed maxArgs");
  }
  const requiredPrefix = normalizeArgv(input.requiredPrefix);
  if (requiredPrefix.length > maxArgs) {
    throw new RangeError("argv profile requiredPrefix exceeds maxArgs");
  }
  const forbiddenExactArgs = Array.from(
    new Set(normalizeArgv(input.forbiddenExactArgs)),
  ).sort();
  const core = Object.freeze({
    schemaVersion: "toadaid.host-argv-profile.v1" as const,
    profileId: boundedId(input.profileId, "argv profileId"),
    capabilityId,
    executableBindingSha256: sha(
      input.executableBindingSha256,
      "argv executableBindingSha256",
    )!,
    minArgs,
    maxArgs,
    requiredPrefix,
    forbiddenExactArgs: Object.freeze(forbiddenExactArgs),
  });
  return Object.freeze({ ...core, profileSha256: sha256(core) });
}

export function normalizeHostArgvProfile(
  value: HostArgvProfile,
): HostArgvProfile {
  const raw = objectValue(value, "host argv profile");
  if (raw.schemaVersion !== "toadaid.host-argv-profile.v1") {
    throw new TypeError("unsupported host argv profile schemaVersion");
  }
  const minArgs = boundedNonNegative(raw.minArgs as number, MAX_ARGV, "argv profile minArgs");
  const maxArgs = boundedNonNegative(raw.maxArgs as number, MAX_ARGV, "argv profile maxArgs");
  if (minArgs > maxArgs) {
    throw new RangeError("argv profile minArgs cannot exceed maxArgs");
  }
  const requiredPrefix = normalizeArgv(raw.requiredPrefix as readonly string[]);
  const forbiddenExactArgs = Array.from(
    new Set(normalizeArgv(raw.forbiddenExactArgs as readonly string[])),
  ).sort();
  if (requiredPrefix.length > maxArgs) {
    throw new RangeError("argv profile requiredPrefix exceeds maxArgs");
  }
  const core = Object.freeze({
    schemaVersion: "toadaid.host-argv-profile.v1" as const,
    profileId: boundedId(raw.profileId as string, "argv profileId"),
    capabilityId: executableCapability(raw.capabilityId as string),
    executableBindingSha256: sha(
      raw.executableBindingSha256 as string,
      "argv executableBindingSha256",
    )!,
    minArgs,
    maxArgs,
    requiredPrefix,
    forbiddenExactArgs: Object.freeze(forbiddenExactArgs),
  });
  const profileSha256 = sha(raw.profileSha256 as string, "profileSha256")!;
  if (profileSha256 !== sha256(core)) {
    throw new Error("host argv profile integrity mismatch");
  }
  return Object.freeze({ ...core, profileSha256 });
}

function normalizeCommandProcessPolicy(
  value: HostCommandProcessPolicy,
): HostServiceJsonValue {
  const raw = objectValue(value, "command process policy");
  if (
    raw.childProcessPolicy !== "FORBID" &&
    raw.childProcessPolicy !== "ALLOW_BOUNDED"
  ) {
    throw new TypeError("command childProcessPolicy is invalid");
  }
  const maxChildProcesses = boundedNonNegative(
    raw.maxChildProcesses as number,
    32,
    "maxChildProcesses",
  );
  if (raw.childProcessPolicy === "FORBID" && maxChildProcesses !== 0) {
    throw new Error("FORBID child process policy requires maxChildProcesses=0");
  }
  if (raw.childProcessPolicy === "ALLOW_BOUNDED" && maxChildProcesses < 1) {
    throw new Error("ALLOW_BOUNDED child process policy requires positive maxChildProcesses");
  }
  if (
    raw.timeoutTermination !== "TERMINATE_PROCESS_TREE" ||
    raw.timeoutQuiescence !== "REQUIRE_CONFIRMED"
  ) {
    throw new Error(
      "command timeout policy must terminate process tree and require confirmed quiescence",
    );
  }
  return Object.freeze({
    childProcessPolicy: raw.childProcessPolicy,
    maxChildProcesses,
    timeoutTermination: "TERMINATE_PROCESS_TREE",
    timeoutQuiescence: "REQUIRE_CONFIRMED",
  });
}

function bytesSha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function normalizeHostRegistryScope(
  scope: HostRegistryScope,
): HostServiceJsonValue {
  const raw = objectValue(scope, "registry scope");
  if (raw.hive !== "HKCU" && raw.hive !== "HKLM") {
    throw new TypeError("registry scope hive must be HKCU or HKLM");
  }
  if (
    raw.view !== "REGISTRY_32" &&
    raw.view !== "REGISTRY_64"
  ) {
    throw new TypeError(
      "registry scope requires explicit REGISTRY_32 or REGISTRY_64 view",
    );
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
    view: raw.view,
    rootKeyPath,
    keyPath,
    relativeKeyPath:
      keyLower === rootLower ? "" : keyPath.slice(rootKeyPath.length + 1),
  });
}

export function normalizeHostServiceProviderIdentity(
  value: HostServiceProviderIdentity,
): HostServiceProviderIdentity {
  const raw = objectValue(
    value,
    "host service provider identity",
  );
  return Object.freeze({
    providerDescriptorSha256: sha(
      raw.providerDescriptorSha256 as string,
      "providerDescriptorSha256",
    )!,
    providerGenerationSha256: sha(
      raw.providerGenerationSha256 as string,
      "providerGenerationSha256",
    )!,
    evidenceNamespace: boundedId(
      raw.evidenceNamespace as string,
      "evidenceNamespace",
    ),
  });
}

export function normalizeHostProcessReference(
  value: HostProcessReference,
): HostProcessReference {
  const raw = objectValue(
    value,
    "host process reference",
  );
  if (
    raw.schemaVersion !==
    "toadaid.host-process-reference.v1"
  ) {
    throw new TypeError(
      "unsupported host process reference schemaVersion",
    );
  }
  const core = Object.freeze({
    schemaVersion:
      "toadaid.host-process-reference.v1" as const,
    hostId: boundedId(
      raw.hostId as string,
      "process.hostId",
    ),
    sessionId: boundedId(
      raw.sessionId as string,
      "process.sessionId",
    ),
    pid: boundedPositive(
      raw.pid as number,
      1,
      2_147_483_647,
      "process.pid",
    ),
    processRef: ref(
      raw.processRef as string,
      "process.processRef",
    ),
    processReadReceiptSha256: sha(
      raw.processReadReceiptSha256 as string,
      "process.processReadReceiptSha256",
    )!,
    processEvidenceSha256: sha(
      raw.processEvidenceSha256 as string,
      "process.processEvidenceSha256",
    )!,
    providerDescriptorSha256: sha(
      raw.providerDescriptorSha256 as string,
      "process.providerDescriptorSha256",
    )!,
    providerGenerationSha256: sha(
      raw.providerGenerationSha256 as string,
      "process.providerGenerationSha256",
    )!,
    evidenceNamespace: boundedId(
      raw.evidenceNamespace as string,
      "process.evidenceNamespace",
    ),
    observedAt: canonicalIso(
      raw.observedAt as string,
      "process.observedAt",
    ),
  });
  const referenceSha256 = sha(
    raw.referenceSha256 as string,
    "process.referenceSha256",
  )!;
  if (referenceSha256 !== sha256(core)) {
    throw new Error(
      "host process reference integrity mismatch",
    );
  }
  return Object.freeze({
    ...core,
    referenceSha256,
  });
}

export function createHostProcessReference(
  receipt: HostServiceReceipt,
  input: Readonly<{
    pid: number;
    processRef: string;
    observedAt?: string;
  }>,
): HostProcessReference {
  if (
    receipt.status !== "OK" ||
    receipt.capabilityId !== "host:process-read" ||
    receipt.resultEvidenceSha256 === null
  ) {
    throw new Error(
      "host process reference requires successful governed host:process-read receipt",
    );
  }
  const core = Object.freeze({
    schemaVersion:
      "toadaid.host-process-reference.v1" as const,
    hostId: boundedId(
      receipt.hostId,
      "process.hostId",
    ),
    sessionId: boundedId(
      receipt.sessionId,
      "process.sessionId",
    ),
    pid: boundedPositive(
      input.pid,
      1,
      2_147_483_647,
      "process.pid",
    ),
    processRef: ref(
      input.processRef,
      "process.processRef",
    ),
    processReadReceiptSha256: sha(
      receipt.receiptSha256,
      "process.processReadReceiptSha256",
    )!,
    processEvidenceSha256: sha(
      receipt.resultEvidenceSha256,
      "process.processEvidenceSha256",
    )!,
    providerDescriptorSha256: sha(
      receipt.providerDescriptorSha256,
      "process.providerDescriptorSha256",
    )!,
    providerGenerationSha256: sha(
      receipt.providerGenerationSha256,
      "process.providerGenerationSha256",
    )!,
    evidenceNamespace: boundedId(
      receipt.evidenceNamespace,
      "process.evidenceNamespace",
    ),
    observedAt: canonicalIso(
      input.observedAt ?? receipt.invokedAt,
      "process.observedAt",
    ),
  });
  return Object.freeze({
    ...core,
    referenceSha256: sha256(core),
  });
}

function currentProviderIdentity(
  runtime: HostServiceEvidenceRuntime,
  hostId: string,
  sessionId: string,
): HostServiceProviderIdentity {
  const current =
    runtime.resolveCurrentProviderIdentity({
      hostId,
      sessionId,
    });
  if (current === null) {
    throw new Error(
      "host service current provider identity is unavailable",
    );
  }
  return normalizeHostServiceProviderIdentity(
    current,
  );
}

function assertProcessReferenceCurrent(
  request: NormalizedHostServiceRequest,
  runtime: HostServiceEvidenceRuntime,
  provider: HostServiceProviderIdentity,
  now: Date,
): void {
  if (request.kind !== "PROCESS_STOP") return;
  const details = objectValue(
    request.details,
    "process stop details",
  );
  const process = normalizeHostProcessReference(
    details.process as unknown as HostProcessReference,
  );
  const maxEvidenceAgeMs =
    details.maxEvidenceAgeMs;
  if (typeof maxEvidenceAgeMs !== "number") {
    throw new TypeError(
      "process stop maxEvidenceAgeMs is missing",
    );
  }

  const ageMs =
    now.getTime() - Date.parse(process.observedAt);
  if (
    !Number.isFinite(ageMs) ||
    ageMs < 0 ||
    ageMs > maxEvidenceAgeMs
  ) {
    throw new Error(
      "process stop reference is stale or from the future",
    );
  }

  if (
    process.hostId !== request.hostId ||
    process.sessionId !== request.sessionId ||
    process.providerDescriptorSha256 !==
      provider.providerDescriptorSha256 ||
    process.providerGenerationSha256 !==
      provider.providerGenerationSha256 ||
    process.evidenceNamespace !==
      provider.evidenceNamespace
  ) {
    throw new Error(
      "process stop reference provider/session identity is stale or mismatched",
    );
  }

  const current =
    runtime.resolveCurrentProcessReference({
      hostId: process.hostId,
      sessionId: process.sessionId,
      processRef: process.processRef,
    });
  if (
    current === null ||
    normalizeHostProcessReference(current)
      .referenceSha256 !== process.referenceSha256
  ) {
    throw new Error(
      "process stop reference is not current governed process-read evidence",
    );
  }
}

function assertLeaseDurationFitsOperation(
  expiresAt: string,
  now: Date,
  maxWallClockMs: number,
): void {
  const expiresAtMs = Date.parse(expiresAt);
  if (
    !Number.isFinite(expiresAtMs) ||
    now.getTime() + maxWallClockMs >
      expiresAtMs
  ) {
    throw new Error(
      "host service operation cannot fit inside remaining P15 lease lifetime",
    );
  }
}

function assertNoLegacyAliasConflict(
  input: GovernedHostServiceInput,
  capability: HostServiceCapabilityId,
): void {
  const legacy =
    LEGACY_HOST_CAPABILITY_ALIASES[
      capability as keyof typeof LEGACY_HOST_CAPABILITY_ALIASES
    ];
  if (
    legacy !== undefined &&
    input.lease.lease.allowedCapabilities.includes(
      legacy,
    )
  ) {
    throw new Error(
      `host service lease mixes deprecated ${legacy} with structured ${capability}`,
    );
  }
}

function hostProcessReferenceJson(
  value: HostProcessReference,
): HostServiceJsonValue {
  const process = normalizeHostProcessReference(value);
  return Object.freeze({
    schemaVersion: process.schemaVersion,
    hostId: process.hostId,
    sessionId: process.sessionId,
    pid: process.pid,
    processRef: process.processRef,
    processReadReceiptSha256:
      process.processReadReceiptSha256,
    processEvidenceSha256:
      process.processEvidenceSha256,
    providerDescriptorSha256:
      process.providerDescriptorSha256,
    providerGenerationSha256:
      process.providerGenerationSha256,
    evidenceNamespace:
      process.evidenceNamespace,
    observedAt: process.observedAt,
    referenceSha256: process.referenceSha256,
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
        argvProfileId: boundedId(request.argvProfileId, "argvProfileId"),
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
        process: hostProcessReferenceJson(
          request.process,
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
          (request.stdinSha256 === undefined) ||
        (request.stdinRef === undefined) !==
          (request.stdinByteLength === undefined)
      ) {
        throw new Error(
          "command stdinRef, stdinSha256, and stdinByteLength must be provided together",
        );
      }
      {
        const stdinRef =
          request.stdinRef === undefined
            ? null
            : ref(request.stdinRef, "stdinRef");
        return Object.freeze({
          executable: normalizeExecutable(request.executable),
          argvProfileId: boundedId(request.argvProfileId, "argvProfileId"),
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
          stdinByteLength:
            request.stdinByteLength === undefined
              ? null
              : boundedPositive(
                  request.stdinByteLength,
                  1,
                  4 * 1024 * 1024,
                  "stdinByteLength",
                ),
          maxOutputBytes:
            boundedPositive(
              request.maxOutputBytes,
              1024 * 1024,
              4 * 1024 * 1024,
              "maxOutputBytes",
            ),
          shell: false,
          elevation: "NONE",
          processPolicy:
            normalizeCommandProcessPolicy(
              request.processPolicy,
            ),
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
  features.push("provider-generation-bound");
  if (request.mutation) features.push("x1-reconciled-mutation");
  if (
    request.kind === "REGISTRY_READ" ||
    request.kind === "REGISTRY_WRITE"
  ) {
    features.push("explicit-registry-view");
  }
  if (request.kind === "FILE_READ" || request.kind === "FILE_WRITE") {
    features.push("realpath-scope-enforced");
  }
  if (
    request.kind === "CLIPBOARD_WRITE" ||
    request.kind === "FILE_WRITE" ||
    request.kind === "REGISTRY_WRITE" ||
    request.kind === "APP_LAUNCH" ||
    request.kind === "COMMAND_EXEC"
  ) {
    features.push("bounded-content-resolution");
  }
  if (request.kind === "APP_LAUNCH" || request.kind === "COMMAND_EXEC") {
    features.push(
      "structured-exec-no-shell",
      "structured-exec-explicit-context",
      "executable-identity-bound",
      "argv-profile-enforced",
    );
  }
  if (request.kind === "COMMAND_EXEC") {
    features.push(
      "bounded-child-process-policy",
      "confirmed-timeout-quiescence",
    );
  }
  if (request.kind === "PROCESS_STOP") {
    features.push(
      "process-identity-evidence-enforced",
      "governed-process-reference",
    );
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

function executionBindingFor(
  request: NormalizedHostServiceRequest,
  runtime: HostServiceExecutionRuntime,
): HostExecutionBinding | null {
  if (request.kind !== "APP_LAUNCH" && request.kind !== "COMMAND_EXEC") {
    return null;
  }
  const details = objectValue(request.details, "execution details");
  const executable = details.executable;
  const profileId = details.argvProfileId;
  const argv = details.argv;
  if (typeof executable !== "string" || typeof profileId !== "string" || !Array.isArray(argv)) {
    throw new TypeError("execution details are missing executable/profile/argv");
  }
  const capabilityId = request.capabilityId as HostExecutableCapabilityId;
  const rawBinding = runtime.resolveExecutableBinding({
    hostId: request.hostId,
    sessionId: request.sessionId,
    capabilityId,
    executable,
  });
  if (rawBinding === null) {
    throw new Error("current executable identity is unavailable");
  }
  const executableBinding = normalizeHostExecutableBinding(rawBinding);
  if (
    executableBinding.capabilityId !== capabilityId ||
    executableBinding.executable !== executable ||
    executableBinding.argvProfileId !== profileId
  ) {
    throw new Error("current executable binding does not match requested capability/path/profile");
  }
  const rawProfile = runtime.resolveArgvProfile({
    hostId: request.hostId,
    sessionId: request.sessionId,
    capabilityId,
    profileId,
  });
  if (rawProfile === null) {
    throw new Error("current argv profile is unavailable");
  }
  const argvProfile = normalizeHostArgvProfile(rawProfile);
  if (
    argvProfile.capabilityId !== capabilityId ||
    argvProfile.profileId !== profileId ||
    argvProfile.executableBindingSha256 !== executableBinding.bindingSha256
  ) {
    throw new Error("argv profile is stale or not bound to current executable identity");
  }
  const normalizedArgv = normalizeArgv(argv as readonly string[]);
  if (normalizedArgv.length < argvProfile.minArgs || normalizedArgv.length > argvProfile.maxArgs) {
    throw new Error("argv does not satisfy current bounded argv profile count");
  }
  for (let index = 0; index < argvProfile.requiredPrefix.length; index += 1) {
    if (normalizedArgv[index] !== argvProfile.requiredPrefix[index]) {
      throw new Error("argv does not satisfy current required prefix");
    }
  }
  for (const arg of normalizedArgv) {
    if (argvProfile.forbiddenExactArgs.includes(arg)) {
      throw new Error("argv contains an argument forbidden by current profile");
    }
  }
  const core = Object.freeze({
    schemaVersion: "toadaid.host-execution-binding.v1" as const,
    executable: executableBinding,
    argvProfile,
    argvSha256: sha256(normalizedArgv),
  });
  return Object.freeze({ ...core, bindingSha256: sha256(core) });
}

interface ContentSpec {
  readonly purpose: HostResolvedContentPurpose;
  readonly name: string | null;
  readonly contentRef: string;
  readonly contentSha256: string;
  readonly byteLength: number;
  readonly maxBytes: number;
}

function contentSpecsFor(request: HostServiceRequest): readonly ContentSpec[] {
  const specs: ContentSpec[] = [];
  const pushEnv = (
    purpose: "APP_ENV" | "COMMAND_ENV",
    values: readonly HostEnvironmentBinding[] | undefined,
  ) => {
    for (const binding of values ?? []) {
      specs.push({
        purpose,
        name: binding.name.toUpperCase(),
        contentRef: binding.valueRef,
        contentSha256: binding.valueSha256,
        byteLength: binding.byteLength,
        maxBytes: 65_536,
      });
    }
  };
  switch (request.kind) {
    case "APP_LAUNCH":
      pushEnv("APP_ENV", request.env);
      break;
    case "CLIPBOARD_WRITE":
      specs.push({
        purpose: "CLIPBOARD_WRITE",
        name: null,
        contentRef: request.contentRef,
        contentSha256: request.contentSha256,
        byteLength: request.byteLength,
        maxBytes: 65_536,
      });
      break;
    case "FILE_WRITE":
      specs.push({
        purpose: "FILE_WRITE",
        name: null,
        contentRef: request.contentRef,
        contentSha256: request.contentSha256,
        byteLength: request.byteLength,
        maxBytes: 16 * 1024 * 1024,
      });
      break;
    case "REGISTRY_WRITE":
      specs.push({
        purpose: "REGISTRY_WRITE",
        name: request.valueName,
        contentRef: request.valueRef,
        contentSha256: request.valueSha256,
        byteLength: request.byteLength,
        maxBytes: 16 * 1024 * 1024,
      });
      break;
    case "COMMAND_EXEC":
      pushEnv("COMMAND_ENV", request.env);
      if (
        request.stdinRef !== undefined &&
        request.stdinSha256 !== undefined &&
        request.stdinByteLength !== undefined
      ) {
        specs.push({
          purpose: "COMMAND_STDIN",
          name: null,
          contentRef: request.stdinRef,
          contentSha256: request.stdinSha256,
          byteLength: request.stdinByteLength,
          maxBytes: 4 * 1024 * 1024,
        });
      }
      break;
    default:
      break;
  }
  return Object.freeze(specs);
}

function resolveHostContent(
  request: HostServiceRequest,
  normalized: NormalizedHostServiceRequest,
  runtime: HostServiceContentRuntime,
): Readonly<{
  resolved: readonly HostResolvedContent[];
  setSha256: string | null;
}> {
  const resolved: HostResolvedContent[] = [];
  for (const spec of contentSpecsFor(request)) {
    const contentRef = ref(spec.contentRef, `${spec.purpose}.contentRef`);
    const expectedSha256 = sha(spec.contentSha256, `${spec.purpose}.contentSha256`)!;
    const expectedByteLength = boundedPositive(
      spec.byteLength,
      1,
      spec.maxBytes,
      `${spec.purpose}.byteLength`,
    );
    const bytes = runtime.resolveContent({
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      capabilityId: normalized.capabilityId,
      purpose: spec.purpose,
      name: spec.name,
      contentRef,
      expectedSha256,
      expectedByteLength,
      maxBytes: spec.maxBytes,
    });
    if (!(bytes instanceof Uint8Array)) {
      throw new Error(`host content resolver could not resolve ${spec.purpose}`);
    }
    if (bytes.byteLength !== expectedByteLength || bytes.byteLength > spec.maxBytes) {
      throw new Error(`resolved ${spec.purpose} byte length mismatch`);
    }
    if (bytesSha256(bytes) !== expectedSha256) {
      throw new Error(`resolved ${spec.purpose} SHA-256 mismatch`);
    }
    resolved.push(
      Object.freeze({
        purpose: spec.purpose,
        name: spec.name,
        refSha256: sha256(contentRef),
        contentSha256: expectedSha256,
        byteLength: expectedByteLength,
        bytes: new Uint8Array(bytes),
      }),
    );
  }
  resolved.sort((a, b) =>
    `${a.purpose}:${a.name ?? ""}:${a.refSha256}`.localeCompare(
      `${b.purpose}:${b.name ?? ""}:${b.refSha256}`,
    ),
  );
  const metadata = resolved.map((item) => ({
    purpose: item.purpose,
    name: item.name,
    refSha256: item.refSha256,
    contentSha256: item.contentSha256,
    byteLength: item.byteLength,
  }));
  return Object.freeze({
    resolved: Object.freeze(resolved),
    setSha256: metadata.length === 0 ? null : sha256(metadata),
  });
}

function redactContentRefs(
  request: NormalizedHostServiceRequest,
): NormalizedHostServiceRequest {
  const details = objectValue(request.details, "host service details");
  let sanitized: Record<string, HostServiceJsonValue> = {
    ...(details as Record<string, HostServiceJsonValue>),
  };
  if (request.kind === "CLIPBOARD_WRITE" || request.kind === "FILE_WRITE") {
    delete sanitized.contentRef;
  } else if (request.kind === "REGISTRY_WRITE") {
    delete sanitized.valueRef;
  } else if (request.kind === "APP_LAUNCH" || request.kind === "COMMAND_EXEC") {
    const env = Array.isArray(details.env)
      ? details.env.map((entry) => {
          const raw = objectValue(entry, "adapter env");
          const copy: Record<string, HostServiceJsonValue> = {
            ...(raw as Record<string, HostServiceJsonValue>),
          };
          delete copy.valueRef;
          return Object.freeze(copy);
        })
      : [];
    sanitized = { ...sanitized, env: Object.freeze(env) };
    if (request.kind === "COMMAND_EXEC") {
      delete sanitized.stdinRef;
    }
  }
  return Object.freeze({ ...request, details: Object.freeze(sanitized) });
}

function normalizeCommandExecutionEvidence(
  value: HostCommandExecutionEvidence | undefined,
  request: HostServiceAdapterRequest,
): HostCommandExecutionEvidence | undefined {
  if (request.parameters.kind !== "COMMAND_EXEC") {
    if (value !== undefined) {
      throw new Error("command execution evidence is only valid for COMMAND_EXEC");
    }
    return undefined;
  }
  if (value === undefined) {
    throw new Error("COMMAND_EXEC adapter result requires command execution evidence");
  }
  const raw = objectValue(value, "command execution evidence");
  if (raw.completionReason !== "EXITED" && raw.completionReason !== "TIMED_OUT") {
    throw new TypeError("command completionReason is invalid");
  }
  const childProcessCount = boundedNonNegative(
    raw.childProcessCount as number,
    32,
    "childProcessCount",
  );
  if (
    typeof raw.terminationRequested !== "boolean" ||
    typeof raw.quiescenceConfirmed !== "boolean"
  ) {
    throw new TypeError("command termination/quiescence evidence must be boolean");
  }
  const details = objectValue(request.parameters.details, "command execution details");
  const processPolicy = objectValue(details.processPolicy, "command process policy");
  const maxChildProcesses = processPolicy.maxChildProcesses;
  if (typeof maxChildProcesses !== "number") {
    throw new TypeError("command process policy maxChildProcesses is missing");
  }
  if (childProcessCount > maxChildProcesses) {
    throw new Error("command child process count exceeds bounded policy");
  }
  if (processPolicy.childProcessPolicy === "FORBID" && childProcessCount !== 0) {
    throw new Error("command reported a child process under FORBID policy");
  }
  if (raw.quiescenceConfirmed !== true) {
    throw new Error("command execution requires confirmed process-tree quiescence");
  }
  if (raw.completionReason === "TIMED_OUT" && raw.terminationRequested !== true) {
    throw new Error("timed-out command requires process-tree termination request");
  }
  if (raw.completionReason === "EXITED" && raw.terminationRequested !== false) {
    throw new Error("normally exited command cannot claim timeout termination");
  }
  return Object.freeze({
    completionReason: raw.completionReason,
    childProcessCount,
    terminationRequested: raw.terminationRequested,
    quiescenceConfirmed: raw.quiescenceConfirmed,
  });
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
  const commandExecution = normalizeCommandExecutionEvidence(
    raw.commandExecution as HostCommandExecutionEvidence | undefined,
    request,
  );
  const adapterEvidence = sha(raw.evidenceSha256 as string, "evidenceSha256")!;
  const evidenceSha256 = sha256({
    adapterEvidence,
    operationId: request.operationId,
    parametersSha256: request.parametersSha256,
    actionParametersSha256: request.actionParametersSha256,
    dispatchParametersSha256:
      request.dispatchParametersSha256,
    executionBindingSha256:
      request.executionBinding?.bindingSha256 ?? null,
    resolvedContentSetSha256:
      request.resolvedContentSetSha256,
    hostId: request.hostId,
    sessionId: request.sessionId,
    capabilityId: request.capabilityId,
    payloadSha256: payload === undefined ? null : sha256(payload),
    payloadRefSha256: payloadRef === undefined ? null : sha256(payloadRef),
    artifacts,
    commandExecution: commandExecution ?? null,
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
    ...(commandExecution === undefined ? {} : { commandExecution }),
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
  assertNoLegacyAliasConflict(
    input,
    normalized.capabilityId,
  );

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
  assertCurrentCapabilityInvocationHead(
    input.invocationHeadRuntime,
    invocation,
  );
  const providerIdentity = currentProviderIdentity(
    input.evidenceRuntime,
    normalized.hostId,
    normalized.sessionId,
  );
  if (
    providerIdentity.providerDescriptorSha256 !==
    binding.providerDescriptorSha256
  ) {
    throw new Error(
      "host service current provider descriptor does not match current C1 binding",
    );
  }
  const replayFence = assertReplayFence(
    input,
    invocation,
    normalized.mutation,
  );

  const now = (runtime.now ?? (() => new Date()))();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new TypeError("host service runtime now is invalid");
  }
  if (
    now.getTime() <
    Date.parse(invocation.record.updatedAt)
  ) {
    throw new RangeError(
      "host service invocation time is earlier than active H1 predecessor",
    );
  }
  assertLeaseDurationFitsOperation(
    leaseBinding.expiresAt,
    now,
    normalized.maxWallClockMs,
  );
  assertProcessReferenceCurrent(
    normalized,
    input.evidenceRuntime,
    providerIdentity,
    now,
  );
  const executionBinding = executionBindingFor(
    normalized,
    input.executionRuntime,
  );
  const contentResolution = resolveHostContent(
    input.request,
    normalized,
    input.contentRuntime,
  );
  const adapterParameters = redactContentRefs(normalized);
  const dispatchParametersSha256 =
    sha256(adapterParameters);

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
  const reconciliationId = boundedId(
    `recon-${sha256({
      invocationRecordSha256: invocation.recordSha256,
      operationId,
    }).slice(0, 32)}`,
    "reconciliationId",
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
    providerIdentity,
    toolName: normalized.toolName,
    parametersSha256,
    actionParametersSha256,
    dispatchParametersSha256,
    executionBinding,
    resolvedContentSetSha256: contentResolution.setSha256,
    resolvedContent: contentResolution.resolved,
    maxWallClockMs: normalized.maxWallClockMs,
    parameters: adapterParameters,
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
      invocationRecordSha256: invocation.recordSha256,
      intentSha256: invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      providerDescriptorSha256:
        providerIdentity.providerDescriptorSha256,
      providerGenerationSha256:
        providerIdentity.providerGenerationSha256,
      evidenceNamespace:
        providerIdentity.evidenceNamespace,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256,
      replayFenceSha256: replayFence?.recordSha256 ?? null,
      operationId,
      parametersSha256,
      actionParametersSha256,
      dispatchParametersSha256,
      executionBindingSha256: executionBinding?.bindingSha256 ?? null,
      resolvedContentSetSha256: contentResolution.setSha256,
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
      invocation,
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
      const opened =
        beginCapabilityInvocationReconciliation(
          replayFence,
          invocation,
          {
            reconciliationId,
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
      publishCapabilityInvocationReconciliationHead(
        input.invocationHeadRuntime,
        invocation,
        opened,
      );
      const reconciliation = opened.reconciliation;
      const lockedInvocation = opened.invocation;
      const core = Object.freeze({
        schemaVersion: "toadaid.host-service-receipt.v1" as const,
        status: "RECONCILIATION_REQUIRED" as const,
        capabilityId: normalized.capabilityId,
        invocationId: invocation.record.invocationId,
        invocationRecordSha256:
          lockedInvocation.recordSha256,
        intentSha256: invocation.record.request.intentSha256,
        runId: invocation.record.runId,
        hostId: normalized.hostId,
        sessionId: normalized.sessionId,
        ownerId: normalized.ownerId,
        providerDescriptorSha256:
          providerIdentity.providerDescriptorSha256,
        providerGenerationSha256:
          providerIdentity.providerGenerationSha256,
        evidenceNamespace:
          providerIdentity.evidenceNamespace,
        leaseSha256: leaseBinding.leaseSha256,
        contractBindingSha256: binding.bindingSha256,
        descriptorSha256: compatibility.descriptorSha256,
        adapterRegistrationSha256,
        replayFenceSha256: replayFence.recordSha256,
        operationId,
        parametersSha256,
        actionParametersSha256,
        dispatchParametersSha256,
        executionBindingSha256: executionBinding?.bindingSha256 ?? null,
        resolvedContentSetSha256: contentResolution.setSha256,
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
        invocation: lockedInvocation,
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
      invocationRecordSha256: invocation.recordSha256,
      intentSha256: invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      providerDescriptorSha256:
        providerIdentity.providerDescriptorSha256,
      providerGenerationSha256:
        providerIdentity.providerGenerationSha256,
      evidenceNamespace:
        providerIdentity.evidenceNamespace,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256,
      replayFenceSha256: replayFence?.recordSha256 ?? null,
      operationId,
      parametersSha256,
      actionParametersSha256,
      dispatchParametersSha256,
      executionBindingSha256: executionBinding?.bindingSha256 ?? null,
      resolvedContentSetSha256: contentResolution.setSha256,
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
      invocation,
      receipt,
      budget: budgetAfter,
      result: null,
      reconciliation: null,
    });
  }
}
