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
  assertDesktopElementReferenceCurrent,
  assertDesktopObservationReceiptIntegrity,
  desktopObservationParametersSha256,
  normalizeDesktopObservationRequest,
} from "./desktopObservation.js";
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
  DesktopInteractionAdapterRegistration,
  DesktopInteractionAdapterRequest,
  DesktopInteractionAdapterResult,
  DesktopInteractionPreparationRequest,
  DesktopInteractionPreparationResult,
  DesktopInteractionPreparationTicket,
  DesktopInteractionCapabilityId,
  DesktopInteractionKind,
  DesktopInteractionObservationBinding,
  DesktopInteractionObservationReference,
  DesktopInteractionReceipt,
  DesktopInteractionRequest,
  DesktopInteractionRuntime,
  GovernedDesktopInteractionAdapter,
  GovernedDesktopInteractionInput,
  GovernedDesktopInteractionOutcome,
  NormalizedDesktopCoordinateTarget,
  NormalizedDesktopElementTarget,
  NormalizedDesktopInteractionRequest,
  NormalizedDesktopPointerTarget,
} from "./desktopInteractionTypes.js";
import type {
  DesktopObservationHeadRuntime,
  DesktopObservationReceipt,
  DesktopObservationRequest,
  DesktopObservedElementReference,
  NormalizedDesktopObservationRequest,
} from "./desktopObservationTypes.js";
import type {
  CapabilityInvocationEnvelope,
} from "./invocationTypes.js";
import type {
  ReplayFenceEnvelope,
} from "./replayFenceTypes.js";
import type {
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type * from "./desktopInteractionTypes.js";

export const DESKTOP_INTERACTION_CAPABILITIES:
  readonly DesktopInteractionCapabilityId[] = Object.freeze([
    "host:pointer-click",
    "host:pointer-move",
    "host:scroll",
    "host:text-input",
    "host:shortcut",
  ]);

export const DESKTOP_INTERACTION_CONTRACT_IDS:
  Readonly<Record<DesktopInteractionCapabilityId, string>> =
  Object.freeze({
    "host:pointer-click":
      "toadaid.host.pointer-click",
    "host:pointer-move":
      "toadaid.host.pointer-move",
    "host:scroll":
      "toadaid.host.scroll",
    "host:text-input":
      "toadaid.host.text-input",
    "host:shortcut":
      "toadaid.host.shortcut",
  });

export const DESKTOP_INTERACTION_TOOL_NAMES:
  Readonly<Record<DesktopInteractionCapabilityId, string>> =
  Object.freeze({
    "host:pointer-click":
      "desktop.pointer-click",
    "host:pointer-move":
      "desktop.pointer-move",
    "host:scroll":
      "desktop.scroll",
    "host:text-input":
      "desktop.text-input",
    "host:shortcut":
      "desktop.shortcut",
  });

const CAPABILITY_SET = new Set<string>(
  DESKTOP_INTERACTION_CAPABILITIES,
);
const CONTRACT_ID_PATTERN =
  /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/;
const MAX_COORDINATE = 100_000;
const MAX_SCROLL_DELTA = 100_000;
const MAX_TEXT_LENGTH = 8_192;
const MAX_SHORTCUT_KEYS = 8;
const DEFAULT_MAX_OBSERVATION_AGE_MS = 5_000;
const MAX_OBSERVATION_AGE_MS = 30_000;
const DEFAULT_MAX_WALL_CLOCK_MS = 5_000;
const MAX_WALL_CLOCK_MS = 30_000;
const MAX_PREPARATION_TTL_MS = 2_000;

export class DesktopInteractionRefusedBeforeDispatchError extends Error {
  readonly status = "REFUSED_BEFORE_DISPATCH" as const;
  readonly reasonCode: string;
  readonly evidenceSha256: string | null;

  constructor(
    reasonCode: string,
    evidenceSha256: string | null = null,
  ) {
    super(`desktop interaction refused before dispatch: ${reasonCode}`);
    this.name = "DesktopInteractionRefusedBeforeDispatchError";
    this.reasonCode = reasonCode;
    this.evidenceSha256 = evidenceSha256;
  }
}

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

function boundedPositiveInteger(
  value: number | undefined,
  fallback: number,
  max: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < 1 ||
    resolved > max
  ) {
    throw new RangeError(
      `${label} must be an integer in [1, ${max}]`,
    );
  }
  return resolved;
}

function boundedInteger(
  value: number,
  min: number,
  max: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(value) ||
    value < min ||
    value > max
  ) {
    throw new RangeError(
      `${label} must be an integer in [${min}, ${max}]`,
    );
  }
  return value;
}

function normalizeCapability(
  value: string,
): DesktopInteractionCapabilityId {
  const normalized = capabilityId(value);
  if (!CAPABILITY_SET.has(normalized)) {
    throw new TypeError(
      `unsupported desktop interaction capability: ${normalized}`,
    );
  }
  return normalized as DesktopInteractionCapabilityId;
}

function capabilityForKind(
  kind: DesktopInteractionKind,
): DesktopInteractionCapabilityId {
  switch (kind) {
    case "POINTER_CLICK":
      return "host:pointer-click";
    case "POINTER_MOVE":
      return "host:pointer-move";
    case "SCROLL":
      return "host:scroll";
    case "TEXT_INPUT":
      return "host:text-input";
    case "SHORTCUT":
      return "host:shortcut";
    default:
      throw new TypeError(
        "unsupported desktop interaction kind",
      );
  }
}

function normalizeObservationBinding(
  value: DesktopInteractionObservationBinding,
): DesktopInteractionObservationBinding {
  const raw = objectValue(value, "observation");
  return Object.freeze({
    receiptSha256:
      sha(
        raw.receiptSha256 as string,
        "observation.receiptSha256",
      )!,
    observationEpoch: boundedId(
      raw.observationEpoch as string,
      "observation.observationEpoch",
    ),
    evidenceSha256:
      sha(
        raw.evidenceSha256 as string,
        "observation.evidenceSha256",
      )!,
    windowId: boundedId(
      raw.windowId as string,
      "observation.windowId",
    ),
  });
}

function normalizeElementTarget(
  value: unknown,
): NormalizedDesktopElementTarget {
  const raw = objectValue(value, "target");
  if (raw.kind !== "ELEMENT") {
    throw new TypeError(
      "desktop element target kind must be ELEMENT",
    );
  }
  const element = objectValue(
    raw.element,
    "target.element",
  );
  if (
    element.schemaVersion !==
    "toadaid.desktop-observed-element-ref.v1"
  ) {
    throw new TypeError(
      "unsupported desktop observed element reference schemaVersion",
    );
  }
  const normalized: DesktopObservedElementReference =
    Object.freeze({
      schemaVersion:
        "toadaid.desktop-observed-element-ref.v1",
      elementId: boundedId(
        element.elementId as string,
        "target.element.elementId",
      ),
      hostId: boundedId(
        element.hostId as string,
        "target.element.hostId",
      ),
      sessionId: boundedId(
        element.sessionId as string,
        "target.element.sessionId",
      ),
      windowId: boundedId(
        element.windowId as string,
        "target.element.windowId",
      ),
      observationEpoch: boundedId(
        element.observationEpoch as string,
        "target.element.observationEpoch",
      ),
      observationEvidenceSha256:
        sha(
          element.observationEvidenceSha256 as string,
          "target.element.observationEvidenceSha256",
        )!,
      providerDescriptorSha256:
        sha(element.providerDescriptorSha256 as string, "target.element.providerDescriptorSha256")!,
      providerGenerationSha256:
        sha(element.providerGenerationSha256 as string, "target.element.providerGenerationSha256")!,
      evidenceNamespace: boundedId(element.evidenceNamespace as string, "target.element.evidenceNamespace"),
      elementEvidenceSha256:
        sha(
          element.elementEvidenceSha256 as string,
          "target.element.elementEvidenceSha256",
        )!,
      inputSecurity:
        element.inputSecurity === "ORDINARY_TEXT" ||
        element.inputSecurity === "SECRET_OR_PASSWORD" ||
        element.inputSecurity === "UNKNOWN"
          ? element.inputSecurity
          : (() => {
              throw new TypeError(
                "target.element.inputSecurity is invalid",
              );
            })(),
    });
  return Object.freeze({
    kind: "ELEMENT",
    element: normalized,
  });
}

function normalizeCoordinateTarget(
  value: unknown,
): NormalizedDesktopCoordinateTarget {
  const raw = objectValue(value, "target");
  if (raw.kind !== "COORDINATE") {
    throw new TypeError(
      "desktop coordinate target kind must be COORDINATE",
    );
  }
  const displayId =
    raw.displayId === undefined
      ? null
      : boundedInteger(
          raw.displayId as number,
          0,
          31,
          "target.displayId",
        );
  const displayTopologyEpoch = raw.displayTopologyEpoch === undefined
    ? null
    : boundedId(raw.displayTopologyEpoch as string, "target.displayTopologyEpoch");
  if ((displayId !== null) !== (displayTopologyEpoch !== null)) {
    throw new Error("coordinate displayId requires exact displayTopologyEpoch");
  }
  const coordinateSpace = raw.coordinateSpace;
  if (coordinateSpace !== "DESKTOP_PHYSICAL" && coordinateSpace !== "WINDOW_CLIENT_PHYSICAL") {
    throw new TypeError("target.coordinateSpace is invalid");
  }
  return Object.freeze({
    kind: "COORDINATE",
    displayId,
    displayTopologyEpoch,
    coordinateSpace,
    x: boundedInteger(
      raw.x as number,
      -MAX_COORDINATE,
      MAX_COORDINATE,
      "target.x",
    ),
    y: boundedInteger(
      raw.y as number,
      -MAX_COORDINATE,
      MAX_COORDINATE,
      "target.y",
    ),
  });
}

function normalizePointerTarget(
  value: unknown,
): NormalizedDesktopPointerTarget {
  const raw = objectValue(value, "target");
  if (raw.kind === "ELEMENT") {
    return normalizeElementTarget(raw);
  }
  if (raw.kind === "COORDINATE") {
    return normalizeCoordinateTarget(raw);
  }
  throw new TypeError(
    "unsupported desktop pointer target kind",
  );
}

function normalizeShortcutKeys(
  values: readonly string[],
): readonly string[] {
  if (
    !Array.isArray(values) ||
    values.length < 2 ||
    values.length > MAX_SHORTCUT_KEYS
  ) {
    throw new RangeError(
      `shortcut keys must contain 2-${MAX_SHORTCUT_KEYS} entries`,
    );
  }
  const seen = new Set<string>();
  const normalized = values.map((value, index) => {
    if (
      typeof value !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(
        value,
      )
    ) {
      throw new TypeError(
        `keys[${index}] is invalid`,
      );
    }
    const key = value.toUpperCase();
    if (seen.has(key)) {
      throw new TypeError(
        `duplicate shortcut key: ${key}`,
      );
    }
    seen.add(key);
    return key;
  });
  const commandModifiers = new Set([
    "CTRL",
    "CONTROL",
    "ALT",
    "META",
    "CMD",
    "WIN",
    "SUPER",
  ]);
  if (
    !normalized.some((key) =>
      commandModifiers.has(key),
    )
  ) {
    throw new Error(
      "desktop shortcut requires an explicit command modifier",
    );
  }
  return Object.freeze(normalized);
}

export function normalizeDesktopInteractionRequest(
  request: DesktopInteractionRequest,
): NormalizedDesktopInteractionRequest {
  const capability = capabilityForKind(
    request.kind as DesktopInteractionKind,
  );
  const hostId = boundedId(request.hostId, "hostId");
  const sessionId = boundedId(
    request.sessionId,
    "sessionId",
  );
  const ownerId = boundedId(request.ownerId, "ownerId");
  const observation = normalizeObservationBinding(
    request.observation,
  );
  const maxObservationAgeMs = boundedPositiveInteger(
    request.maxObservationAgeMs,
    DEFAULT_MAX_OBSERVATION_AGE_MS,
    MAX_OBSERVATION_AGE_MS,
    "maxObservationAgeMs",
  );
  const maxWallClockMs = boundedPositiveInteger(
    request.maxWallClockMs,
    DEFAULT_MAX_WALL_CLOCK_MS,
    MAX_WALL_CLOCK_MS,
    "maxWallClockMs",
  );

  if (request.kind === "POINTER_CLICK") {
    const button = request.button ?? "LEFT";
    if (
      button !== "LEFT" &&
      button !== "RIGHT" &&
      button !== "MIDDLE"
    ) {
      throw new TypeError(
        "pointer click button is invalid",
      );
    }
    return Object.freeze({
      kind: request.kind,
      capabilityId: capability,
      toolName:
        DESKTOP_INTERACTION_TOOL_NAMES[capability],
      hostId,
      sessionId,
      ownerId,
      observation,
      target: normalizePointerTarget(request.target),
      button,
      clickCount: boundedPositiveInteger(
        request.clickCount,
        1,
        3,
        "clickCount",
      ),
      deltaX: 0,
      deltaY: 0,
      text: null,
      contentClass: null,
      replace: false,
      keys: Object.freeze([]),
      maxObservationAgeMs,
      maxWallClockMs,
    });
  }

  if (request.kind === "POINTER_MOVE") {
    return Object.freeze({
      kind: request.kind,
      capabilityId: capability,
      toolName:
        DESKTOP_INTERACTION_TOOL_NAMES[capability],
      hostId,
      sessionId,
      ownerId,
      observation,
      target: normalizePointerTarget(request.target),
      button: null,
      clickCount: 0,
      deltaX: 0,
      deltaY: 0,
      text: null,
      contentClass: null,
      replace: false,
      keys: Object.freeze([]),
      maxObservationAgeMs,
      maxWallClockMs,
    });
  }

  if (request.kind === "SCROLL") {
    const deltaX = boundedInteger(
      request.deltaX,
      -MAX_SCROLL_DELTA,
      MAX_SCROLL_DELTA,
      "deltaX",
    );
    const deltaY = boundedInteger(
      request.deltaY,
      -MAX_SCROLL_DELTA,
      MAX_SCROLL_DELTA,
      "deltaY",
    );
    if (deltaX === 0 && deltaY === 0) {
      throw new RangeError(
        "scroll requires a non-zero delta",
      );
    }
    return Object.freeze({
      kind: request.kind,
      capabilityId: capability,
      toolName:
        DESKTOP_INTERACTION_TOOL_NAMES[capability],
      hostId,
      sessionId,
      ownerId,
      observation,
      target: null,
      button: null,
      clickCount: 0,
      deltaX,
      deltaY,
      text: null,
      contentClass: null,
      replace: false,
      keys: Object.freeze([]),
      maxObservationAgeMs,
      maxWallClockMs,
    });
  }

  if (request.kind === "TEXT_INPUT") {
    if (request.contentClass !== "ORDINARY_TEXT") {
      throw new Error(
        "desktop text input refuses secret/password content; use a separately governed secret-entry capability",
      );
    }
    if (
      typeof request.text !== "string" ||
      request.text.length < 1 ||
      request.text.length > MAX_TEXT_LENGTH ||
      request.text.includes("\u0000")
    ) {
      throw new TypeError(
        "desktop text input is invalid",
      );
    }
    const target =
      normalizeElementTarget(request.target);
    if (
      target.element.inputSecurity !==
      "ORDINARY_TEXT"
    ) {
      throw new Error(
        "desktop text input requires P16 ORDINARY_TEXT target evidence",
      );
    }
    return Object.freeze({
      kind: request.kind,
      capabilityId: capability,
      toolName:
        DESKTOP_INTERACTION_TOOL_NAMES[capability],
      hostId,
      sessionId,
      ownerId,
      observation,
      target,
      button: null,
      clickCount: 0,
      deltaX: 0,
      deltaY: 0,
      text: request.text,
      contentClass: "ORDINARY_TEXT",
      replace: request.replace ?? false,
      keys: Object.freeze([]),
      maxObservationAgeMs,
      maxWallClockMs,
    });
  }

  if (request.kind === "SHORTCUT") {
    return Object.freeze({
      kind: request.kind,
      capabilityId: capability,
      toolName:
        DESKTOP_INTERACTION_TOOL_NAMES[capability],
      hostId,
      sessionId,
      ownerId,
      observation,
      target: null,
      button: null,
      clickCount: 0,
      deltaX: 0,
      deltaY: 0,
      text: null,
      contentClass: null,
      replace: false,
      keys: normalizeShortcutKeys(request.keys),
      maxObservationAgeMs,
      maxWallClockMs,
    });
  }

  throw new TypeError(
    "unsupported desktop interaction request",
  );
}

export function desktopInteractionParametersSha256(
  request: DesktopInteractionRequest,
): string {
  return sha256(
    normalizeDesktopInteractionRequest(request),
  );
}

export function normalizeDesktopInteractionAdapterRegistration(
  value: DesktopInteractionAdapterRegistration,
): DesktopInteractionAdapterRegistration {
  if (
    value.schemaVersion !==
    "toadaid.desktop-interaction-adapter-registration.v1"
  ) {
    throw new TypeError(
      "unsupported desktop interaction adapter registration schemaVersion",
    );
  }
  const capability = normalizeCapability(
    value.capabilityId,
  );
  const normalizedTool = toolName(value.toolName);
  if (
    normalizedTool !==
    DESKTOP_INTERACTION_TOOL_NAMES[capability]
  ) {
    throw new Error(
      "desktop interaction adapter toolName does not match capability",
    );
  }
  if (
    typeof value.contractId !== "string" ||
    !CONTRACT_ID_PATTERN.test(value.contractId) ||
    value.contractId !==
      DESKTOP_INTERACTION_CONTRACT_IDS[capability]
  ) {
    throw new TypeError(
      "desktop interaction adapter contractId is invalid or mismatched",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.desktop-interaction-adapter-registration.v1",
    adapterId: boundedId(value.adapterId, "adapterId"),
    capabilityId: capability,
    toolName: normalizedTool,
    contractId: value.contractId,
    descriptorSha256:
      sha(
        value.descriptorSha256,
        "descriptorSha256",
      )!,
    implementationFingerprintSha256:
      sha(
        value.implementationFingerprintSha256,
        "implementationFingerprintSha256",
      )!,
  });
}

export function desktopInteractionAdapterRegistrationSha256(
  value: DesktopInteractionAdapterRegistration,
): string {
  return sha256(normalizeDesktopInteractionAdapterRegistration(value));
}

function assertC1H1Binding(
  input: GovernedDesktopInteractionInput,
  normalized: NormalizedDesktopInteractionRequest,
  registration: DesktopInteractionAdapterRegistration,
) {
  const invocation =
    validateCapabilityInvocationEnvelope(
      input.invocation,
    );
  if (invocation.record.status !== "STARTED") {
    throw new Error(
      "desktop interaction requires STARTED H1 invocation",
    );
  }
  if (
    invocation.record.capabilityId !==
      normalized.capabilityId ||
    invocation.record.toolName !==
      normalized.toolName
  ) {
    throw new Error(
      "desktop interaction H1 capability/tool identity mismatch",
    );
  }
  const parametersSha256 = sha256(normalized);
  if (
    invocation.record.request.argumentsSha256 !==
    parametersSha256
  ) {
    throw new Error(
      "desktop interaction parameters do not match H1 argumentsSha256",
    );
  }

  const binding =
    validateCapabilityInvocationContractBinding(
      input.contractBinding,
    );
  const compatibility =
    assertCapabilityContractCompatible(
      input.contractRegistry,
      input.contractRequirement,
    );
  if (
    input.contractRequirement.capabilityId !==
      normalized.capabilityId ||
    compatibility.capabilityId !==
      normalized.capabilityId
  ) {
    throw new Error(
      "desktop interaction C1 capability mismatch",
    );
  }
  if (
    binding.invocationId !==
      invocation.record.invocationId ||
    binding.runId !== invocation.record.runId ||
    binding.capabilityId !==
      invocation.record.capabilityId ||
    binding.intentSha256 !==
      invocation.record.request.intentSha256 ||
    binding.requirementSha256 !==
      compatibility.requirementSha256 ||
    binding.descriptorSha256 !==
      compatibility.descriptorSha256 ||
    binding.contractId !== compatibility.contractId
  ) {
    throw new Error(
      "desktop interaction C1 binding is stale or mismatched",
    );
  }

  const ready = input.contractReady;
  if (
    ready.schemaVersion !==
      "toadaid.capability-invocation-contract-ready.v1" ||
    ready.invocationId !==
      invocation.record.invocationId ||
    ready.capabilityId !==
      normalized.capabilityId ||
    ready.bindingSha256 !== binding.bindingSha256 ||
    ready.compatibility.requirementSha256 !==
      compatibility.requirementSha256 ||
    ready.compatibility.descriptorSha256 !==
      compatibility.descriptorSha256 ||
    ready.provider.providerDescriptorSha256 !==
      binding.providerDescriptorSha256 ||
    ready.provider.adapterRegistrationSha256 !==
      binding.adapterRegistrationSha256 ||
    ready.provider.implementationFingerprintSha256 !==
      binding.implementationFingerprintSha256
  ) {
    throw new Error(
      "desktop interaction contract-ready receipt is stale or mismatched",
    );
  }

  if (
    registration.capabilityId !==
      normalized.capabilityId ||
    registration.toolName !==
      normalized.toolName ||
    registration.contractId !==
      compatibility.contractId ||
    registration.descriptorSha256 !==
      compatibility.descriptorSha256 ||
    desktopInteractionAdapterRegistrationSha256(registration) !==
      binding.adapterRegistrationSha256 ||
    registration.implementationFingerprintSha256 !==
      binding.implementationFingerprintSha256
  ) {
    throw new Error(
      "desktop interaction adapter registration does not match current C1 truth",
    );
  }

  return { invocation, binding, compatibility };
}

function assertReplayFence(
  fenceInput: ReplayFenceEnvelope,
  invocation: CapabilityInvocationEnvelope,
): ReplayFenceEnvelope {
  const fence = validateReplayFenceEnvelope(
    fenceInput,
  );
  const current =
    validateCapabilityInvocationEnvelope(
      invocation,
    );
  if (
    fence.record.binding.runId !==
      current.record.runId ||
    fence.record.binding.invocationId !==
      current.record.invocationId ||
    fence.record.binding.capabilityId !==
      current.record.capabilityId ||
    fence.record.binding.intentSha256 !==
      current.record.request.intentSha256
  ) {
    throw new Error(
      "desktop interaction X1 replay fence does not match H1 invocation",
    );
  }
  if (fence.record.replayClass !== "NON_REPLAYABLE") {
    throw new Error(
      "desktop interaction v1 requires NON_REPLAYABLE X1 classification",
    );
  }
  return fence;
}

function assertCurrentObservationHead(
  receipt: DesktopObservationReceipt,
  runtime: DesktopObservationHeadRuntime,
): void {
  if (
    receipt.status !== "OK" ||
    receipt.evidenceSha256 === null ||
    receipt.windowId === null
  ) {
    throw new Error(
      "desktop interaction requires successful exact-window P16 evidence",
    );
  }
  const currentProvider = runtime.resolveCurrentProviderIdentity({
    hostId: receipt.hostId,
    sessionId: receipt.sessionId,
  });
  if (
    currentProvider === null ||
    currentProvider.providerDescriptorSha256 !== receipt.providerDescriptorSha256 ||
    currentProvider.providerGenerationSha256 !== receipt.providerGenerationSha256 ||
    currentProvider.evidenceNamespace !== receipt.evidenceNamespace
  ) {
    throw new Error("desktop interaction observation provider generation is stale");
  }
  const current =
    runtime.resolveCurrentObservationHead({
      hostId: receipt.hostId,
      sessionId: receipt.sessionId,
      windowId: receipt.windowId,
    });
  if (
    current === null ||
    current.schemaVersion !==
      "toadaid.desktop-observation-head.v1" ||
    current.status !== "OK" ||
    current.hostId !== receipt.hostId ||
    current.sessionId !== receipt.sessionId ||
    current.windowId !== receipt.windowId ||
    current.observationEpoch !==
      receipt.observationEpoch ||
    current.providerDescriptorSha256 !== receipt.providerDescriptorSha256 ||
    current.providerGenerationSha256 !== receipt.providerGenerationSha256 ||
    current.evidenceNamespace !== receipt.evidenceNamespace ||
    current.evidenceSha256 !==
      receipt.evidenceSha256 ||
    current.receiptSha256 !==
      receipt.receiptSha256
  ) {
    throw new Error(
      "desktop interaction observation is stale or not current",
    );
  }
}

function assertObservationBinding(
  normalized: NormalizedDesktopInteractionRequest,
  observationRequest: DesktopObservationRequest,
  receipt: DesktopObservationReceipt,
  runtime: DesktopObservationHeadRuntime,
  now: Date,
): NormalizedDesktopObservationRequest {
  assertDesktopObservationReceiptIntegrity(receipt);
  if (
    receipt.status !== "OK" ||
    receipt.evidenceSha256 === null ||
    receipt.windowId === null
  ) {
    throw new Error(
      "desktop interaction requires successful exact-window P16 observation",
    );
  }
  const observation =
    normalizeDesktopObservationRequest(
      observationRequest,
    );
  if (observation.kind !== "UI_SNAPSHOT") {
    throw new Error(
      "desktop interaction requires UI_SNAPSHOT evidence",
    );
  }
  if (
    desktopObservationParametersSha256(
      observationRequest,
    ) !== receipt.parametersSha256
  ) {
    throw new Error(
      "desktop interaction P16 request/receipt parameters mismatch",
    );
  }
  if (
    receipt.hostId !== normalized.hostId ||
    receipt.sessionId !== normalized.sessionId ||
    receipt.ownerId !== normalized.ownerId ||
    receipt.windowId !==
      normalized.observation.windowId ||
    receipt.observationEpoch !==
      normalized.observation.observationEpoch ||
    receipt.evidenceSha256 !==
      normalized.observation.evidenceSha256 ||
    receipt.receiptSha256 !==
      normalized.observation.receiptSha256 ||
    observation.hostId !== normalized.hostId ||
    observation.sessionId !== normalized.sessionId ||
    observation.ownerId !== normalized.ownerId ||
    observation.windowId !== receipt.windowId
  ) {
    throw new Error(
      "desktop interaction P16 observation binding mismatch",
    );
  }
  const ageMs =
    now.getTime() - Date.parse(receipt.observedAt);
  if (
    !Number.isFinite(ageMs) ||
    ageMs < 0 ||
    ageMs > normalized.maxObservationAgeMs
  ) {
    throw new Error(
      "desktop interaction P16 observation is too old",
    );
  }
  assertCurrentObservationHead(receipt, runtime);
  return observation;
}

function targetEvidenceSha256(
  normalized: NormalizedDesktopInteractionRequest,
  observation: NormalizedDesktopObservationRequest,
  receipt: DesktopObservationReceipt,
  runtime: DesktopObservationHeadRuntime,
): string {
  if (normalized.target?.kind === "ELEMENT") {
    assertDesktopElementReferenceCurrent(
      normalized.target.element,
      receipt,
      runtime,
    );
    return sha256({
      receiptSha256: receipt.receiptSha256,
      evidenceSha256: receipt.evidenceSha256,
      elementId:
        normalized.target.element.elementId,
      elementEvidenceSha256:
        normalized.target.element.elementEvidenceSha256,
    });
  }

  if (normalized.target?.kind === "COORDINATE") {
    const target = normalized.target;
    const geometry = receipt.geometry;
    if (geometry === null) throw new Error("desktop coordinate target requires exact P16 geometry evidence");
    if (target.coordinateSpace !== geometry.coordinateSpace) throw new Error("desktop coordinate target coordinate space mismatch");
    if (target.displayId !== null) {
      if (target.coordinateSpace !== "DESKTOP_PHYSICAL" ||
          !receipt.displayIds.includes(target.displayId) ||
          target.displayTopologyEpoch !== receipt.displayTopologyEpoch ||
          target.displayTopologyEpoch !== geometry.displayTopologyEpoch) {
        throw new Error("desktop coordinate display target is stale or not authorized by P16 topology evidence");
      }
    }
    if (
      target.x < geometry.bounds.left ||
      target.x >= geometry.bounds.right ||
      target.y < geometry.bounds.top ||
      target.y >= geometry.bounds.bottom
    ) throw new Error("desktop coordinate target is outside authorized P16 geometry");
    return sha256({
      receiptSha256: receipt.receiptSha256,
      evidenceSha256: receipt.evidenceSha256,
      target,
      geometry,
      displayIds: receipt.displayIds,
      displayTopologyEpoch: receipt.displayTopologyEpoch,
    });
  }

  return sha256({
    receiptSha256: receipt.receiptSha256,
    evidenceSha256: receipt.evidenceSha256,
    windowId: receipt.windowId,
  });
}

function actionParametersSha256(
  request: NormalizedDesktopInteractionRequest,
): string {
  return sha256({
    kind: request.kind,
    target: request.target,
    button: request.button,
    clickCount: request.clickCount,
    deltaX: request.deltaX,
    deltaY: request.deltaY,
    text: request.text,
    contentClass: request.contentClass,
    replace: request.replace,
    keys: request.keys,
  });
}

function buildDesktopInteractionPreparationTicket(
  value: DesktopInteractionPreparationResult,
  request: DesktopInteractionPreparationRequest,
  preparedAt: Date,
): DesktopInteractionPreparationTicket {
  const raw = objectValue(
    value,
    "desktop interaction preparation result",
  );
  if (
    raw.schemaVersion !==
    "toadaid.desktop-interaction-prepare-result.v1"
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_SCHEMA_INVALID",
    );
  }

  if (raw.status === "REFUSED_BEFORE_DISPATCH") {
    const reasonCode = boundedId(
      raw.reasonCode as string,
      "preparation.reasonCode",
    );
    const evidenceSha256 =
      raw.evidenceSha256 == null
        ? null
        : sha(
            raw.evidenceSha256 as string,
            "preparation.evidenceSha256",
          )!;
    throw new DesktopInteractionRefusedBeforeDispatchError(
      reasonCode,
      evidenceSha256,
    );
  }

  if (raw.status !== "PREPARED") {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_STATUS_INVALID",
    );
  }

  const providerDescriptorSha256 = sha(
    raw.providerDescriptorSha256 as string,
    "preparation.providerDescriptorSha256",
  )!;
  const providerGenerationSha256 = sha(
    raw.providerGenerationSha256 as string,
    "preparation.providerGenerationSha256",
  )!;
  const implementationFingerprintSha256 = sha(
    raw.implementationFingerprintSha256 as string,
    "preparation.implementationFingerprintSha256",
  )!;

  if (
    providerDescriptorSha256 !==
      request.providerDescriptorSha256 ||
    providerGenerationSha256 !==
      request.providerGenerationSha256 ||
    implementationFingerprintSha256 !==
      request.implementationFingerprintSha256
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_IDENTITY_MISMATCH",
    );
  }

  const providerNonce = boundedId(
    raw.providerNonce as string,
    "preparation.providerNonce",
  );
  const resolvedTargetIdentitySha256 = sha(
    raw.resolvedTargetIdentitySha256 as string,
    "preparation.resolvedTargetIdentitySha256",
  )!;
  const preparedAtIso = canonicalIso(
    preparedAt.toISOString(),
    "preparedAt",
  );
  const expiresAt = canonicalIso(
    new Date(
      preparedAt.getTime() + request.requestedTtlMs,
    ).toISOString(),
    "expiresAt",
  );

  const core = Object.freeze({
    schemaVersion:
      "toadaid.desktop-interaction-preparation-ticket.v1" as const,
    preparationId: boundedId(
      `prep-${sha256({
        invocationId: request.invocationId,
        parametersSha256: request.parametersSha256,
        targetEvidenceSha256:
          request.targetEvidenceSha256,
        providerNonce,
        resolvedTargetIdentitySha256,
      }).slice(0, 32)}`,
      "preparationId",
    ),
    invocationId: request.invocationId,
    runId: request.runId,
    hostId: request.hostId,
    sessionId: request.sessionId,
    windowId: request.windowId,
    capabilityId: request.capabilityId,
    parametersSha256: request.parametersSha256,
    targetEvidenceSha256:
      request.targetEvidenceSha256,
    providerDescriptorSha256,
    providerGenerationSha256,
    implementationFingerprintSha256,
    providerNonce,
    resolvedTargetIdentitySha256,
    preparedAt: preparedAtIso,
    expiresAt,
  });

  return Object.freeze({
    ...core,
    ticketSha256: sha256(core),
  });
}

function assertDesktopInteractionPreparationCurrent(
  ticket: DesktopInteractionPreparationTicket,
  request: DesktopInteractionPreparationRequest,
  runtime: DesktopObservationHeadRuntime,
  now: Date,
): void {
  if (
    ticket.invocationId !== request.invocationId ||
    ticket.runId !== request.runId ||
    ticket.hostId !== request.hostId ||
    ticket.sessionId !== request.sessionId ||
    ticket.windowId !== request.windowId ||
    ticket.capabilityId !== request.capabilityId ||
    ticket.parametersSha256 !==
      request.parametersSha256 ||
    ticket.targetEvidenceSha256 !==
      request.targetEvidenceSha256 ||
    ticket.providerDescriptorSha256 !==
      request.providerDescriptorSha256 ||
    ticket.providerGenerationSha256 !==
      request.providerGenerationSha256 ||
    ticket.implementationFingerprintSha256 !==
      request.implementationFingerprintSha256
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_TICKET_BINDING_MISMATCH",
    );
  }

  const expectedSha256 = sha256({
    schemaVersion: ticket.schemaVersion,
    preparationId: ticket.preparationId,
    invocationId: ticket.invocationId,
    runId: ticket.runId,
    hostId: ticket.hostId,
    sessionId: ticket.sessionId,
    windowId: ticket.windowId,
    capabilityId: ticket.capabilityId,
    parametersSha256: ticket.parametersSha256,
    targetEvidenceSha256:
      ticket.targetEvidenceSha256,
    providerDescriptorSha256:
      ticket.providerDescriptorSha256,
    providerGenerationSha256:
      ticket.providerGenerationSha256,
    implementationFingerprintSha256:
      ticket.implementationFingerprintSha256,
    providerNonce: ticket.providerNonce,
    resolvedTargetIdentitySha256:
      ticket.resolvedTargetIdentitySha256,
    preparedAt: ticket.preparedAt,
    expiresAt: ticket.expiresAt,
  });
  if (expectedSha256 !== ticket.ticketSha256) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_TICKET_INTEGRITY_MISMATCH",
    );
  }

  const expiresAtMs = Date.parse(ticket.expiresAt);
  const preparedAtMs = Date.parse(ticket.preparedAt);
  if (
    !Number.isFinite(expiresAtMs) ||
    !Number.isFinite(preparedAtMs) ||
    expiresAtMs <= preparedAtMs ||
    expiresAtMs - preparedAtMs >
      MAX_PREPARATION_TTL_MS ||
    now.getTime() > expiresAtMs
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_EXPIRED",
    );
  }

  const currentProvider =
    runtime.resolveCurrentProviderIdentity({
      hostId: request.hostId,
      sessionId: request.sessionId,
    });
  if (
    currentProvider === null ||
    currentProvider.providerDescriptorSha256 !==
      ticket.providerDescriptorSha256 ||
    currentProvider.providerGenerationSha256 !==
      ticket.providerGenerationSha256
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PROVIDER_GENERATION_CHANGED",
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

function reservedCost(
  request: NormalizedDesktopInteractionRequest,
): RunBudgetVector {
  return Object.freeze({
    ...zeroCost(),
    toolCalls: 1,
    wallClockMs: request.maxWallClockMs,
  });
}

function claimInteractionPending(
  runtime: DesktopObservationHeadRuntime,
  receipt: DesktopObservationReceipt,
  interactionEpoch: string,
): void {
  const expected = Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-head.v1" as const,
    hostId: receipt.hostId,
    sessionId: receipt.sessionId,
    windowId: receipt.windowId!,
    observationEpoch: receipt.observationEpoch,
    providerDescriptorSha256: receipt.providerDescriptorSha256,
    providerGenerationSha256: receipt.providerGenerationSha256,
    evidenceNamespace: receipt.evidenceNamespace,
    status: "OK" as const,
    evidenceSha256: receipt.evidenceSha256!,
    receiptSha256: receipt.receiptSha256,
  });
  const pending = Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-head.v1" as const,
    hostId: receipt.hostId,
    sessionId: receipt.sessionId,
    windowId: receipt.windowId!,
    observationEpoch: interactionEpoch,
    providerDescriptorSha256: receipt.providerDescriptorSha256,
    providerGenerationSha256: receipt.providerGenerationSha256,
    evidenceNamespace: receipt.evidenceNamespace,
    status: "PENDING" as const,
    evidenceSha256: null,
    receiptSha256: null,
  });

  if (
    !runtime.claimCurrentObservationHead(
      expected,
      pending,
    )
  ) {
    throw new Error(
      "desktop interaction observation head changed before dispatch",
    );
  }

  const current =
    runtime.resolveCurrentObservationHead({
      hostId: pending.hostId,
      sessionId: pending.sessionId,
      windowId: pending.windowId,
    });
  if (
    current === null ||
    current.schemaVersion !== pending.schemaVersion ||
    current.hostId !== pending.hostId ||
    current.sessionId !== pending.sessionId ||
    current.windowId !== pending.windowId ||
    current.observationEpoch !==
      pending.observationEpoch ||
    current.providerDescriptorSha256 !== pending.providerDescriptorSha256 ||
    current.providerGenerationSha256 !== pending.providerGenerationSha256 ||
    current.evidenceNamespace !== pending.evidenceNamespace ||
    current.status !== "PENDING" ||
    current.evidenceSha256 !== null ||
    current.receiptSha256 !== null
  ) {
    throw new Error(
      "desktop interaction PENDING head was not published as current",
    );
  }
}

function normalizeResultingObservation(
  value: DesktopInteractionObservationReference | null | undefined,
  hostId: string,
  sessionId: string,
  windowId: string,
  runtime: DesktopObservationHeadRuntime,
): DesktopInteractionObservationReference | null {
  if (value == null) return null;
  const raw = objectValue(
    value,
    "resultingObservation",
  );
  const normalized = Object.freeze({
    observationEpoch: boundedId(
      raw.observationEpoch as string,
      "resultingObservation.observationEpoch",
    ),
    evidenceSha256:
      sha(
        raw.evidenceSha256 as string,
        "resultingObservation.evidenceSha256",
      )!,
    receiptSha256:
      sha(
        raw.receiptSha256 as string,
        "resultingObservation.receiptSha256",
      )!,
  });
  const current =
    runtime.resolveCurrentObservationHead({
      hostId,
      sessionId,
      windowId,
    });
  const currentProvider = runtime.resolveCurrentProviderIdentity({ hostId, sessionId });
  if (
    current === null ||
    current.schemaVersion !==
      "toadaid.desktop-observation-head.v1" ||
    current.status !== "OK" ||
    current.hostId !== hostId ||
    current.sessionId !== sessionId ||
    current.windowId !== windowId ||
    currentProvider === null ||
    current.providerDescriptorSha256 !== currentProvider.providerDescriptorSha256 ||
    current.providerGenerationSha256 !== currentProvider.providerGenerationSha256 ||
    current.evidenceNamespace !== currentProvider.evidenceNamespace ||
    current.observationEpoch !==
      normalized.observationEpoch ||
    current.evidenceSha256 !==
      normalized.evidenceSha256 ||
    current.receiptSha256 !==
      normalized.receiptSha256
  ) {
    throw new Error(
      "desktop interaction resulting observation is not current governed P16 evidence",
    );
  }
  return normalized;
}

function normalizeAdapterResult(
  value: DesktopInteractionAdapterResult,
  request: DesktopInteractionAdapterRequest,
  runtime: DesktopObservationHeadRuntime,
): DesktopInteractionAdapterResult {
  const raw = objectValue(
    value,
    "desktop interaction adapter result",
  );
  if (
    raw.schemaVersion !==
    "toadaid.desktop-interaction-adapter-result.v1"
  ) {
    throw new TypeError(
      "unsupported desktop interaction adapter result schemaVersion",
    );
  }
  if (
    sha(
      raw.preparationTicketSha256 as string,
      "preparationTicketSha256",
    ) !== request.preparationTicket.ticketSha256
  ) {
    throw new Error(
      "desktop interaction adapter result preparation ticket mismatch",
    );
  }
  if (
    boundedId(
      raw.interactionEpoch as string,
      "interactionEpoch",
    ) !== request.interactionEpoch ||
    boundedId(raw.hostId as string, "hostId") !==
      request.hostId ||
    boundedId(raw.sessionId as string, "sessionId") !==
      request.sessionId ||
    boundedId(raw.windowId as string, "windowId") !==
      request.windowId
  ) {
    throw new Error(
      "desktop interaction adapter result identity mismatch",
    );
  }
  const adapterEvidenceSha256 =
    sha(
      raw.evidenceSha256 as string,
      "evidenceSha256",
    )!;
  const resultingObservation =
    normalizeResultingObservation(
      raw.resultingObservation as
        | DesktopInteractionObservationReference
        | null
        | undefined,
      request.hostId,
      request.sessionId,
      request.windowId,
      runtime,
    );
  const evidenceSha256 = sha256({
    adapterEvidenceSha256,
    preparationTicketSha256:
      request.preparationTicket.ticketSha256,
    interactionEpoch: request.interactionEpoch,
    parametersSha256: request.parametersSha256,
    targetEvidenceSha256:
      request.targetEvidenceSha256,
    hostId: request.hostId,
    sessionId: request.sessionId,
    windowId: request.windowId,
    resultingObservation,
  });
  return Object.freeze({
    schemaVersion:
      "toadaid.desktop-interaction-adapter-result.v1",
    preparationTicketSha256:
      request.preparationTicket.ticketSha256,
    interactionEpoch: request.interactionEpoch,
    hostId: request.hostId,
    sessionId: request.sessionId,
    windowId: request.windowId,
    evidenceSha256,
    resultingObservation,
  });
}

function receiptSha256(
  receipt: Omit<
    DesktopInteractionReceipt,
    "receiptSha256"
  >,
): string {
  return sha256(receipt);
}

function errorClass(error: unknown): string {
  if (
    error instanceof Error &&
    error.name.length > 0 &&
    error.name.length <= 128
  ) {
    return error.name;
  }
  return "DesktopInteractionError";
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

export async function interactGovernedDesktop(
  adapter: GovernedDesktopInteractionAdapter,
  input: GovernedDesktopInteractionInput,
  runtime: DesktopInteractionRuntime = {},
): Promise<GovernedDesktopInteractionOutcome> {
  const normalized =
    normalizeDesktopInteractionRequest(
      input.request,
    );
  const parametersSha256 = sha256(normalized);
  const registration =
    normalizeDesktopInteractionAdapterRegistration(
      adapter.registration,
    );

  if (
    typeof adapter.prepare !== "function" ||
    typeof adapter.dispatch !== "function"
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "P17B_PREPARED_DISPATCH_ADAPTER_REQUIRED",
    );
  }

  const leaseBinding =
    assertHostConnectorSessionLeaseUsable(
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
    assertC1H1Binding(
      input,
      normalized,
      registration,
    );
  assertCurrentCapabilityInvocationHead(
    input.invocationHeadRuntime,
    invocation,
  );
  const fence = assertReplayFence(
    input.replayFence,
    invocation,
  );

  const now = (
    runtime.now ?? (() => new Date())
  )();
  if (
    !(now instanceof Date) ||
    Number.isNaN(now.getTime())
  ) {
    throw new TypeError(
      "desktop interaction runtime now is invalid",
    );
  }

  const observation =
    assertObservationBinding(
      normalized,
      input.observationRequest,
      input.observationReceipt,
      input.observationHeadRuntime,
      now,
    );
  const targetSha256 = targetEvidenceSha256(
    normalized,
    observation,
    input.observationReceipt,
    input.observationHeadRuntime,
  );

  const budgetBefore =
    validateRunBudgetLedgerEnvelope(input.budget);
  if (
    budgetBefore.record.runId !==
    invocation.record.runId
  ) {
    throw new Error(
      "desktop interaction Q1 budget runId mismatch",
    );
  }
  const cost = reservedCost(normalized);
  const availabilityBeforePreparation =
    evaluateRunBudgetAvailability(
      budgetBefore,
      cost,
    );
  if (!availabilityBeforePreparation.allowed) {
    throw new RangeError(
      `desktop interaction run budget exceeded: ${availabilityBeforePreparation.exceededMetrics.join(",")}`,
    );
  }

  const currentProvider =
    input.observationHeadRuntime
      .resolveCurrentProviderIdentity({
        hostId: normalized.hostId,
        sessionId: normalized.sessionId,
      });
  if (
    currentProvider === null ||
    currentProvider.providerDescriptorSha256 !==
      input.observationReceipt
        .providerDescriptorSha256 ||
    currentProvider.providerDescriptorSha256 !==
      binding.providerDescriptorSha256 ||
    currentProvider.providerGenerationSha256 !==
      input.observationReceipt
        .providerGenerationSha256
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PROVIDER_GENERATION_CHANGED",
    );
  }

  const preparationRequest:
    DesktopInteractionPreparationRequest =
    Object.freeze({
      schemaVersion:
        "toadaid.desktop-interaction-prepare-request.v1",
      invocationId: invocation.record.invocationId,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      windowId:
        input.observationReceipt.windowId!,
      capabilityId: normalized.capabilityId,
      toolName: normalized.toolName,
      parametersSha256,
      targetEvidenceSha256: targetSha256,
      providerDescriptorSha256:
        binding.providerDescriptorSha256,
      providerGenerationSha256:
        currentProvider.providerGenerationSha256,
      implementationFingerprintSha256:
        binding.implementationFingerprintSha256,
      requestedTtlMs: Math.min(
        MAX_PREPARATION_TTL_MS,
        normalized.maxWallClockMs,
      ),
      kind: normalized.kind,
      target: normalized.target,
    });

  let preparationResult:
    DesktopInteractionPreparationResult;
  try {
    preparationResult =
      await adapter.prepare(preparationRequest);
  } catch (error) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_FAILED",
      errorFingerprint(error),
    );
  }

  const preparedAt = (
    runtime.now ?? (() => new Date())
  )();
  if (
    !(preparedAt instanceof Date) ||
    Number.isNaN(preparedAt.getTime())
  ) {
    throw new TypeError(
      "desktop interaction preparation time is invalid",
    );
  }

  let preparationTicket:
    DesktopInteractionPreparationTicket;
  try {
    preparationTicket =
      buildDesktopInteractionPreparationTicket(
        preparationResult,
        preparationRequest,
        preparedAt,
      );
  } catch (error) {
    if (
      error instanceof
      DesktopInteractionRefusedBeforeDispatchError
    ) {
      throw error;
    }
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "PREPARATION_RESULT_INVALID",
      errorFingerprint(error),
    );
  }

  const dispatchNow = (
    runtime.now ?? (() => new Date())
  )();
  if (
    !(dispatchNow instanceof Date) ||
    Number.isNaN(dispatchNow.getTime())
  ) {
    throw new TypeError(
      "desktop interaction dispatch time is invalid",
    );
  }
  if (
    dispatchNow.getTime() <
    Date.parse(invocation.record.updatedAt)
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "H1_TIME_REGRESSION",
    );
  }

  assertDesktopInteractionPreparationCurrent(
    preparationTicket,
    preparationRequest,
    input.observationHeadRuntime,
    dispatchNow,
  );

  const dispatchObservation =
    assertObservationBinding(
      normalized,
      input.observationRequest,
      input.observationReceipt,
      input.observationHeadRuntime,
      dispatchNow,
    );
  const dispatchTargetSha256 =
    targetEvidenceSha256(
      normalized,
      dispatchObservation,
      input.observationReceipt,
      input.observationHeadRuntime,
    );
  if (
    dispatchTargetSha256 !==
    preparationTicket.targetEvidenceSha256
  ) {
    throw new DesktopInteractionRefusedBeforeDispatchError(
      "TARGET_EVIDENCE_CHANGED",
    );
  }

  const availabilityAtDispatch =
    evaluateRunBudgetAvailability(
      budgetBefore,
      cost,
    );
  if (!availabilityAtDispatch.allowed) {
    throw new RangeError(
      `desktop interaction run budget exceeded before dispatch: ${availabilityAtDispatch.exceededMetrics.join(",")}`,
    );
  }

  const interactionEpoch = boundedId(
    (runtime.randomId ?? randomUUID)(),
    "interactionEpoch",
  );
  const dispatchedAt = canonicalIso(
    dispatchNow.toISOString(),
    "dispatchedAt",
  );
  const reconciliationId = boundedId(
    `recon-${sha256({
      invocationRecordSha256: invocation.recordSha256,
      interactionEpoch,
    }).slice(0, 32)}`,
    "reconciliationId",
  );

  // Read-only provider preparation is over. Mutation can begin only after the
  // exact P16 head is atomically claimed.
  claimInteractionPending(
    input.observationHeadRuntime,
    input.observationReceipt,
    interactionEpoch,
  );

  // Q1 mutation usage is recorded at the dispatch boundary, not when provider
  // preparation begins.
  const budgetAfter = recordRunBudgetUsage(
    budgetBefore,
    {
      receiptId: boundedId(
        `desktop-action-${sha256({
          invocationId:
            invocation.record.invocationId,
          interactionEpoch,
        }).slice(0, 32)}`,
        "receiptId",
      ),
      kind: "TOOL",
      occurredAt: dispatchedAt,
      invocationId:
        invocation.record.invocationId,
      sourceSha256: parametersSha256,
      delta: cost,
    },
    {
      ...(runtime.now
        ? { now: runtime.now }
        : {}),
      ...(runtime.randomId
        ? { randomId: runtime.randomId }
        : {}),
    },
  );

  const adapterRequest:
    DesktopInteractionAdapterRequest =
    Object.freeze({
      schemaVersion:
        "toadaid.desktop-interaction-adapter-request.v1",
      preparationTicket,
      invocationId:
        invocation.record.invocationId,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      windowId:
        input.observationReceipt.windowId!,
      capabilityId: normalized.capabilityId,
      toolName: normalized.toolName,
      interactionEpoch,
      parametersSha256,
      targetEvidenceSha256: targetSha256,
      maxWallClockMs:
        normalized.maxWallClockMs,
      parameters: normalized,
    });

  const registrationSha256 =
    desktopInteractionAdapterRegistrationSha256(
      registration,
    );
  const actionSha256 =
    actionParametersSha256(normalized);

  // Only a failure after dispatch begins is an uncertain external mutation.
  try {
    const result = normalizeAdapterResult(
      await adapter.dispatch(adapterRequest),
      adapterRequest,
      input.observationHeadRuntime,
    );
    const core = Object.freeze({
      schemaVersion:
        "toadaid.desktop-interaction-receipt.v1" as const,
      status: "OK" as const,
      capabilityId: normalized.capabilityId,
      invocationId:
        invocation.record.invocationId,
      invocationRecordSha256:
        invocation.recordSha256,
      intentSha256:
        invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      windowId:
        input.observationReceipt.windowId!,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256:
        binding.bindingSha256,
      descriptorSha256:
        compatibility.descriptorSha256,
      adapterRegistrationSha256:
        registrationSha256,
      replayFenceSha256:
        fence.recordSha256,
      interactionEpoch,
      observationReceiptSha256:
        input.observationReceipt.receiptSha256,
      targetEvidenceSha256: targetSha256,
      preparationTicketSha256:
        preparationTicket.ticketSha256,
      parametersSha256,
      actionParametersSha256: actionSha256,
      dispatchedAt,
      resultEvidenceSha256:
        result.evidenceSha256,
      resultingObservation:
        result.resultingObservation ?? null,
      reconciliationSha256: null,
      budget: Object.freeze({
        ledgerSha256Before:
          budgetBefore.recordSha256,
        ledgerSha256After:
          budgetAfter.recordSha256,
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
    const opened =
      beginCapabilityInvocationReconciliation(
        fence,
        invocation,
        {
          reconciliationId,
          reasonCode:
            "DESKTOP_INTERACTION_UNCERTAIN",
          evidenceRefs: [
            {
              id: "desktop-target",
              sha256: targetSha256,
            },
            {
              id: "desktop-preparation",
              sha256:
                preparationTicket.ticketSha256,
            },
          ],
          openedAt: dispatchedAt,
        },
        {
          ...(runtime.now
            ? { now: runtime.now }
            : {}),
          ...(runtime.randomId
            ? { randomId: runtime.randomId }
            : {}),
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
      schemaVersion:
        "toadaid.desktop-interaction-receipt.v1" as const,
      status:
        "RECONCILIATION_REQUIRED" as const,
      capabilityId: normalized.capabilityId,
      invocationId:
        invocation.record.invocationId,
      invocationRecordSha256:
        lockedInvocation.recordSha256,
      intentSha256:
        invocation.record.request.intentSha256,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      windowId:
        input.observationReceipt.windowId!,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256:
        binding.bindingSha256,
      descriptorSha256:
        compatibility.descriptorSha256,
      adapterRegistrationSha256:
        registrationSha256,
      replayFenceSha256:
        fence.recordSha256,
      interactionEpoch,
      observationReceiptSha256:
        input.observationReceipt.receiptSha256,
      targetEvidenceSha256: targetSha256,
      preparationTicketSha256:
        preparationTicket.ticketSha256,
      parametersSha256,
      actionParametersSha256: actionSha256,
      dispatchedAt,
      resultEvidenceSha256: null,
      resultingObservation: null,
      reconciliationSha256:
        reconciliation.recordSha256,
      budget: Object.freeze({
        ledgerSha256Before:
          budgetBefore.recordSha256,
        ledgerSha256After:
          budgetAfter.recordSha256,
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
}
