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
  evaluateRunBudgetAvailability,
  recordRunBudgetUsage,
  validateRunBudgetLedgerEnvelope,
} from "./runBudgetLedger.js";
import type {
  DesktopObservationAdapterRegistration,
  DesktopObservationAdapterRequest,
  DesktopObservationAdapterResult,
  DesktopObservationArtifactReference,
  DesktopObservationCapabilityId,
  DesktopObservationElementEvidence,
  DesktopObservationHead,
  DesktopObservationHeadRuntime,
  DesktopObservationKind,
  DesktopObservationReceipt,
  DesktopObservationRegion,
  DesktopObservationRequest,
  DesktopObservedElementReference,
  DesktopWaitForCondition,
  GovernedDesktopObservationAdapter,
  GovernedDesktopObservationInput,
  GovernedDesktopObservationOutcome,
  NormalizedDesktopObservationRequest,
  DesktopObservationRuntime,
} from "./desktopObservationTypes.js";
import type {
  RunBudgetVector,
} from "./runBudgetTypes.js";

export type * from "./desktopObservationTypes.js";

export const DESKTOP_OBSERVATION_CAPABILITIES:
  readonly DesktopObservationCapabilityId[] = Object.freeze([
    "host:display-inventory",
    "host:screenshot",
    "host:ui-snapshot",
    "host:wait-for",
  ]);

export const DESKTOP_OBSERVATION_CONTRACT_IDS:
  Readonly<Record<DesktopObservationCapabilityId, string>> =
  Object.freeze({
    "host:display-inventory":
      "toadaid.host.display-inventory",
    "host:screenshot":
      "toadaid.host.screenshot",
    "host:ui-snapshot":
      "toadaid.host.ui-snapshot",
    "host:wait-for":
      "toadaid.host.wait-for",
  });

export const DESKTOP_OBSERVATION_TOOL_NAMES:
  Readonly<Record<DesktopObservationCapabilityId, string>> =
  Object.freeze({
    "host:display-inventory":
      "desktop.display-inventory",
    "host:screenshot":
      "desktop.screenshot",
    "host:ui-snapshot":
      "desktop.ui-snapshot",
    "host:wait-for":
      "desktop.wait-for",
  });

const CONTRACT_ID_PATTERN =
  /^[a-z][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/;
const CAPABILITY_SET = new Set<string>(
  DESKTOP_OBSERVATION_CAPABILITIES,
);
const MAX_DISPLAYS = 8;
const MAX_DISPLAY_INDEX = 31;
const MAX_COORDINATE = 100_000;
const MAX_ARTIFACTS = 16;
const MAX_ELEMENTS = 256;
const DEFAULT_MAX_ELEMENTS = 128;
const DEFAULT_CAPTURE_TIMEOUT_MS = 10_000;
const MAX_CAPTURE_TIMEOUT_MS = 30_000;
const DEFAULT_WAIT_TIMEOUT_MS = 10_000;
const MAX_WAIT_TIMEOUT_MS = 120_000;
const DEFAULT_WAIT_INTERVAL_MS = 250;
const MAX_WAIT_INTERVAL_MS = 5_000;

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

function booleanValue(
  value: boolean | undefined,
  fallback: boolean,
  label: string,
): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new TypeError(`${label} must be boolean`);
  }
  return value;
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

function normalizeCapability(
  value: string,
): DesktopObservationCapabilityId {
  const normalized = capabilityId(value);
  if (!CAPABILITY_SET.has(normalized)) {
    throw new TypeError(
      `unsupported desktop observation capability: ${normalized}`,
    );
  }
  return normalized as DesktopObservationCapabilityId;
}

function capabilityForKind(
  kind: DesktopObservationKind,
): DesktopObservationCapabilityId {
  switch (kind) {
    case "DISPLAY_INVENTORY":
      return "host:display-inventory";
    case "SCREENSHOT":
      return "host:screenshot";
    case "UI_SNAPSHOT":
      return "host:ui-snapshot";
    case "WAIT_FOR":
      return "host:wait-for";
  }
}

function normalizeDisplayIds(
  values: readonly number[] | undefined,
): readonly number[] {
  const input = values ?? [];
  if (!Array.isArray(input) || input.length > MAX_DISPLAYS) {
    throw new RangeError(
      `displayIds exceeds ${MAX_DISPLAYS} entries`,
    );
  }
  const seen = new Set<number>();
  const normalized = input.map((value, index) => {
    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value > MAX_DISPLAY_INDEX
    ) {
      throw new RangeError(
        `displayIds[${index}] must be an integer in [0, ${MAX_DISPLAY_INDEX}]`,
      );
    }
    if (seen.has(value)) {
      throw new TypeError(
        `duplicate display id: ${value}`,
      );
    }
    seen.add(value);
    return value;
  });
  normalized.sort((a, b) => a - b);
  return Object.freeze(normalized);
}

function normalizeRegion(
  value: DesktopObservationRegion | undefined,
): DesktopObservationRegion | null {
  if (value === undefined) return null;
  const raw = objectValue(value, "region");
  const coordinates = [
    raw.left,
    raw.top,
    raw.right,
    raw.bottom,
  ];
  if (
    coordinates.some(
      (coordinate) =>
        !Number.isSafeInteger(coordinate) ||
        Math.abs(coordinate as number) > MAX_COORDINATE,
    )
  ) {
    throw new RangeError(
      `region coordinates must be safe integers within ±${MAX_COORDINATE}`,
    );
  }
  const left = raw.left as number;
  const top = raw.top as number;
  const right = raw.right as number;
  const bottom = raw.bottom as number;
  if (right <= left || bottom <= top) {
    throw new RangeError(
      "region right/bottom must exceed left/top",
    );
  }
  return Object.freeze({ left, top, right, bottom });
}

function normalizeScope(
  request: DesktopObservationRequest,
): {
  readonly displayIds: readonly number[];
  readonly region: DesktopObservationRegion | null;
} {
  const scope =
    request.kind === "SCREENSHOT" ||
    request.kind === "UI_SNAPSHOT"
      ? request.scope
      : undefined;
  const displayIds = normalizeDisplayIds(scope?.displayIds);
  const region = normalizeRegion(scope?.region);
  if (displayIds.length > 0 && region !== null) {
    throw new Error(
      "desktop observation scope must choose displayIds or region, not both",
    );
  }
  return { displayIds, region };
}

function normalizeWaitCondition(
  value: DesktopWaitForCondition,
): DesktopWaitForCondition {
  const allowed = new Set<DesktopWaitForCondition>([
    "text_exists",
    "active_window",
    "element_exists",
    "element_enabled",
    "focused_element",
  ]);
  if (!allowed.has(value)) {
    throw new TypeError(
      "unsupported desktop wait-for condition",
    );
  }
  return value;
}

export function normalizeDesktopObservationRequest(
  request: DesktopObservationRequest,
): NormalizedDesktopObservationRequest {
  const hostId = boundedId(request.hostId, "hostId");
  const sessionId = boundedId(
    request.sessionId,
    "sessionId",
  );
  const ownerId = boundedId(request.ownerId, "ownerId");
  const capabilityId = capabilityForKind(request.kind);
  const tool = DESKTOP_OBSERVATION_TOOL_NAMES[capabilityId];
  const { displayIds, region } = normalizeScope(request);

  if (request.kind === "DISPLAY_INVENTORY") {
    return Object.freeze({
      kind: request.kind,
      capabilityId,
      toolName: tool,
      hostId,
      sessionId,
      ownerId,
      displayIds: Object.freeze([]),
      region: null,
      windowId: null,
      annotate: false,
      includeScreenshot: false,
      useDom: false,
      maxElements: 0,
      condition: null,
      text: null,
      timeoutMs: 0,
      intervalMs: 0,
      maxWallClockMs: boundedPositiveInteger(
        request.maxWallClockMs,
        DEFAULT_CAPTURE_TIMEOUT_MS,
        MAX_CAPTURE_TIMEOUT_MS,
        "maxWallClockMs",
      ),
    });
  }

  if (request.kind === "SCREENSHOT") {
    if (displayIds.length === 0 && region === null) {
      throw new Error(
        "screenshot requires explicit displayIds or bounded region",
      );
    }
    return Object.freeze({
      kind: request.kind,
      capabilityId,
      toolName: tool,
      hostId,
      sessionId,
      ownerId,
      displayIds,
      region,
      windowId: null,
      annotate: booleanValue(
        request.annotate,
        false,
        "annotate",
      ),
      includeScreenshot: true,
      useDom: false,
      maxElements: 0,
      condition: null,
      text: null,
      timeoutMs: 0,
      intervalMs: 0,
      maxWallClockMs: boundedPositiveInteger(
        request.maxWallClockMs,
        DEFAULT_CAPTURE_TIMEOUT_MS,
        MAX_CAPTURE_TIMEOUT_MS,
        "maxWallClockMs",
      ),
    });
  }

  if (request.kind === "UI_SNAPSHOT") {
    const windowId =
      request.windowId === undefined
        ? null
        : boundedId(request.windowId, "windowId");
    if (
      displayIds.length === 0 &&
      region === null &&
      windowId === null
    ) {
      throw new Error(
        "ui snapshot requires explicit displayIds, region, or windowId",
      );
    }
    return Object.freeze({
      kind: request.kind,
      capabilityId,
      toolName: tool,
      hostId,
      sessionId,
      ownerId,
      displayIds,
      region,
      windowId,
      annotate: false,
      includeScreenshot: booleanValue(
        request.includeScreenshot,
        false,
        "includeScreenshot",
      ),
      useDom: booleanValue(
        request.useDom,
        false,
        "useDom",
      ),
      maxElements: boundedPositiveInteger(
        request.maxElements,
        DEFAULT_MAX_ELEMENTS,
        MAX_ELEMENTS,
        "maxElements",
      ),
      condition: null,
      text: null,
      timeoutMs: 0,
      intervalMs: 0,
      maxWallClockMs: boundedPositiveInteger(
        request.maxWallClockMs,
        DEFAULT_CAPTURE_TIMEOUT_MS,
        MAX_CAPTURE_TIMEOUT_MS,
        "maxWallClockMs",
      ),
    });
  }

  const windowId = boundedId(
    request.windowId,
    "windowId",
  );
  const condition = normalizeWaitCondition(
    request.condition,
  );
  const text =
    request.text === undefined
      ? null
      : (() => {
          if (
            typeof request.text !== "string" ||
            request.text.length < 1 ||
            request.text.length > 2_048 ||
            /[\u0000]/.test(request.text)
          ) {
            throw new TypeError(
              "wait-for text is invalid",
            );
          }
          return request.text;
        })();
  if (
    condition === "text_exists" &&
    text === null
  ) {
    throw new Error(
      "text_exists requires text",
    );
  }
  const timeoutMs = boundedPositiveInteger(
    request.timeoutMs,
    DEFAULT_WAIT_TIMEOUT_MS,
    MAX_WAIT_TIMEOUT_MS,
    "timeoutMs",
  );
  const intervalMs = boundedPositiveInteger(
    request.intervalMs,
    DEFAULT_WAIT_INTERVAL_MS,
    MAX_WAIT_INTERVAL_MS,
    "intervalMs",
  );
  if (intervalMs > timeoutMs) {
    throw new RangeError(
      "wait-for intervalMs cannot exceed timeoutMs",
    );
  }
  return Object.freeze({
    kind: request.kind,
    capabilityId,
    toolName: tool,
    hostId,
    sessionId,
    ownerId,
    displayIds: Object.freeze([]),
    region: null,
    windowId,
    annotate: false,
    includeScreenshot: false,
    useDom: booleanValue(
      request.useDom,
      false,
      "useDom",
    ),
    maxElements: MAX_ELEMENTS,
    condition,
    text,
    timeoutMs,
    intervalMs,
    maxWallClockMs: timeoutMs,
  });
}

export function desktopObservationParametersSha256(
  request: DesktopObservationRequest,
): string {
  return sha256(
    normalizeDesktopObservationRequest(request),
  );
}

export function normalizeDesktopObservationAdapterRegistration(
  value: DesktopObservationAdapterRegistration,
): DesktopObservationAdapterRegistration {
  if (
    value.schemaVersion !==
    "toadaid.desktop-observation-adapter-registration.v1"
  ) {
    throw new TypeError(
      "unsupported desktop observation adapter registration schemaVersion",
    );
  }
  const capability = normalizeCapability(
    value.capabilityId,
  );
  const normalizedTool = toolName(value.toolName);
  if (
    normalizedTool !==
    DESKTOP_OBSERVATION_TOOL_NAMES[capability]
  ) {
    throw new Error(
      "desktop observation adapter toolName does not match capability",
    );
  }
  if (
    typeof value.contractId !== "string" ||
    !CONTRACT_ID_PATTERN.test(value.contractId)
  ) {
    throw new TypeError(
      "desktop observation adapter contractId is invalid",
    );
  }
  if (
    value.contractId !==
    DESKTOP_OBSERVATION_CONTRACT_IDS[capability]
  ) {
    throw new Error(
      "desktop observation adapter contractId does not match capability",
    );
  }

  return Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-adapter-registration.v1",
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

export function desktopObservationAdapterRegistrationSha256(
  value: DesktopObservationAdapterRegistration,
): string {
  return sha256(normalizeDesktopObservationAdapterRegistration(value));
}

function assertC1H1Binding(
  input: GovernedDesktopObservationInput,
  normalized: NormalizedDesktopObservationRequest,
  registration: DesktopObservationAdapterRegistration,
): {
  readonly invocation: ReturnType<
    typeof validateCapabilityInvocationEnvelope
  >;
  readonly binding: ReturnType<
    typeof validateCapabilityInvocationContractBinding
  >;
  readonly compatibility: ReturnType<
    typeof assertCapabilityContractCompatible
  >;
} {
  const invocation =
    validateCapabilityInvocationEnvelope(
      input.invocation,
    );
  if (invocation.record.status !== "STARTED") {
    throw new Error(
      "desktop observation requires STARTED H1 invocation",
    );
  }
  if (
    invocation.record.capabilityId !==
      normalized.capabilityId ||
    invocation.record.toolName !==
      normalized.toolName
  ) {
    throw new Error(
      "desktop observation H1 capability/tool identity mismatch",
    );
  }

  const parametersSha256 = sha256(normalized);
  if (
    invocation.record.request.argumentsSha256 !==
    parametersSha256
  ) {
    throw new Error(
      "desktop observation parameters do not match H1 argumentsSha256",
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
      "desktop observation C1 capability mismatch",
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
      "desktop observation C1 binding is stale or mismatched",
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
    ready.compatibility.implementationFingerprintSha256 !==
      compatibility.implementationFingerprintSha256
  ) {
    throw new Error(
      "desktop observation contract-ready receipt is stale or mismatched",
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
    registration.implementationFingerprintSha256 !==
      compatibility.implementationFingerprintSha256
  ) {
    throw new Error(
      "desktop observation adapter registration does not match current C1 truth",
    );
  }

  return { invocation, binding, compatibility };
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
  request: NormalizedDesktopObservationRequest,
): RunBudgetVector {
  return Object.freeze({
    ...zeroCost(),
    toolCalls: 1,
    wallClockMs: request.maxWallClockMs,
  });
}

function normalizeArtifactReferences(
  values: readonly DesktopObservationArtifactReference[],
): readonly DesktopObservationArtifactReference[] {
  if (
    !Array.isArray(values) ||
    values.length > MAX_ARTIFACTS
  ) {
    throw new RangeError(
      `desktop observation artifacts exceed ${MAX_ARTIFACTS}`,
    );
  }
  const seen = new Set<string>();
  const allowedKinds = new Set([
    "DISPLAY_INVENTORY",
    "SCREENSHOT",
    "UI_TREE",
    "DOM",
    "WAIT_RESULT",
  ]);
  const normalized = values.map((value, index) => {
    const raw = objectValue(
      value,
      `artifacts[${index}]`,
    );
    const id = boundedId(
      raw.id as string,
      `artifacts[${index}].id`,
    );
    if (seen.has(id)) {
      throw new TypeError(
        `duplicate desktop observation artifact: ${id}`,
      );
    }
    seen.add(id);
    if (!allowedKinds.has(raw.kind as string)) {
      throw new TypeError(
        `artifacts[${index}].kind is invalid`,
      );
    }
    return Object.freeze({
      id,
      kind:
        raw.kind as DesktopObservationArtifactReference["kind"],
      sha256:
        sha(
          raw.sha256 as string,
          `artifacts[${index}].sha256`,
        )!,
    });
  });
  normalized.sort((a, b) =>
    a.id.localeCompare(b.id),
  );
  return Object.freeze(normalized);
}

function normalizeElementEvidence(
  values: readonly DesktopObservationElementEvidence[]
    | undefined,
  maxElements: number,
): readonly DesktopObservationElementEvidence[] {
  const input = values ?? [];
  if (
    !Array.isArray(input) ||
    input.length > maxElements
  ) {
    throw new RangeError(
      `desktop observation elements exceed ${maxElements}`,
    );
  }
  const seen = new Set<string>();
  const normalized = input.map((value, index) => {
    const raw = objectValue(
      value,
      `elements[${index}]`,
    );
    const elementId = boundedId(
      raw.elementId as string,
      `elements[${index}].elementId`,
    );
    if (seen.has(elementId)) {
      throw new TypeError(
        `duplicate desktop observation element: ${elementId}`,
      );
    }
    seen.add(elementId);
    const inputSecurity = raw.inputSecurity;
    if (
      inputSecurity !== "ORDINARY_TEXT" &&
      inputSecurity !== "SECRET_OR_PASSWORD" &&
      inputSecurity !== "UNKNOWN"
    ) {
      throw new TypeError(
        `elements[${index}].inputSecurity is invalid`,
      );
    }
    return Object.freeze({
      elementId,
      evidenceSha256:
        sha(
          raw.evidenceSha256 as string,
          `elements[${index}].evidenceSha256`,
        )!,
      inputSecurity,
    });
  });
  normalized.sort((a, b) =>
    a.elementId.localeCompare(b.elementId),
  );
  return Object.freeze(normalized);
}

function normalizeAdapterResult(
  value: DesktopObservationAdapterResult,
  request: DesktopObservationAdapterRequest,
): DesktopObservationAdapterResult {
  const raw = objectValue(
    value,
    "desktop observation adapter result",
  );
  if (
    raw.schemaVersion !==
    "toadaid.desktop-observation-adapter-result.v1"
  ) {
    throw new TypeError(
      "unsupported desktop observation adapter result schemaVersion",
    );
  }
  if (
    boundedId(
      raw.observationEpoch as string,
      "observationEpoch",
    ) !== request.observationEpoch ||
    boundedId(raw.hostId as string, "hostId") !==
      request.hostId ||
    boundedId(raw.sessionId as string, "sessionId") !==
      request.sessionId
  ) {
    throw new Error(
      "desktop observation adapter result identity mismatch",
    );
  }

  const displayIds = normalizeDisplayIds(
    raw.displayIds as readonly number[],
  );
  const windowId =
    raw.windowId === null
      ? null
      : boundedId(raw.windowId as string, "windowId");
  if (
    request.parameters.windowId !== null &&
    windowId !== request.parameters.windowId
  ) {
    throw new Error(
      "desktop observation adapter window identity mismatch",
    );
  }
  if (
    request.parameters.displayIds.length > 0 &&
    JSON.stringify(displayIds) !==
      JSON.stringify(request.parameters.displayIds)
  ) {
    throw new Error(
      "desktop observation adapter display identity mismatch",
    );
  }

  const adapterEvidenceSha256 =
    sha(
      raw.evidenceSha256 as string,
      "evidenceSha256",
    )!;
  const artifacts = normalizeArtifactReferences(
    raw.artifacts as readonly DesktopObservationArtifactReference[],
  );
  const elements = normalizeElementEvidence(
    raw.elements as
      | readonly DesktopObservationElementEvidence[]
      | undefined,
    request.parameters.maxElements,
  );

  const artifactKinds = new Set(
    artifacts.map((artifact) => artifact.kind),
  );
  if (artifacts.length === 0) {
    throw new Error(
      "desktop observation adapter result must include evidence artifacts",
    );
  }

  if (request.parameters.kind === "DISPLAY_INVENTORY") {
    if (
      artifactKinds.size !== 1 ||
      !artifactKinds.has("DISPLAY_INVENTORY")
    ) {
      throw new Error(
        "desktop observation adapter result artifact kind mismatch for display inventory",
      );
    }
  } else if (request.parameters.kind === "SCREENSHOT") {
    if (
      artifactKinds.size !== 1 ||
      !artifactKinds.has("SCREENSHOT")
    ) {
      throw new Error(
        "desktop observation adapter result artifact kind mismatch for screenshot",
      );
    }
  } else if (request.parameters.kind === "UI_SNAPSHOT") {
    const allowedKinds = new Set([
      "UI_TREE",
      "DOM",
      "SCREENSHOT",
    ]);
    if (
      artifacts.some(
        (artifact) => !allowedKinds.has(artifact.kind),
      )
    ) {
      throw new Error(
        "desktop observation adapter result artifact kind mismatch for ui snapshot",
      );
    }
    if (
      request.parameters.useDom &&
      !artifactKinds.has("DOM")
    ) {
      throw new Error(
        "desktop observation adapter result missing requested DOM artifact",
      );
    }
    if (
      !request.parameters.useDom &&
      !artifactKinds.has("UI_TREE")
    ) {
      throw new Error(
        "desktop observation adapter result missing UI tree artifact",
      );
    }
    if (
      request.parameters.includeScreenshot &&
      !artifactKinds.has("SCREENSHOT")
    ) {
      throw new Error(
        "desktop observation adapter result missing requested screenshot artifact",
      );
    }
    if (
      elements.length > 0 &&
      request.parameters.windowId === null
    ) {
      throw new Error(
        "desktop observation adapter result cannot issue reusable element evidence without explicit windowId",
      );
    }
  } else {
    if (
      artifactKinds.size !== 1 ||
      !artifactKinds.has("WAIT_RESULT")
    ) {
      throw new Error(
        "desktop observation adapter result artifact kind mismatch for wait-for",
      );
    }
    if (raw.matched !== true) {
      throw new Error(
        "desktop wait-for adapter result must report matched=true",
      );
    }
  }

  if (
    request.parameters.kind !== "UI_SNAPSHOT" &&
    elements.length > 0
  ) {
    throw new Error(
      "desktop observation adapter result elements are valid only for ui snapshot",
    );
  }

  const matched =
    request.parameters.kind === "WAIT_FOR"
      ? true
      : null;
  const evidenceSha256 = sha256({
    adapterEvidenceSha256,
    parametersSha256: request.parametersSha256,
    observationEpoch: request.observationEpoch,
    hostId: request.hostId,
    sessionId: request.sessionId,
    displayIds,
    windowId,
    artifacts,
    elements,
    matched,
  });

  return Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-adapter-result.v1",
    observationEpoch: request.observationEpoch,
    hostId: request.hostId,
    sessionId: request.sessionId,
    displayIds,
    windowId,
    evidenceSha256,
    artifacts,
    ...(elements.length > 0
      ? { elements }
      : {}),
    ...(request.parameters.kind === "WAIT_FOR"
      ? { matched: true }
      : {}),
  });
}

function observedElementRefs(
  result: DesktopObservationAdapterResult,
  request: DesktopObservationAdapterRequest,
): readonly DesktopObservedElementReference[] {
  if (result.elements === undefined) {
    return Object.freeze([]);
  }
  if (result.windowId === null) {
    throw new Error(
      "desktop element evidence requires exact windowId",
    );
  }
  return Object.freeze(
    result.elements.map((element) =>
      Object.freeze({
        schemaVersion:
          "toadaid.desktop-observed-element-ref.v1" as const,
        elementId: element.elementId,
        hostId: request.hostId,
        sessionId: request.sessionId,
        windowId: result.windowId!,
        observationEpoch:
          request.observationEpoch,
        observationEvidenceSha256:
          result.evidenceSha256,
        elementEvidenceSha256:
          element.evidenceSha256,
        inputSecurity: element.inputSecurity,
      }),
    ),
  );
}

function receiptSha256(
  receipt: Omit<
    DesktopObservationReceipt,
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
  return "DesktopObservationError";
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

function observationHead(
  status: DesktopObservationHead["status"],
  request: Pick<
    NormalizedDesktopObservationRequest,
    "hostId" | "sessionId" | "windowId"
  >,
  observationEpoch: string,
  evidenceSha256: string | null,
  receiptSha256: string | null,
): DesktopObservationHead {
  if (request.windowId === null) {
    throw new Error(
      "desktop observation head requires exact windowId",
    );
  }
  return Object.freeze({
    schemaVersion:
      "toadaid.desktop-observation-head.v1",
    hostId: request.hostId,
    sessionId: request.sessionId,
    windowId: request.windowId,
    observationEpoch,
    status,
    evidenceSha256,
    receiptSha256,
  });
}

function sameObservationHead(
  left: DesktopObservationHead | null,
  right: DesktopObservationHead,
): boolean {
  return (
    left !== null &&
    left.schemaVersion === right.schemaVersion &&
    left.hostId === right.hostId &&
    left.sessionId === right.sessionId &&
    left.windowId === right.windowId &&
    left.observationEpoch === right.observationEpoch &&
    left.status === right.status &&
    left.evidenceSha256 === right.evidenceSha256 &&
    left.receiptSha256 === right.receiptSha256
  );
}

function publishObservationHead(
  runtime: DesktopObservationHeadRuntime,
  status: DesktopObservationHead["status"],
  request: NormalizedDesktopObservationRequest,
  observationEpoch: string,
  evidenceSha256: string | null,
  receiptSha256: string | null,
): void {
  if (request.windowId === null) return;

  const next = observationHead(
    status,
    request,
    observationEpoch,
    evidenceSha256,
    receiptSha256,
  );

  if (status === "PENDING") {
    runtime.publishCurrentObservationHead(next);
    const current =
      runtime.resolveCurrentObservationHead({
        hostId: next.hostId,
        sessionId: next.sessionId,
        windowId: next.windowId,
      });
    if (!sameObservationHead(current, next)) {
      throw new Error(
        "desktop observation PENDING head was not published as current",
      );
    }
    return;
  }

  const expected = observationHead(
    "PENDING",
    request,
    observationEpoch,
    null,
    null,
  );
  runtime.claimCurrentObservationHead(
    expected,
    next,
  );
}

export function assertDesktopObservationReceiptIntegrity(
  receipt: DesktopObservationReceipt,
): void {
  const claimed = sha(
    receipt.receiptSha256,
    "receiptSha256",
  )!;
  const {
    receiptSha256: _receiptSha256,
    ...core
  } = receipt;
  if (sha256(core) !== claimed) {
    throw new Error(
      "desktop observation receipt integrity mismatch",
    );
  }
}

export function assertDesktopElementReferenceCurrent(
  reference: DesktopObservedElementReference,
  receipt: DesktopObservationReceipt,
  runtime: DesktopObservationHeadRuntime,
): void {
  assertDesktopObservationReceiptIntegrity(receipt);

  if (
    receipt.status !== "OK" ||
    receipt.evidenceSha256 === null ||
    receipt.windowId === null
  ) {
    throw new Error(
      "desktop observation is not current usable element evidence",
    );
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
    current.hostId !== receipt.hostId ||
    current.sessionId !== receipt.sessionId ||
    current.windowId !== receipt.windowId ||
    current.status !== "OK" ||
    current.observationEpoch !==
      receipt.observationEpoch ||
    current.evidenceSha256 !==
      receipt.evidenceSha256 ||
    current.receiptSha256 !==
      receipt.receiptSha256
  ) {
    throw new Error(
      "desktop observation receipt is not the current window observation head",
    );
  }

  if (
    reference.schemaVersion !==
      "toadaid.desktop-observed-element-ref.v1" ||
    reference.hostId !== receipt.hostId ||
    reference.sessionId !== receipt.sessionId ||
    reference.windowId !== receipt.windowId ||
    reference.observationEpoch !==
      receipt.observationEpoch ||
    reference.observationEvidenceSha256 !==
      receipt.evidenceSha256
  ) {
    throw new Error(
      "desktop element reference is stale or mismatched",
    );
  }
  if (
    !receipt.elements.some(
      (item) =>
        item.elementId === reference.elementId &&
        item.elementEvidenceSha256 ===
          reference.elementEvidenceSha256 &&
        item.inputSecurity ===
          reference.inputSecurity,
    )
  ) {
    throw new Error(
      "desktop element reference is not present in current observation",
    );
  }
}

export async function observeGovernedDesktop(
  adapter: GovernedDesktopObservationAdapter,
  input: GovernedDesktopObservationInput,
  runtime: DesktopObservationRuntime = {},
): Promise<GovernedDesktopObservationOutcome> {
  const normalized =
    normalizeDesktopObservationRequest(input.request);
  const parametersSha256 = sha256(normalized);
  const registration = normalizeDesktopObservationAdapterRegistration(
    adapter.registration,
  );

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

  const budgetBefore =
    validateRunBudgetLedgerEnvelope(input.budget);
  if (
    budgetBefore.record.runId !==
    invocation.record.runId
  ) {
    throw new Error(
      "desktop observation Q1 budget runId mismatch",
    );
  }

  const cost = reservedCost(normalized);
  const availability = evaluateRunBudgetAvailability(
    budgetBefore,
    cost,
  );
  if (!availability.allowed) {
    throw new RangeError(
      `desktop observation run budget exceeded: ${availability.exceededMetrics.join(",")}`,
    );
  }

  const observationEpoch = boundedId(
    (runtime.randomId ?? randomUUID)(),
    "observationEpoch",
  );
  const observedAt = canonicalIso(
    undefined,
    "observedAt",
    runtime.now ?? (() => new Date()),
  );

  const budgetAfter = recordRunBudgetUsage(
    budgetBefore,
    {
      receiptId: boundedId(
        `desktop-${sha256({
          invocationId: invocation.record.invocationId,
          observationEpoch,
        }).slice(0, 32)}`,
        "receiptId",
      ),
      kind: "TOOL",
      occurredAt: observedAt,
      invocationId: invocation.record.invocationId,
      sourceSha256: parametersSha256,
      delta: cost,
    },
    {
      ...(runtime.now ? { now: runtime.now } : {}),
      ...(runtime.randomId
        ? { randomId: runtime.randomId }
        : {}),
    },
  );

  const adapterRequest: DesktopObservationAdapterRequest =
    Object.freeze({
      schemaVersion:
        "toadaid.desktop-observation-adapter-request.v1",
      invocationId: invocation.record.invocationId,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      capabilityId: normalized.capabilityId,
      toolName: normalized.toolName,
      observationEpoch,
      parametersSha256,
      maxWallClockMs: normalized.maxWallClockMs,
      parameters: normalized,
    });

  const registrationSha256 =
    desktopObservationAdapterRegistrationSha256(
      registration,
    );

  publishObservationHead(
    input.observationHeadRuntime,
    "PENDING",
    normalized,
    observationEpoch,
    null,
    null,
  );

  try {
    const result = normalizeAdapterResult(
      await adapter.observe(adapterRequest),
      adapterRequest,
    );
    const elements = observedElementRefs(
      result,
      adapterRequest,
    );
    const core = Object.freeze({
      schemaVersion:
        "toadaid.desktop-observation-receipt.v1" as const,
      status: "OK" as const,
      capabilityId: normalized.capabilityId,
      invocationId: invocation.record.invocationId,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256:
        registrationSha256,
      observationEpoch,
      parametersSha256,
      observedAt,
      displayIds: result.displayIds,
      windowId: result.windowId,
      evidenceSha256: result.evidenceSha256,
      artifacts: result.artifacts,
      elements,
      budget: Object.freeze({
        ledgerSha256Before:
          budgetBefore.recordSha256,
        ledgerSha256After:
          budgetAfter.recordSha256,
        reservedCost: cost,
      }),
      degradedReason: null,
      errorClass: null,
      errorFingerprint: null,
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256: receiptSha256(core),
    });
    publishObservationHead(
      input.observationHeadRuntime,
      "OK",
      normalized,
      observationEpoch,
      result.evidenceSha256,
      receipt.receiptSha256,
    );
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result,
    });
  } catch (error) {
    const reason =
      error instanceof TypeError ||
      error instanceof RangeError ||
      (
        error instanceof Error &&
        /adapter result|identity mismatch|window identity|display identity|must report matched/.test(
          error.message,
        )
      )
        ? "ADAPTER_RESULT_INVALID"
        : "ADAPTER_ERROR";
    const core = Object.freeze({
      schemaVersion:
        "toadaid.desktop-observation-receipt.v1" as const,
      status: "DEGRADED" as const,
      capabilityId: normalized.capabilityId,
      invocationId: invocation.record.invocationId,
      runId: invocation.record.runId,
      hostId: normalized.hostId,
      sessionId: normalized.sessionId,
      ownerId: normalized.ownerId,
      leaseSha256: leaseBinding.leaseSha256,
      contractBindingSha256: binding.bindingSha256,
      descriptorSha256: compatibility.descriptorSha256,
      adapterRegistrationSha256:
        registrationSha256,
      observationEpoch,
      parametersSha256,
      observedAt,
      displayIds: normalized.displayIds,
      windowId: normalized.windowId,
      evidenceSha256: null,
      artifacts: Object.freeze([]),
      elements: Object.freeze([]),
      budget: Object.freeze({
        ledgerSha256Before:
          budgetBefore.recordSha256,
        ledgerSha256After:
          budgetAfter.recordSha256,
        reservedCost: cost,
      }),
      degradedReason: reason,
      errorClass: errorClass(error),
      errorFingerprint: errorFingerprint(error),
    });
    const receipt = Object.freeze({
      ...core,
      receiptSha256: receiptSha256(core),
    });
    try {
      publishObservationHead(
        input.observationHeadRuntime,
        "DEGRADED",
        normalized,
        observationEpoch,
        null,
        receipt.receiptSha256,
      );
    } catch {
      // The already-published PENDING head still invalidates prior refs.
    }
    return Object.freeze({
      receipt,
      budget: budgetAfter,
      result: null,
    });
  }
}
