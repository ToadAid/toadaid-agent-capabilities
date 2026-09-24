export { captureBrowserEvidence, normalizeBrowserEvidencePolicy } from "./browserEvidence.js";
export { executeBrowserInteraction, normalizeBrowserInteractionPolicy } from "./browserInteraction.js";
export {
  assertCapabilityAllowed,
  CapabilityAuthorizationError,
  CORE_CAPABILITY_MANIFEST,
  createCapabilityManifest,
  resolveCapabilityAuthority,
  validateCapabilityPolicyChain,
} from "./capabilityPolicy.js";
export type {
  CapabilityAuthorityDecision,
  CapabilityDecisionTraceEntry,
  CapabilityDefinition,
  CapabilityEffectiveDecision,
  CapabilityId,
  CapabilityManifest,
  CapabilityPolicyDecision,
  CapabilityPolicyLayer,
  CapabilityPolicyScope,
} from "./capabilityPolicy.js";
export type {
  BrowserEvidencePolicy,
  BrowserEvidenceReceipt,
  BrowserEvidenceRequest,
  BrowserEvidenceRuntime,
  BrowserInteractionAction,
  BrowserInteractionActionKind,
  BrowserInteractionActionReceipt,
  BrowserInteractionPolicy,
  BrowserInteractionReceipt,
  BrowserInteractionRequest,
  BrowserInteractionRuntime,
  BrowserInteractionTarget,
  BrowserNetworkEvidence,
  BrowserScreenshotEvidence,
  DomEvidence,
  DomHeadingEvidence,
  DomInteractiveElement,
  NormalizedBrowserEvidencePolicy,
  NormalizedBrowserInteractionPolicy,
} from "./contracts.js";
