export type CapabilityId = string;
export type CapabilityPolicyDecision = "ALLOW" | "DEFAULT" | "BLOCK";
export type CapabilityEffectiveDecision = "ALLOW" | "BLOCK";
export type CapabilityPolicyScope = "agent" | "project" | "session" | "delegation";

export interface CapabilityDefinition {
  id: CapabilityId;
  description: string;
  defaultDecision: CapabilityEffectiveDecision;
}

export interface CapabilityManifest {
  schemaVersion: "toadaid.capability-manifest.v1";
  capabilities: readonly CapabilityDefinition[];
}

export interface CapabilityPolicyLayer {
  scope: CapabilityPolicyScope;
  subject: string;
  decisions: Readonly<Record<CapabilityId, CapabilityPolicyDecision>>;
}

export interface CapabilityDecisionTraceEntry {
  source: "manifest" | CapabilityPolicyScope;
  subject: string;
  requestedDecision: CapabilityPolicyDecision | CapabilityEffectiveDecision;
  effectiveDecision: CapabilityEffectiveDecision;
  stickyBlock: boolean;
}

export interface CapabilityAuthorityDecision {
  schemaVersion: "toadaid.capability-authority-decision.v1";
  capabilityId: CapabilityId;
  installed: boolean;
  decision: CapabilityEffectiveDecision;
  reason:
    | "AUTHORIZED_BY_POLICY"
    | "BLOCKED_BY_POLICY"
    | "MANIFEST_DEFAULT"
    | "UNKNOWN_CAPABILITY";
  trace: readonly CapabilityDecisionTraceEntry[];
}

const CAPABILITY_ID_PATTERN = /^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)+$/;
const SCOPE_ORDER: Readonly<Record<CapabilityPolicyScope, number>> = {
  agent: 0,
  project: 1,
  session: 2,
  delegation: 3,
};

function assertCapabilityId(id: string, label: string): void {
  if (!CAPABILITY_ID_PATTERN.test(id)) {
    throw new TypeError(`${label} must match ${CAPABILITY_ID_PATTERN.source}`);
  }
}

function assertSubject(subject: string, label: string): void {
  if (!subject.trim()) {
    throw new TypeError(`${label} must not be empty`);
  }
}

export function createCapabilityManifest(
  capabilities: readonly CapabilityDefinition[],
): CapabilityManifest {
  const seen = new Set<string>();
  const normalized = capabilities.map((capability, index) => {
    assertCapabilityId(capability.id, `capabilities[${index}].id`);
    if (seen.has(capability.id)) {
      throw new TypeError(`duplicate capability id: ${capability.id}`);
    }
    seen.add(capability.id);

    if (!capability.description.trim()) {
      throw new TypeError(`capability description must not be empty: ${capability.id}`);
    }

    return Object.freeze({ ...capability });
  });

  return Object.freeze({
    schemaVersion: "toadaid.capability-manifest.v1" as const,
    capabilities: Object.freeze(normalized),
  });
}

export const CORE_CAPABILITY_MANIFEST = createCapabilityManifest([
  {
    id: "browser:evidence",
    description: "Capture bounded browser evidence from policy-authorized origins.",
    defaultDecision: "BLOCK",
  },
  {
    id: "browser:interaction",
    description: "Execute bounded browser navigation, click, and type actions.",
    defaultDecision: "BLOCK",
  },
  {
    id: "browser:session",
    description: "Create, validate, use, and revoke an owner-bound origin-scoped browser session lease.",
    defaultDecision: "BLOCK",
  },
  {
    id: "browser:session-persist",
    description: "Permit runtime-owned browser session state to persist beyond an ephemeral context.",
    defaultDecision: "BLOCK",
  },
  {
    id: "workspace:snapshot",
    description: "Capture a bounded immutable workspace snapshot in external history storage.",
    defaultDecision: "BLOCK",
  },
  {
    id: "workspace:diff",
    description: "Compare immutable workspace snapshots and return deterministic change evidence.",
    defaultDecision: "BLOCK",
  },
  {
    id: "workspace:restore",
    description: "Restore policy-managed workspace files from a verified snapshot.",
    defaultDecision: "BLOCK",
  },
  {
    id: "workspace:maintenance",
    description: "Apply bounded retention, orphan cleanup, and workspace-history repair.",
    defaultDecision: "BLOCK",
  },
  {
    id: "runtime:bounded-repair",
    description: "Apply deterministic syntax-only repair to malformed tool-call JSON without inferring semantics or authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "review:inspect",
    description: "Build and execute bounded code-review inspection plans with mandatory coverage accounting.",
    defaultDecision: "BLOCK",
  },
  {
    id: "review:fix",
    description: "Apply explicitly selected review findings through governed workspace snapshot and diff boundaries.",
    defaultDecision: "BLOCK",
  },
] as const);

function capabilityMap(manifest: CapabilityManifest): ReadonlyMap<string, CapabilityDefinition> {
  return new Map(manifest.capabilities.map((capability) => [capability.id, capability]));
}

export function validateCapabilityPolicyChain(
  manifest: CapabilityManifest,
  layers: readonly CapabilityPolicyLayer[],
): readonly CapabilityPolicyLayer[] {
  const installed = capabilityMap(manifest);
  const seenScopes = new Set<CapabilityPolicyScope>();
  let previousOrder = -1;

  for (const [index, layer] of layers.entries()) {
    assertSubject(layer.subject, `layers[${index}].subject`);

    const order = SCOPE_ORDER[layer.scope];
    if (order < previousOrder) {
      throw new TypeError("capability policy layers must follow agent -> project -> session -> delegation order");
    }
    if (seenScopes.has(layer.scope)) {
      throw new TypeError(`duplicate capability policy scope: ${layer.scope}`);
    }
    seenScopes.add(layer.scope);
    previousOrder = order;

    for (const [capabilityId, decision] of Object.entries(layer.decisions)) {
      assertCapabilityId(capabilityId, `layers[${index}].decisions key`);
      if (!installed.has(capabilityId)) {
        throw new TypeError(`policy references capability that is not installed: ${capabilityId}`);
      }
      if (decision !== "ALLOW" && decision !== "DEFAULT" && decision !== "BLOCK") {
        throw new TypeError(`invalid capability decision for ${capabilityId}`);
      }
    }
  }

  return layers;
}

export function resolveCapabilityAuthority(
  capabilityId: CapabilityId,
  manifest: CapabilityManifest,
  layers: readonly CapabilityPolicyLayer[],
): CapabilityAuthorityDecision {
  assertCapabilityId(capabilityId, "capabilityId");
  validateCapabilityPolicyChain(manifest, layers);

  const definition = capabilityMap(manifest).get(capabilityId);
  if (!definition) {
    return {
      schemaVersion: "toadaid.capability-authority-decision.v1",
      capabilityId,
      installed: false,
      decision: "BLOCK",
      reason: "UNKNOWN_CAPABILITY",
      trace: [],
    };
  }

  let effective = definition.defaultDecision;
  let stickyBlock = false;
  let sawExplicitAllow = false;
  const trace: CapabilityDecisionTraceEntry[] = [
    {
      source: "manifest",
      subject: "installed-default",
      requestedDecision: definition.defaultDecision,
      effectiveDecision: effective,
      stickyBlock: false,
    },
  ];

  for (const layer of layers) {
    const requested = layer.decisions[capabilityId] ?? "DEFAULT";

    if (requested === "BLOCK") {
      effective = "BLOCK";
      stickyBlock = true;
    } else if (requested === "ALLOW" && !stickyBlock) {
      effective = "ALLOW";
      sawExplicitAllow = true;
    }

    trace.push({
      source: layer.scope,
      subject: layer.subject,
      requestedDecision: requested,
      effectiveDecision: effective,
      stickyBlock,
    });
  }

  let reason: CapabilityAuthorityDecision["reason"];
  if (stickyBlock) {
    reason = "BLOCKED_BY_POLICY";
  } else if (sawExplicitAllow && effective === "ALLOW") {
    reason = "AUTHORIZED_BY_POLICY";
  } else {
    reason = "MANIFEST_DEFAULT";
  }

  return {
    schemaVersion: "toadaid.capability-authority-decision.v1",
    capabilityId,
    installed: true,
    decision: effective,
    reason,
    trace,
  };
}

export class CapabilityAuthorizationError extends Error {
  readonly authority: CapabilityAuthorityDecision;

  constructor(authority: CapabilityAuthorityDecision) {
    super(`capability is not authorized: ${authority.capabilityId} (${authority.reason})`);
    this.name = "CapabilityAuthorizationError";
    this.authority = authority;
  }
}

export function assertCapabilityAllowed(
  capabilityId: CapabilityId,
  manifest: CapabilityManifest,
  layers: readonly CapabilityPolicyLayer[],
): CapabilityAuthorityDecision {
  const authority = resolveCapabilityAuthority(capabilityId, manifest, layers);
  if (authority.decision !== "ALLOW") {
    throw new CapabilityAuthorizationError(authority);
  }
  return authority;
}
