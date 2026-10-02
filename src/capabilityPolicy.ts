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
    id: "host:session",
    description: "Create, validate, narrow, use, and revoke an owner-bound host-connector session lease.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:filesystem-read",
    description: "Read bounded host filesystem data through an explicitly scoped host-connector session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:filesystem-write",
    description: "Mutate bounded host filesystem data through an explicitly scoped host-connector session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:command-execute",
    description: "Execute bounded host commands through an explicitly scoped host-connector session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:tool-invoke",
    description: "Invoke bounded host tools through an explicitly scoped host-connector session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:connector-use",
    description: "Use an MCP/skill/connector transport through an explicitly scoped host-connector session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:display-inventory",
    description: "Read bounded display/DPI inventory through a live scoped host session.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:screenshot",
    description: "Capture a bounded screenshot from explicitly scoped display or region evidence.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:ui-snapshot",
    description: "Capture bounded accessibility/DOM-derived desktop UI evidence from an explicit scope.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:wait-for",
    description: "Poll a bounded exact-window UI condition locally under an explicit timeout budget.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:pointer-click",
    description: "Dispatch a bounded pointer click against current governed desktop evidence.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:pointer-move",
    description: "Move the pointer only against current governed desktop evidence and explicit scope.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:scroll",
    description: "Scroll an exact governed desktop window under bounded deltas.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:text-input",
    description: "Enter bounded ordinary non-secret text into an exact governed UI element.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:shortcut",
    description: "Dispatch a bounded explicit keyboard shortcut against an exact governed window.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:app-launch",
    description: "Launch an explicit host application executable with structured arguments under a scoped host lease.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:clipboard-read",
    description: "Read bounded host clipboard text through a scoped host lease.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:clipboard-write",
    description: "Write bounded ordinary host clipboard text through separately authorized mutation authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:process-read",
    description: "Read bounded host process evidence through a scoped host lease.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:process-stop",
    description: "Stop an exact process only from prior process evidence through separately authorized mutation authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:file-read",
    description: "Read bounded host file content under an explicit canonical root/path scope.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:file-write",
    description: "Write bounded host file content under an explicit canonical root/path scope and mutation authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:notification",
    description: "Emit a bounded host notification through separately authorized mutation authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:registry-read",
    description: "Read a bounded explicit host registry hive/root/key scope.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:registry-write",
    description: "Mutate a bounded explicit host registry hive/root/key scope through separately authorized authority.",
    defaultDecision: "BLOCK",
  },
  {
    id: "host:command-exec",
    description: "Execute an explicit absolute executable with structured argv/cwd/env and no implicit shell or elevation.",
    defaultDecision: "BLOCK",
  },
  {
    id: "security:sandbox-exec",
    description: "Execute bounded security proof steps only inside a separately authorized governed sandbox.",
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
  {
    id: "web:extract",
    description: "Perform deterministic bounded structured extraction through an isolated web worker.",
    defaultDecision: "BLOCK",
  },
  {
    id: "web:adaptive-locate",
    description: "Relocate changed web elements through bounded structural similarity scoring.",
    defaultDecision: "BLOCK",
  },
  {
    id: "web:crawl",
    description: "Run bounded resumable web crawls with sealed continuity checkpoints and per-origin budgets.",
    defaultDecision: "BLOCK",
  },
  {
    id: "web:xhr-capture",
    description: "Capture bounded background XHR/fetch evidence through a guarded browser worker.",
    defaultDecision: "BLOCK",
  },
  {
    id: "web:stealth-fetch",
    description: "Permit optional stealth fetching only when separately authorized by current policy.",
    defaultDecision: "BLOCK",
  },
  {
    id: "interrupt:create",
    description: "Create a typed durable human interrupt bound to an exact run-state capsule.",
    defaultDecision: "BLOCK",
  },
  {
    id: "interrupt:resolve",
    description: "Resolve an open human interrupt with schema-validated human input bound to the same run state.",
    defaultDecision: "BLOCK",
  },
  {
    id: "secret:lease",
    description: "Create an owner/provider/profile-scoped lease over an opaque runtime-owned secret handle.",
    defaultDecision: "BLOCK",
  },
  {
    id: "secret:materialize",
    description: "Issue and verify a short-lived secret materialization grant for one currently authorized consumer capability.",
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
