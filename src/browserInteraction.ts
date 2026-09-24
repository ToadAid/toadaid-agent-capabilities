import { randomUUID } from "node:crypto";
import { chromium, type Locator, type Page } from "playwright-chromium";

import { exactInteger, normalizeBrowserEvidencePolicy } from "./browserEvidence.js";
import {
  collectDomEvidence,
  installBrowserNetworkGuard,
  locatorForTarget,
  networkEvidence,
  parseAuthorizedHttpUrl,
  persistedHttpUrl,
  persistScreenshot,
  targetFingerprint,
} from "./browserRuntime.js";
import type {
  BrowserInteractionAction,
  BrowserInteractionActionKind,
  BrowserInteractionActionReceipt,
  BrowserInteractionPolicy,
  BrowserInteractionReceipt,
  BrowserInteractionRequest,
  BrowserInteractionRuntime,
  BrowserInteractionTarget,
  NormalizedBrowserInteractionPolicy,
} from "./contracts.js";

const DEFAULT_MAX_ACTIONS = 12;
const MAX_ACTIONS = 50;
const DEFAULT_MAX_TARGET_CHARS = 500;
const MAX_TARGET_CHARS = 4_000;
const DEFAULT_MAX_TYPE_CHARS = 2_000;
const MAX_TYPE_CHARS = 10_000;
const DEFAULT_ACTION_TIMEOUT_MS = 10_000;
const MAX_ACTION_TIMEOUT_MS = 30_000;
const ACTION_KINDS: readonly BrowserInteractionActionKind[] = ["navigate", "click", "type"];

export function normalizeBrowserInteractionPolicy(
  policy: BrowserInteractionPolicy,
): NormalizedBrowserInteractionPolicy {
  const evidence = normalizeBrowserEvidencePolicy(policy);
  const allowedActionKinds = [...new Set(policy.allowedActionKinds)];
  for (const kind of allowedActionKinds) {
    if (!ACTION_KINDS.includes(kind)) {
      throw new TypeError(`unsupported browser interaction action kind: ${kind}`);
    }
  }

  return {
    ...evidence,
    allowedActionKinds,
    maxActions: exactInteger(policy.maxActions, DEFAULT_MAX_ACTIONS, 0, MAX_ACTIONS, "maxActions"),
    maxTargetChars: exactInteger(
      policy.maxTargetChars,
      DEFAULT_MAX_TARGET_CHARS,
      1,
      MAX_TARGET_CHARS,
      "maxTargetChars",
    ),
    maxTypeChars: exactInteger(
      policy.maxTypeChars,
      DEFAULT_MAX_TYPE_CHARS,
      0,
      MAX_TYPE_CHARS,
      "maxTypeChars",
    ),
    actionTimeoutMs: exactInteger(
      policy.actionTimeoutMs,
      DEFAULT_ACTION_TIMEOUT_MS,
      1_000,
      MAX_ACTION_TIMEOUT_MS,
      "actionTimeoutMs",
    ),
  };
}

function assertTarget(target: BrowserInteractionTarget, policy: NormalizedBrowserInteractionPolicy): void {
  if (!target.value.trim()) {
    throw new TypeError("interaction target value must not be empty");
  }
  if (target.value.length > policy.maxTargetChars) {
    throw new RangeError(`interaction target exceeds maxTargetChars (${policy.maxTargetChars})`);
  }
}

function assertActionAuthorized(
  action: BrowserInteractionAction,
  policy: NormalizedBrowserInteractionPolicy,
): void {
  if (!policy.allowedActionKinds.includes(action.kind)) {
    throw new Error(`interaction action is not authorized by policy: ${action.kind}`);
  }

  if (action.kind === "navigate") {
    parseAuthorizedHttpUrl(action.url, policy.allowedTopLevelOrigins, "navigate.url");
    return;
  }

  assertTarget(action.target, policy);
  if (action.kind === "type" && action.text.length > policy.maxTypeChars) {
    throw new RangeError(`interaction text exceeds maxTypeChars (${policy.maxTypeChars})`);
  }
}

async function uniqueVisibleLocator(
  page: Page,
  target: BrowserInteractionTarget,
  timeoutMs: number,
): Promise<Locator> {
  const locator = locatorForTarget(page, target);
  await locator.first().waitFor({ state: "visible", timeout: timeoutMs });
  const count = await locator.count();
  if (count !== 1) {
    throw new Error(`interaction target must resolve to exactly one element; resolved ${count}`);
  }
  return locator;
}

async function assertTypeTarget(locator: Locator): Promise<void> {
  const reason = await locator.evaluate((element) => {
    if (element instanceof HTMLInputElement) {
      if (["password", "file", "hidden"].includes(element.type)) return `input[type=${element.type}]`;
      if (element.disabled) return "disabled input";
      if (element.readOnly) return "read-only input";
      return null;
    }
    if (element instanceof HTMLTextAreaElement) {
      if (element.disabled) return "disabled textarea";
      if (element.readOnly) return "read-only textarea";
      return null;
    }
    if (element instanceof HTMLElement && element.isContentEditable) {
      return "contenteditable target (not supported in P2)";
    }
    return "non-text-writable element";
  });

  if (reason !== null) {
    throw new Error(`type action refused for ${reason}`);
  }
}

async function applyAction(
  page: Page,
  action: BrowserInteractionAction,
  index: number,
  policy: NormalizedBrowserInteractionPolicy,
): Promise<BrowserInteractionActionReceipt> {
  const beforeUrl = page.url();

  if (action.kind === "navigate") {
    const targetUrl = parseAuthorizedHttpUrl(
      action.url,
      policy.allowedTopLevelOrigins,
      "navigate.url",
    );
    await page.goto(targetUrl.toString(), {
      waitUntil: "domcontentloaded",
      timeout: policy.actionTimeoutMs,
    });
    const finalUrl = parseAuthorizedHttpUrl(
      page.url(),
      policy.allowedTopLevelOrigins,
      "post-navigation page",
    );
    return {
      index,
      kind: action.kind,
      status: "APPLIED",
      navigatedTo: persistedHttpUrl(finalUrl),
    };
  }

  const locator = await uniqueVisibleLocator(page, action.target, policy.actionTimeoutMs);
  const target = {
    by: action.target.by,
    sha256: targetFingerprint(action.target),
  } as const;

  if (action.kind === "type") {
    await assertTypeTarget(locator);
    await locator.fill(action.text, { timeout: policy.actionTimeoutMs });
  } else {
    await locator.click({ timeout: policy.actionTimeoutMs });
  }

  const finalUrl = parseAuthorizedHttpUrl(
    page.url(),
    policy.allowedTopLevelOrigins,
    "post-action page",
  );
  const navigated = page.url() !== beforeUrl;

  if (action.kind === "type") {
    return {
      index,
      kind: action.kind,
      status: "APPLIED",
      target,
      typedCharacters: action.text.length,
      ...(navigated ? { navigatedTo: persistedHttpUrl(finalUrl) } : {}),
    };
  }

  return {
    index,
    kind: action.kind,
    status: "APPLIED",
    target,
    ...(navigated ? { navigatedTo: persistedHttpUrl(finalUrl) } : {}),
  };
}

export async function executeBrowserInteraction(
  request: BrowserInteractionRequest,
  policyInput: BrowserInteractionPolicy,
  runtime: BrowserInteractionRuntime,
): Promise<BrowserInteractionReceipt> {
  if (!runtime.artifactRoot.trim()) {
    throw new TypeError("runtime.artifactRoot must not be empty");
  }

  const policy = normalizeBrowserInteractionPolicy(policyInput);
  const requestedUrl = parseAuthorizedHttpUrl(
    request.url,
    policy.allowedTopLevelOrigins,
    "request.url",
  );
  if (request.actions.length > policy.maxActions) {
    throw new RangeError(`interaction plan exceeds maxActions (${policy.maxActions})`);
  }
  for (const action of request.actions) assertActionAuthorized(action, policy);

  const receiptId = randomUUID();
  const now = runtime.now ?? (() => new Date());
  const startedAt = now().toISOString();

  const browser = await chromium.launch({ headless: runtime.headless ?? true });
  try {
    const context = await browser.newContext({
      acceptDownloads: false,
      serviceWorkers: "block",
    });
    const audit = await installBrowserNetworkGuard(context, policy);
    const page = await context.newPage();

    await page.goto(requestedUrl.toString(), {
      waitUntil: "domcontentloaded",
      timeout: policy.timeoutMs,
    });
    parseAuthorizedHttpUrl(page.url(), policy.allowedTopLevelOrigins, "initial page");

    page.on("popup", (popup) => {
      void popup.close();
    });

    const actions: BrowserInteractionActionReceipt[] = [];
    for (let index = 0; index < request.actions.length; index += 1) {
      const action = request.actions[index];
      if (action === undefined) throw new Error("interaction plan index unexpectedly missing");
      actions.push(await applyAction(page, action, index, policy));
    }

    const finalUrl = parseAuthorizedHttpUrl(
      page.url(),
      policy.allowedTopLevelOrigins,
      "final page",
    );
    const dom = await collectDomEvidence(page, policy);
    const screenshot = await persistScreenshot(
      page,
      runtime.artifactRoot,
      receiptId,
      policy.fullPageScreenshot,
    );

    return {
      schemaVersion: "toadaid.browser-interaction.receipt.v1",
      receiptId,
      capability: "browser.interaction.execute",
      status: "COMPLETED",
      startedAt,
      completedAt: now().toISOString(),
      request: {
        url: persistedHttpUrl(requestedUrl),
        actionCount: request.actions.length,
      },
      policy,
      actions,
      page: {
        finalUrl: persistedHttpUrl(finalUrl),
        title: dom.title,
      },
      screenshot,
      dom,
      network: networkEvidence(audit),
    };
  } finally {
    await browser.close();
  }
}
