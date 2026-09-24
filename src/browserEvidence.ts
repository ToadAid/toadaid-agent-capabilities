import { randomUUID } from "node:crypto";
import { chromium } from "playwright-chromium";

import {
  collectDomEvidence,
  installBrowserNetworkGuard,
  networkEvidence,
  parseAuthorizedHttpUrl,
  persistedHttpUrl,
  persistScreenshot,
} from "./browserRuntime.js";
import type {
  BrowserEvidencePolicy,
  BrowserEvidenceReceipt,
  BrowserEvidenceRequest,
  BrowserEvidenceRuntime,
  NormalizedBrowserEvidencePolicy,
} from "./contracts.js";

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_DOM_CHARS = 20_000;
const MAX_DOM_CHARS = 100_000;
const DEFAULT_MAX_INTERACTIVE_ELEMENTS = 100;
const MAX_INTERACTIVE_ELEMENTS = 500;

export function exactInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function httpOrigin(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TypeError(`${label} must use http: or https:`);
  }

  return parsed.origin;
}

function normalizedOrigins(values: readonly string[], label: string): readonly string[] {
  return [...new Set(values.map((value) => httpOrigin(value, label)))].sort();
}

export function normalizeBrowserEvidencePolicy(
  policy: BrowserEvidencePolicy,
): NormalizedBrowserEvidencePolicy {
  const allowedTopLevelOrigins = normalizedOrigins(
    policy.allowedTopLevelOrigins,
    "allowedTopLevelOrigins entry",
  );
  if (allowedTopLevelOrigins.length === 0) {
    throw new TypeError("allowedTopLevelOrigins must contain at least one origin");
  }

  return {
    allowedTopLevelOrigins,
    allowedResourceOrigins: normalizedOrigins(
      policy.allowedResourceOrigins ?? [],
      "allowedResourceOrigins entry",
    ),
    timeoutMs: exactInteger(policy.timeoutMs, DEFAULT_TIMEOUT_MS, 1_000, MAX_TIMEOUT_MS, "timeoutMs"),
    maxDomChars: exactInteger(
      policy.maxDomChars,
      DEFAULT_MAX_DOM_CHARS,
      100,
      MAX_DOM_CHARS,
      "maxDomChars",
    ),
    maxInteractiveElements: exactInteger(
      policy.maxInteractiveElements,
      DEFAULT_MAX_INTERACTIVE_ELEMENTS,
      0,
      MAX_INTERACTIVE_ELEMENTS,
      "maxInteractiveElements",
    ),
    fullPageScreenshot: policy.fullPageScreenshot ?? true,
  };
}

export async function captureBrowserEvidence(
  request: BrowserEvidenceRequest,
  policyInput: BrowserEvidencePolicy,
  runtime: BrowserEvidenceRuntime,
): Promise<BrowserEvidenceReceipt> {
  if (!runtime.artifactRoot.trim()) {
    throw new TypeError("runtime.artifactRoot must not be empty");
  }

  const policy = normalizeBrowserEvidencePolicy(policyInput);
  const requestedUrl = parseAuthorizedHttpUrl(
    request.url,
    policy.allowedTopLevelOrigins,
    "request.url",
  );
  const receiptId = randomUUID();

  const browser = await chromium.launch({ headless: runtime.headless ?? true });
  try {
    const context = await browser.newContext({
      acceptDownloads: false,
      serviceWorkers: "block",
    });
    const audit = await installBrowserNetworkGuard(context, policy);

    const page = await context.newPage();
    const response = await page.goto(requestedUrl.toString(), {
      waitUntil: "domcontentloaded",
      timeout: policy.timeoutMs,
    });

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
      schemaVersion: "toadaid.browser-evidence.receipt.v1",
      receiptId,
      capability: "browser.evidence.capture",
      status: "CAPTURED",
      capturedAt: (runtime.now ?? (() => new Date()))().toISOString(),
      request: {
        url: persistedHttpUrl(requestedUrl),
      },
      policy,
      page: {
        requestedUrl: persistedHttpUrl(requestedUrl),
        finalUrl: persistedHttpUrl(finalUrl),
        httpStatus: response?.status() ?? null,
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
