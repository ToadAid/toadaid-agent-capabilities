import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { chromium } from "playwright-chromium";

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
const MAX_HEADINGS = 50;

function exactInteger(
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

function assertedRequestedUrl(
  requestedUrl: string,
  policy: NormalizedBrowserEvidencePolicy,
): URL {
  let parsed: URL;
  try {
    parsed = new URL(requestedUrl);
  } catch {
    throw new TypeError("request.url must be a valid absolute URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TypeError("request.url must use http: or https:");
  }

  if (!policy.allowedTopLevelOrigins.includes(parsed.origin)) {
    throw new Error(`request origin is not authorized by policy: ${parsed.origin}`);
  }

  return parsed;
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
  const requestedUrl = assertedRequestedUrl(request.url, policy);
  const networkOrigins = new Set([
    ...policy.allowedTopLevelOrigins,
    ...policy.allowedResourceOrigins,
  ]);
  const blockedOrigins = new Set<string>();
  const blockedWebSocketOrigins = new Set<string>();

  const receiptId = randomUUID();
  const artifactRoot = resolve(runtime.artifactRoot);
  const screenshotAbsolutePath = join(artifactRoot, "browser", `${receiptId}.png`);
  await mkdir(join(artifactRoot, "browser"), { recursive: true });

  const browser = await chromium.launch({ headless: runtime.headless ?? true });
  try {
    const context = await browser.newContext({
      acceptDownloads: false,
      serviceWorkers: "block",
    });

    await context.route("**/*", async (route) => {
      const requestUrl = route.request().url();
      let parsed: URL;
      try {
        parsed = new URL(requestUrl);
      } catch {
        await route.abort("blockedbyclient");
        return;
      }

      if (parsed.protocol === "data:" || parsed.protocol === "blob:") {
        await route.continue();
        return;
      }

      if (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        networkOrigins.has(parsed.origin)
      ) {
        await route.continue();
        return;
      }

      blockedOrigins.add(parsed.origin === "null" ? parsed.protocol : parsed.origin);
      await route.abort("blockedbyclient");
    });

    await context.routeWebSocket("**/*", (webSocket) => {
      try {
        blockedWebSocketOrigins.add(new URL(webSocket.url()).origin);
      } catch {
        blockedWebSocketOrigins.add("unparseable-websocket-origin");
      }
      return webSocket.close({ code: 1008, reason: "blocked by browser evidence policy" });
    });

    const page = await context.newPage();
    const response = await page.goto(requestedUrl.toString(), {
      waitUntil: "domcontentloaded",
      timeout: policy.timeoutMs,
    });

    const finalUrl = new URL(page.url());
    if (!policy.allowedTopLevelOrigins.includes(finalUrl.origin)) {
      throw new Error(`final page origin is not authorized by policy: ${finalUrl.origin}`);
    }

    const dom = await page.evaluate(
      ({ maxDomChars, maxInteractiveElements, maxHeadings }) => {
        const compact = (value: string): string => value.replace(/\s+/g, " ").trim();
        const bodyText = document.body?.innerText ?? "";

        const headings = Array.from(document.querySelectorAll("h1,h2,h3,h4,h5,h6"))
          .slice(0, maxHeadings)
          .map((element) => ({
            level: Number(element.tagName.slice(1)),
            text: compact(element.textContent ?? "").slice(0, 500),
          }));

        const interactiveElements = Array.from(
          document.querySelectorAll("a,button,input,select,textarea,[role]"),
        )
          .slice(0, maxInteractiveElements)
          .map((element) => {
            const htmlElement = element as HTMLElement;
            const text = compact(
              htmlElement.innerText || element.getAttribute("placeholder") || "",
            ).slice(0, 300);

            let href: string | null = null;
            if (element instanceof HTMLAnchorElement && element.href) {
              try {
                const parsed = new URL(element.href);
                href = `${parsed.origin}${parsed.pathname}`;
              } catch {
                href = null;
              }
            }

            return {
              tag: element.tagName.toLowerCase(),
              role: element.getAttribute("role"),
              ariaLabel: element.getAttribute("aria-label"),
              text,
              href,
              type: element instanceof HTMLInputElement ? element.type : null,
              name: element.getAttribute("name"),
            };
          });

        return {
          title: document.title,
          textExcerpt: bodyText.slice(0, maxDomChars),
          textTruncated: bodyText.length > maxDomChars,
          headings,
          interactiveElements,
        };
      },
      {
        maxDomChars: policy.maxDomChars,
        maxInteractiveElements: policy.maxInteractiveElements,
        maxHeadings: MAX_HEADINGS,
      },
    );

    await page.screenshot({
      path: screenshotAbsolutePath,
      type: "png",
      fullPage: policy.fullPageScreenshot,
    });

    const screenshotBytes = await readFile(screenshotAbsolutePath);
    const screenshotRelativePath = relative(artifactRoot, screenshotAbsolutePath)
      .split(sep)
      .join("/");

    return {
      schemaVersion: "toadaid.browser-evidence.receipt.v1",
      receiptId,
      capability: "browser.evidence.capture",
      status: "CAPTURED",
      capturedAt: (runtime.now ?? (() => new Date()))().toISOString(),
      request: {
        url: requestedUrl.toString(),
      },
      policy,
      page: {
        requestedUrl: requestedUrl.toString(),
        finalUrl: finalUrl.toString(),
        httpStatus: response?.status() ?? null,
        title: dom.title,
      },
      screenshot: {
        relativePath: screenshotRelativePath,
        sha256: createHash("sha256").update(screenshotBytes).digest("hex"),
        bytes: screenshotBytes.byteLength,
      },
      dom,
      network: {
        blockedOrigins: [...blockedOrigins].sort(),
        blockedWebSocketOrigins: [...blockedWebSocketOrigins].sort(),
      },
    };
  } finally {
    await browser.close();
  }
}
