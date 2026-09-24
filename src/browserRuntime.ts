import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import type { BrowserContext, Locator, Page } from "playwright-chromium";

import type {
  BrowserInteractionTarget,
  BrowserNetworkEvidence,
  BrowserScreenshotEvidence,
  DomEvidence,
  NormalizedBrowserEvidencePolicy,
} from "./contracts.js";

const MAX_HEADINGS = 50;
const SAFE_HTTP_METHODS = new Set(["GET", "HEAD"]);

export interface BrowserNetworkAudit {
  blockedOrigins: Set<string>;
  blockedWebSocketOrigins: Set<string>;
  blockedHttpMethods: Set<string>;
}

export function parseAuthorizedHttpUrl(
  value: string,
  allowedOrigins: readonly string[],
  label: string,
): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be a valid absolute URL`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TypeError(`${label} must use http: or https:`);
  }

  if (!allowedOrigins.includes(parsed.origin)) {
    throw new Error(`${label} origin is not authorized by policy: ${parsed.origin}`);
  }

  return parsed;
}

export function persistedHttpUrl(value: string | URL): string {
  const parsed = typeof value === "string" ? new URL(value) : value;
  return `${parsed.origin}${parsed.pathname}`;
}

export async function installBrowserNetworkGuard(
  context: BrowserContext,
  policy: NormalizedBrowserEvidencePolicy,
): Promise<BrowserNetworkAudit> {
  const topLevelOrigins = new Set(policy.allowedTopLevelOrigins);
  const networkOrigins = new Set([
    ...policy.allowedTopLevelOrigins,
    ...policy.allowedResourceOrigins,
  ]);
  const audit: BrowserNetworkAudit = {
    blockedOrigins: new Set<string>(),
    blockedWebSocketOrigins: new Set<string>(),
    blockedHttpMethods: new Set<string>(),
  };

  await context.route("**/*", async (route) => {
    const request = route.request();
    const requestUrl = request.url();
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

    const method = request.method().toUpperCase();
    if (!SAFE_HTTP_METHODS.has(method)) {
      audit.blockedHttpMethods.add(method);
      await route.abort("blockedbyclient");
      return;
    }

    // Treat every frame navigation as top-level authority. This is intentionally
    // stricter than resource authority and avoids relying on request.frame(),
    // which Playwright documents can be unavailable for early navigation requests.
    const allowedOrigins = request.isNavigationRequest() ? topLevelOrigins : networkOrigins;

    if (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      allowedOrigins.has(parsed.origin)
    ) {
      await route.continue();
      return;
    }

    audit.blockedOrigins.add(parsed.origin === "null" ? parsed.protocol : parsed.origin);
    await route.abort("blockedbyclient");
  });

  await context.routeWebSocket("**/*", (webSocket) => {
    try {
      audit.blockedWebSocketOrigins.add(new URL(webSocket.url()).origin);
    } catch {
      audit.blockedWebSocketOrigins.add("unparseable-websocket-origin");
    }
    return webSocket.close({ code: 1008, reason: "blocked by browser capability policy" });
  });

  return audit;
}

export function networkEvidence(audit: BrowserNetworkAudit): BrowserNetworkEvidence {
  return {
    blockedOrigins: [...audit.blockedOrigins].sort(),
    blockedWebSocketOrigins: [...audit.blockedWebSocketOrigins].sort(),
    blockedHttpMethods: [...audit.blockedHttpMethods].sort(),
  };
}

export async function collectDomEvidence(
  page: Page,
  policy: NormalizedBrowserEvidencePolicy,
): Promise<DomEvidence> {
  return page.evaluate(
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
}

export async function persistScreenshot(
  page: Page,
  artifactRootInput: string,
  receiptId: string,
  fullPage: boolean,
): Promise<BrowserScreenshotEvidence> {
  const artifactRoot = resolve(artifactRootInput);
  const browserArtifactRoot = join(artifactRoot, "browser");
  const screenshotAbsolutePath = join(browserArtifactRoot, `${receiptId}.png`);
  await mkdir(browserArtifactRoot, { recursive: true });

  await page.screenshot({
    path: screenshotAbsolutePath,
    type: "png",
    fullPage,
  });

  const screenshotBytes = await readFile(screenshotAbsolutePath);
  return {
    relativePath: relative(artifactRoot, screenshotAbsolutePath).split(sep).join("/"),
    sha256: createHash("sha256").update(screenshotBytes).digest("hex"),
    bytes: screenshotBytes.byteLength,
  };
}

export function locatorForTarget(page: Page, target: BrowserInteractionTarget): Locator {
  switch (target.by) {
    case "css":
      return page.locator(target.value);
    case "text":
      return page.getByText(target.value, { exact: target.exact ?? true });
    case "label":
      return page.getByLabel(target.value, { exact: target.exact ?? true });
  }
}

export function targetFingerprint(target: BrowserInteractionTarget): string {
  return createHash("sha256").update(JSON.stringify(target)).digest("hex");
}
