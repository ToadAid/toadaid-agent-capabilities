import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { captureBrowserEvidence, normalizeBrowserEvidencePolicy } from "../src/index.js";

test("policy normalizes exact origins and rejects non-http origins", () => {
  const normalized = normalizeBrowserEvidencePolicy({
    allowedTopLevelOrigins: ["https://example.com/path", "https://example.com"],
    allowedResourceOrigins: ["https://static.example.com/assets"],
  });

  assert.deepEqual(normalized.allowedTopLevelOrigins, ["https://example.com"]);
  assert.deepEqual(normalized.allowedResourceOrigins, ["https://static.example.com"]);
  assert.throws(
    () => normalizeBrowserEvidencePolicy({ allowedTopLevelOrigins: ["file:///etc"] }),
    /http: or https:/,
  );
});

test("agent request cannot grant itself an origin", async () => {
  await assert.rejects(
    captureBrowserEvidence(
      { url: "https://example.com" },
      { allowedTopLevelOrigins: ["https://allowed.example"] },
      { artifactRoot: join(tmpdir(), "unused-agent-capability-test") },
    ),
    /not authorized by policy/,
  );
});

test("captures bounded browser evidence without input values", async (t) => {
  const artifactRoot = await mkdtemp(join(tmpdir(), "toadaid-browser-evidence-"));
  t.after(async () => {
    await rm(artifactRoot, { recursive: true, force: true });
  });

  const server = createServer((request, response) => {
    if (request.url === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(`<!doctype html>
        <html>
          <head><title>Frog Evidence</title></head>
          <body>
            <h1>Browser Evidence</h1>
            <p>This page proves the frog can observe rendered HTML.</p>
            <input name="query" placeholder="Search" value="should-not-be-captured">
            <a href="/next?token=must-not-persist">Next</a>
            <img src="http://127.0.0.1:9/private.png" alt="blocked">
          </body>
        </html>`);
      return;
    }
    response.writeHead(404);
    response.end("not found");
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  t.after(() => {
    server.close();
  });

  const address = server.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;

  const receipt = await captureBrowserEvidence(
    { url: `${origin}/` },
    {
      allowedTopLevelOrigins: [origin],
      maxDomChars: 5_000,
      maxInteractiveElements: 20,
    },
    {
      artifactRoot,
      now: () => new Date("2026-09-24T12:00:00.000Z"),
    },
  );

  assert.equal(receipt.status, "CAPTURED");
  assert.equal(receipt.page.httpStatus, 200);
  assert.equal(receipt.page.title, "Frog Evidence");
  assert.equal(receipt.capturedAt, "2026-09-24T12:00:00.000Z");
  assert.equal(receipt.dom.headings[0]?.text, "Browser Evidence");
  assert.match(receipt.dom.textExcerpt, /frog can observe rendered HTML/);
  assert.ok(receipt.network.blockedOrigins.includes("http://127.0.0.1:9"));

  const serializedInteractive = JSON.stringify(receipt.dom.interactiveElements);
  assert.doesNotMatch(serializedInteractive, /should-not-be-captured/);
  assert.doesNotMatch(serializedInteractive, /must-not-persist/);
  assert.match(serializedInteractive, /Search/);

  const screenshotPath = join(artifactRoot, receipt.screenshot.relativePath);
  const screenshot = await readFile(screenshotPath);
  assert.ok(screenshot.byteLength > 0);
  assert.equal(receipt.screenshot.bytes, screenshot.byteLength);
  assert.match(receipt.screenshot.sha256, /^[a-f0-9]{64}$/);
});
