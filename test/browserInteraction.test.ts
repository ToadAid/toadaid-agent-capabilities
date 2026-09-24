import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  executeBrowserInteraction,
  normalizeBrowserInteractionPolicy,
} from "../src/index.js";

test("interaction policy requires explicit action authority", async () => {
  await assert.rejects(
    executeBrowserInteraction(
      {
        url: "https://example.com",
        actions: [{ kind: "navigate", url: "https://example.com/next" }],
      },
      {
        allowedTopLevelOrigins: ["https://example.com"],
        allowedActionKinds: [],
      },
      { artifactRoot: join(tmpdir(), "unused-browser-interaction-test") },
    ),
    /not authorized by policy: navigate/,
  );
});

test("interaction plan is bounded before browser launch", async () => {
  await assert.rejects(
    executeBrowserInteraction(
      {
        url: "https://example.com",
        actions: [
          { kind: "navigate", url: "https://example.com/one" },
          { kind: "navigate", url: "https://example.com/two" },
        ],
      },
      {
        allowedTopLevelOrigins: ["https://example.com"],
        allowedActionKinds: ["navigate"],
        maxActions: 1,
      },
      { artifactRoot: join(tmpdir(), "unused-browser-interaction-test") },
    ),
    /exceeds maxActions/,
  );
});

test("normalizes bounded interaction authority", () => {
  const policy = normalizeBrowserInteractionPolicy({
    allowedTopLevelOrigins: ["https://example.com/path"],
    allowedActionKinds: ["click", "type", "click"],
    maxActions: 4,
    maxTypeChars: 300,
  });

  assert.deepEqual(policy.allowedTopLevelOrigins, ["https://example.com"]);
  assert.deepEqual(policy.allowedActionKinds, ["click", "type"]);
  assert.equal(policy.maxActions, 4);
  assert.equal(policy.maxTypeChars, 300);
});

test("executes bounded interactions without persisting typed text or POST side effects", async (t) => {
  const artifactRoot = await mkdtemp(join(tmpdir(), "toadaid-browser-interaction-"));
  t.after(async () => {
    await rm(artifactRoot, { recursive: true, force: true });
  });

  let postAttempts = 0;
  const server = createServer((request, response) => {
    const origin = `http://${request.headers.host}`;
    const url = new URL(request.url ?? "/", origin);

    if (request.method === "POST") {
      postAttempts += 1;
      response.writeHead(204);
      response.end();
      return;
    }

    if (url.pathname === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(`<!doctype html>
        <html>
          <head><title>Interaction Start</title></head>
          <body>
            <label>Message <input id="message" /></label>
            <input id="password" type="password" />
            <button id="apply" onclick="document.querySelector('#state').textContent='applied'; fetch('/mutate', {method:'POST', body:'blocked'}).catch(() => {})">Apply</button>
            <p id="state">idle</p>
          </body>
        </html>`);
      return;
    }

    if (url.pathname === "/next") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(`<!doctype html><html><head><title>Interaction Done</title></head><body><h1>Done</h1></body></html>`);
      return;
    }

    response.writeHead(404);
    response.end("not found");
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  t.after(() => server.close());

  const address = server.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  const typedSecret = "receipt-must-not-contain-this";

  const receipt = await executeBrowserInteraction(
    {
      url: `${origin}/`,
      actions: [
        { kind: "type", target: { by: "label", value: "Message" }, text: typedSecret },
        { kind: "click", target: { by: "text", value: "Apply" } },
        { kind: "navigate", url: `${origin}/next?token=must-not-persist#fragment` },
      ],
    },
    {
      allowedTopLevelOrigins: [origin],
      allowedActionKinds: ["type", "click", "navigate"],
      maxActions: 3,
    },
    {
      artifactRoot,
      now: () => new Date("2026-09-24T20:00:00.000Z"),
    },
  );

  assert.equal(receipt.status, "COMPLETED");
  assert.equal(receipt.actions.length, 3);
  assert.equal(receipt.actions[0]?.typedCharacters, typedSecret.length);
  assert.equal(receipt.actions[2]?.navigatedTo, `${origin}/next`);
  assert.equal(receipt.page.finalUrl, `${origin}/next`);
  assert.equal(receipt.page.title, "Interaction Done");
  assert.ok(receipt.network.blockedHttpMethods.includes("POST"));
  assert.equal(postAttempts, 0);

  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, /receipt-must-not-contain-this/);
  assert.doesNotMatch(serialized, /must-not-persist/);
  assert.doesNotMatch(serialized, /fragment/);

  const screenshot = await readFile(join(artifactRoot, receipt.screenshot.relativePath));
  assert.ok(screenshot.byteLength > 0);
  assert.equal(receipt.screenshot.bytes, screenshot.byteLength);
});

test("refuses password typing", async (t) => {
  const artifactRoot = await mkdtemp(join(tmpdir(), "toadaid-browser-interaction-password-"));
  t.after(async () => {
    await rm(artifactRoot, { recursive: true, force: true });
  });

  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html><body><input id="password" type="password" /></body></html>`);
  });
  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  t.after(() => server.close());

  const address = server.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;

  await assert.rejects(
    executeBrowserInteraction(
      {
        url: origin,
        actions: [{ kind: "type", target: { by: "css", value: "#password" }, text: "nope" }],
      },
      {
        allowedTopLevelOrigins: [origin],
        allowedActionKinds: ["type"],
      },
      { artifactRoot },
    ),
    /input\[type=password\]/,
  );
});
