import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = mkdtempSync(join(tmpdir(), "toadaid-v1-agent0-"));
const packDir = join(tempRoot, "pack");
const consumerDir = join(tempRoot, "consumer");
const packageDir = join(consumerDir, "node_modules", "@toadaid", "agent-capabilities");
const consumerNodeModules = join(consumerDir, "node_modules");

function fail(message) { throw new Error(`V1 graduation proof failed: ${message}`); }
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) fail(`${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`);
  return result;
}

try {
  mkdirSync(packDir, { recursive: true });
  mkdirSync(packageDir, { recursive: true });
  const packed = run("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", packDir], { cwd: repoRoot });
  let packMeta;
  try { packMeta = JSON.parse(packed.stdout); } catch { fail("npm pack did not return JSON"); }
  const filename = packMeta[0]?.filename;
  if (typeof filename !== "string" || !filename.endsWith(".tgz")) fail("npm pack did not report a tarball");
  const tarball = join(packDir, filename);
  if (!existsSync(tarball)) fail("packed tarball is missing");
  run("tar", ["-xzf", tarball, "-C", packageDir, "--strip-components=1"]);

  const installedPackageJson = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  if (installedPackageJson.name !== "@toadaid/agent-capabilities") fail("clean-room package name mismatch");
  if (!existsSync(join(packageDir, "dist", "src", "index.js"))) fail("clean-room package lacks built root export");
  if (existsSync(join(packageDir, "src")) || existsSync(join(packageDir, "test")) || existsSync(join(packageDir, "scripts"))) {
    fail("clean-room package contains repository-only source/test/script paths");
  }

  // The packed capability code is clean-room. Link only its declared runtime dependency
  // from the already-installed repository dependency set so this deterministic proof
  // never contacts a registry or downloads a browser.
  const playwrightSource = join(repoRoot, "node_modules", "playwright-chromium");
  if (!existsSync(playwrightSource)) fail("declared runtime dependency playwright-chromium is not installed; run npm install/npm ci first");
  mkdirSync(consumerNodeModules, { recursive: true });
  const playwrightTarget = join(consumerNodeModules, "playwright-chromium");
  symlinkSync(realpathSync(playwrightSource), playwrightTarget, "dir");

  const consumerProof = readFileSync(join(repoRoot, "scripts", "v1-agent0-consumer.mjs"), "utf8");
  writeFileSync(join(consumerDir, "proof.mjs"), consumerProof, "utf8");
  const proof = run(process.execPath, ["proof.mjs"], { cwd: consumerDir });
  const line = proof.stdout.trim().split(/\r?\n/).find((item) => item.startsWith("V1_AGENT0_VERTICAL_OK "));
  if (!line) fail(`consumer proof did not emit success marker\n${proof.stdout}`);
  console.log(line);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
