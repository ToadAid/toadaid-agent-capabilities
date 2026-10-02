import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const expectedExports = [
  ".",
  "./policy",
  "./invocation",
  "./budget",
  "./contracts",
  "./replay",
  "./modules",
  "./host-session",
  "./desktop-observation",
  "./desktop-interaction",
  "./host-services",
  "./browser-runtime",
  "./browser-resilience",
];

function fail(message) {
  throw new Error(`package verification failed: ${message}`);
}

if (pkg.name !== "@toadaid/agent-capabilities") fail("unexpected package name");
if (pkg.type !== "module") fail("package must remain ESM");
if (pkg.scripts?.prepare !== "npm run build") fail("Git installs must build through prepare");
if (pkg.scripts?.build !== "tsc -p tsconfig.build.json") fail("distribution build must use tsconfig.build.json");
if (!Array.isArray(pkg.files) || !pkg.files.includes("dist/src") || !pkg.files.includes("README.md")) {
  fail("files allowlist must contain dist/src and README.md");
}

const actualExports = Object.keys(pkg.exports ?? {}).sort();
if (JSON.stringify(actualExports) !== JSON.stringify([...expectedExports].sort())) {
  fail(`public export surface drifted: ${actualExports.join(", ")}`);
}

for (const key of expectedExports) {
  const target = pkg.exports[key];
  if (!target || typeof target.import !== "string" || typeof target.types !== "string") fail(`invalid export mapping for ${key}`);
  for (const field of ["import", "types"]) {
    const path = target[field];
    if (!path.startsWith("./dist/src/")) fail(`${key}.${field} escapes dist/src`);
    if (!existsSync(new URL(`..${path.slice(1)}`, import.meta.url))) fail(`missing built export target: ${path}`);
  }
}

for (const key of expectedExports) {
  const specifier = key === "." ? pkg.name : `${pkg.name}/${key.slice(2)}`;
  const namespace = await import(specifier);
  if (Object.keys(namespace).length === 0) fail(`self-import returned empty namespace: ${specifier}`);
}

const dryRun = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  cwd: new URL("..", import.meta.url),
  encoding: "utf8",
});
if (dryRun.status !== 0) fail(`npm pack --dry-run failed: ${dryRun.stderr.trim()}`);
let packed;
try {
  packed = JSON.parse(dryRun.stdout);
} catch {
  fail("npm pack --dry-run did not return JSON");
}
const files = new Set((packed[0]?.files ?? []).map((entry) => entry.path));
for (const required of ["package.json", "README.md", ...expectedExports.flatMap((key) => {
  const target = pkg.exports[key];
  return [target.import.slice(2), target.types.slice(2)];
})]) {
  if (!files.has(required)) fail(`packed artifact is missing ${required}`);
}
for (const path of files) {
  if (path.startsWith("src/") || path.startsWith("test/") || path.startsWith("dist/test/") || path.startsWith(".github/") || path.startsWith("docs/") || path.startsWith("scripts/")) {
    fail(`packed artifact leaks non-distribution path: ${path}`);
  }
}

console.log(`PACKAGE_DISTRIBUTION_OK exports=${expectedExports.length} files=${files.size}`);
