import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
const packageName = pkg.name;

const declaredSurfaces = [
  "./policy",
  "./invocation",
  "./contracts",
  "./modules",
  "./host-session",
  "./workspace-history",
  "./desktop-observation",
  "./desktop-interaction",
  "./host-services",
  "./browser-runtime",
];

const hostSurfaces = declaredSurfaces.filter(
  (key) => key !== "./browser-runtime",
);

const forbiddenHostFiles = new Set([
  "browserRuntime.js",
  "browserEvidence.js",
  "browserInteraction.js",
  "browserRuntime.d.ts",
  "browserEvidence.d.ts",
  "browserInteraction.d.ts",
]);

function fail(message) {
  throw new Error(`package surface verification failed: ${message}`);
}

function exportSpecifier(key) {
  return `${packageName}/${key.slice(2)}`;
}

function staticSpecifiers(source) {
  const found = new Set();
  const patterns = [
    /(?:import|export)\s+(?:type\s+)?(?:[^"'()]*?\s+from\s+)?["']([^"']+)["']/g,
    /import\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]) found.add(match[1]);
    }
  }
  return [...found];
}

function resolveRelativeImport(fromFile, specifier) {
  const candidate = resolve(dirname(fromFile), specifier);

  if (fromFile.endsWith(".d.ts") && candidate.endsWith(".js")) {
    const declarationCandidate =
      `${candidate.slice(0, -3)}.d.ts`;
    if (existsSync(declarationCandidate)) {
      return declarationCandidate;
    }
  }

  if (existsSync(candidate)) return candidate;
  fail(`missing relative dependency ${specifier} from ${fromFile}`);
}

function walkGraph(entryFile) {
  const pending = [entryFile];
  const visited = new Set();
  const external = new Set();

  while (pending.length > 0) {
    const current = pending.pop();
    if (visited.has(current)) continue;
    visited.add(current);

    const source = readFileSync(current, "utf8");
    for (const specifier of staticSpecifiers(source)) {
      if (specifier.startsWith(".")) {
        const resolved = resolveRelativeImport(current, specifier);
        pending.push(resolved);
      } else if (!specifier.startsWith("node:")) {
        external.add(specifier);
      }
    }
  }

  return { visited, external };
}

function assertHostGraphClean(key, field) {
  const target = pkg.exports?.[key]?.[field];
  if (typeof target !== "string") {
    fail(`missing ${field} mapping for ${key}`);
  }
  const entry = resolve(root, target.replace(/^\.\//, ""));
  const graph = walkGraph(entry);

  if (graph.external.has("playwright-chromium")) {
    fail(`${key}.${field} reaches playwright-chromium`);
  }

  for (const file of graph.visited) {
    const basename = file.split(/[\\/]/).pop();
    if (forbiddenHostFiles.has(basename)) {
      fail(`${key}.${field} reaches browser runtime implementation: ${basename}`);
    }
  }
}

for (const key of declaredSurfaces) {
  const mapping = pkg.exports?.[key];
  if (!mapping || typeof mapping.import !== "string" || typeof mapping.types !== "string") {
    fail(`missing declared D2 surface: ${key}`);
  }
}

for (const key of hostSurfaces) {
  assertHostGraphClean(key, "import");
  assertHostGraphClean(key, "types");
}

const browserImportTarget = resolve(
  root,
  pkg.exports["./browser-runtime"].import.replace(/^\.\//, ""),
);
const browserGraph = walkGraph(browserImportTarget);
if (!browserGraph.external.has("playwright-chromium")) {
  fail("./browser-runtime must own the Playwright runtime dependency boundary");
}

if (pkg.dependencies?.["playwright-chromium"]) {
  fail("playwright-chromium must not be a normal runtime dependency");
}
if (pkg.peerDependencies?.["playwright-chromium"] !== "1.63.0") {
  fail("browser runtime Playwright peer version drifted");
}
if (pkg.peerDependenciesMeta?.["playwright-chromium"]?.optional !== true) {
  fail("playwright-chromium peer must remain optional for host-only installs");
}
if (pkg.devDependencies?.["playwright-chromium"] !== "1.63.0") {
  fail("development build must retain exact Playwright dependency");
}

const temp = mkdtempSync(join(tmpdir(), "toadaid-d2-consumer-"));
try {
  const packed = spawnSync(
    "npm",
    [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      temp,
    ],
    {
      cwd: root,
      encoding: "utf8",
    },
  );
  if (packed.status !== 0) {
    fail(`npm pack failed: ${packed.stderr.trim()}`);
  }

  let packedJson;
  try {
    packedJson = JSON.parse(packed.stdout);
  } catch {
    fail("npm pack did not return JSON");
  }
  const filename = packedJson[0]?.filename;
  if (typeof filename !== "string") {
    fail("npm pack result did not contain filename");
  }

  writeFileSync(
    join(temp, "package.json"),
    JSON.stringify(
      {
        name: "toadaid-d2-host-consumer-proof",
        private: true,
        type: "module",
      },
      null,
      2,
    ) + "\n",
  );

  const installed = spawnSync(
    "npm",
    [
      "install",
      join(temp, filename),
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    {
      cwd: temp,
      encoding: "utf8",
    },
  );
  if (installed.status !== 0) {
    fail(`host-only tarball install failed: ${installed.stderr.trim()}`);
  }

  if (existsSync(join(temp, "node_modules", "playwright-chromium"))) {
    fail("host-only install pulled playwright-chromium");
  }

  const runtimeConsumer = hostSurfaces
    .map((key) => `await import(${JSON.stringify(exportSpecifier(key))});`)
    .join("\n");
  writeFileSync(
    join(temp, "consumer.mjs"),
    `${runtimeConsumer}\nconsole.log("D2_HOST_RUNTIME_IMPORTS_OK");\n`,
  );

  const runtimeProof = spawnSync(
    process.execPath,
    [join(temp, "consumer.mjs")],
    {
      cwd: temp,
      encoding: "utf8",
    },
  );
  if (runtimeProof.status !== 0) {
    fail(`host runtime subpath import failed: ${runtimeProof.stderr.trim()}`);
  }

  const typeConsumer = hostSurfaces
    .map(
      (key, index) =>
        `type Surface${index} = typeof import(${JSON.stringify(exportSpecifier(key))});`,
    )
    .join("\n");
  writeFileSync(
    join(temp, "consumer.mts"),
    `${typeConsumer}\nexport {};\n`,
  );

  const tscBin = fileURLToPath(
    new URL("../node_modules/typescript/bin/tsc", import.meta.url),
  );
  const typeProof = spawnSync(
    process.execPath,
    [
      tscBin,
      "--noEmit",
      "--target",
      "ES2022",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--skipLibCheck",
      "false",
      "--typeRoots",
      join(root, "node_modules", "@types"),
      join(temp, "consumer.mts"),
    ],
    {
      cwd: temp,
      encoding: "utf8",
    },
  );
  if (typeProof.status !== 0) {
    fail(`host type subpath import failed: ${typeProof.stderr.trim() || typeProof.stdout.trim()}`);
  }

  console.log(
    `PACKAGE_SURFACES_OK declared=${declaredSurfaces.length} host=${hostSurfaces.length} playwrightInstalled=false`,
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
}
