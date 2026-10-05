#!/usr/bin/env node
// ToadAid Agent Capabilities — generic-agent installer core (CAP-WIN-P2)
//
// This file is the ONE installer policy. Every platform entrypoint (the POSIX
// bash wrapper today, a native Windows wrapper later) only locates Node and
// invokes this core; none of them may add, remove, or reinterpret policy.
//
// It prepares an exact local package artifact plus a host-owned integration
// manifest. It DOES NOT wire a host, grant capability authority, modify host
// policy, enable ALLOW, execute providers, publish to npm, or install into a
// host repository.
//
// Refusals print `toadaid-capabilities-install-agent: <reason>` to stderr and
// exit with code 2. No partial output is left behind on refusal.

import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const PROGRAM = 'toadaid-capabilities-install-agent'
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const PROFILE_PATH = 'profiles/safe-observe.json'
const SAFE_OBSERVE_CAPABILITIES = Object.freeze([
  'browser:evidence',
  'workspace:snapshot',
  'workspace:diff',
  'host:process-read',
])

const USAGE = `Usage: bin/toadaid-capabilities-install-agent [options]

Prepare a checked-out ToadAid Agent Capabilities repository for integration
into a generic Node.js agent.

Options:
  --profile NAME       requested capability profile (default: safe-observe)
  --state-root PATH    host-owned integration state root
  --artifact-root PATH generated local package artifact directory
  --manifest PATH      integration manifest path
  --expect-commit SHA  refuse unless the checkout HEAD is exactly this commit
  --check-only         verify prerequisites and report without writing
  -h, --help           show this help

Security boundary:
  Installation makes capability code available; it grants NO authority.
  The generated profile request starts OFF with zero capability grants.
  Host policy, provider bindings, approvals, secrets, and ALLOW transitions
  remain host-owned and must be wired separately.
`

class Refusal extends Error {}

/** Refuse with the canonical message; the caller unwinds and exits 2. */
function refuse(reason) {
  throw new Refusal(reason)
}

function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`)
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

function commandAvailable(name) {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (dir === '') continue
    const candidate = path.join(dir, name)
    try {
      if (fs.statSync(candidate).isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK)
        return true
      }
    } catch {
      // keep searching PATH
    }
  }
  return false
}

function git(args, options = {}) {
  return spawnSync('git', ['-C', REPO_ROOT, ...args], {
    encoding: options.encoding ?? 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  })
}

/** Exact bytes of a path at the pinned commit (never the mutable working tree). */
function readPinnedBlob(commit, repoPath) {
  const blob = git(['cat-file', 'blob', `${commit}:${repoPath}`], { encoding: 'buffer' })
  return blob.status === 0 ? blob.stdout : null
}

function parseJson(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch {
    return null
  }
}

function validPackageIdentity(pkg) {
  return (
    pkg !== null &&
    pkg.name === '@toadaid/agent-capabilities' &&
    pkg.private === true &&
    typeof pkg.version === 'string' &&
    pkg.engines?.node === '>=22'
  )
}

function validSafeObserveProfile(profile) {
  const ids = profile?.requestedCapabilities?.map((entry) => entry.capabilityId) ?? []
  return (
    profile !== null &&
    profile.schemaVersion === 'toadaid.agent-capability-profile.v1' &&
    profile.profileId === 'safe-observe' &&
    profile.activationDefault === 'OFF' &&
    profile.installationGrantsAuthority === false &&
    Array.isArray(profile.capabilityGrants) &&
    profile.capabilityGrants.length === 0 &&
    JSON.stringify(ids) === JSON.stringify(SAFE_OBSERVE_CAPABILITIES)
  )
}

/** mv semantics: rename, falling back to an exclusive copy across filesystems. */
function moveFile(source, target) {
  try {
    fs.renameSync(source, target)
  } catch (error) {
    if (error?.code !== 'EXDEV') throw error
    fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL)
    fs.unlinkSync(source)
  }
}

/**
 * Create-once install of `source` at `target` with `mode`. An existing file is
 * accepted only when byte-identical (idempotent rerun); symlinks, non-regular
 * files, and different bytes are refused.
 */
function writeExact(target, mode, source) {
  let existing = null
  try {
    existing = fs.lstatSync(target)
  } catch {
    existing = null
  }

  if (existing?.isSymbolicLink()) refuse(`refusing symlink target: ${target}`)

  if (existing !== null) {
    if (!existing.isFile()) refuse(`refusing non-regular existing target: ${target}`)
    if (!fs.readFileSync(source).equals(fs.readFileSync(target))) {
      refuse(`refusing to overwrite different existing file: ${target}`)
    }
    let chmodFailed = false
    try {
      fs.chmodSync(target, mode)
    } catch {
      chmodFailed = true
    }
    fs.rmSync(source, { force: true })
    if (chmodFailed) refuse(`cannot set mode on existing target: ${target}`)
    return
  }

  try {
    moveFile(source, target)
  } catch {
    refuse(`cannot install target: ${target}`)
  }
  try {
    fs.chmodSync(target, mode)
  } catch {
    refuse(`cannot set mode on target: ${target}`)
  }
}

function parseArguments(argv, defaults) {
  const options = { ...defaults, help: false }
  for (let index = 0; index < argv.length; ) {
    const arg = argv[index]
    const takesValue = {
      '--profile': 'profile',
      '--state-root': 'stateRoot',
      '--artifact-root': 'artifactRoot',
      '--manifest': 'manifestPath',
      '--expect-commit': 'expectCommit',
    }[arg]
    if (takesValue !== undefined) {
      if (index + 1 >= argv.length) refuse(`${arg} requires a value`)
      options[takesValue] = argv[index + 1]
      index += 2
    } else if (arg === '--check-only') {
      options.checkOnly = true
      index += 1
    } else if (arg === '-h' || arg === '--help') {
      options.help = true
      return options
    } else {
      refuse(`unknown argument: ${arg}`)
    }
  }
  return options
}

function install(argv) {
  process.umask(0o077)

  const home = process.env.HOME ?? ''
  const xdgStateHome = process.env.XDG_STATE_HOME ?? ''
  const defaults = {
    profile: 'safe-observe',
    stateRoot: `${xdgStateHome !== '' ? xdgStateHome : `${home}/.local/state`}/toadaid-agent-capabilities`,
    artifactRoot: '',
    manifestPath: '',
    expectCommit: '',
    checkOnly: false,
  }

  if (home === '') refuse('HOME must be set')

  const options = parseArguments(argv, defaults)
  if (options.help) {
    process.stdout.write(USAGE)
    return
  }

  if (options.profile !== 'safe-observe') {
    refuse(`unsupported profile in Generic Install P1: ${options.profile}`)
  }

  let expectedCommit = null
  if (options.expectCommit !== '') {
    if (!/^[0-9a-fA-F]{40}$/.test(options.expectCommit)) {
      refuse('--expect-commit must be a full 40-character hex commit id')
    }
    expectedCommit = options.expectCommit.toLowerCase()
  }

  for (const command of ['git', 'npm']) {
    if (!commandAvailable(command)) refuse(`required command unavailable: ${command}`)
  }

  const [nodeMajor] = process.versions.node.split('.').map(Number)
  if (!(nodeMajor >= 22)) refuse('Node.js 22 or newer is required')

  const tscBin = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsc')
  try {
    fs.accessSync(tscBin, fs.constants.X_OK)
  } catch {
    refuse('checkout build dependencies are missing; run npm ci --include=dev in the checkout first')
  }

  // ---- exact checkout identity; every canonical byte below is read from it
  const headResult = git(['rev-parse', '--verify', 'HEAD^{commit}'])
  const head = headResult.status === 0 ? headResult.stdout.trim() : ''
  if (!/^[0-9a-f]{40}$/.test(head)) refuse('cannot resolve exact checkout/profile identity')

  if (expectedCommit !== null && head !== expectedCommit) {
    refuse(`checkout HEAD ${head} does not match --expect-commit ${expectedCommit}`)
  }

  const packageBytes = readPinnedBlob(head, 'package.json')
  const profileBytes = readPinnedBlob(head, PROFILE_PATH)
  if (packageBytes === null || profileBytes === null) {
    refuse('package.json or safe-observe profile is missing')
  }

  const pkg = parseJson(packageBytes)
  if (!validPackageIdentity(pkg)) refuse('package identity/private-runtime contract is invalid')
  if (!validSafeObserveProfile(parseJson(profileBytes))) refuse('safe-observe profile contract is invalid')

  const treeResult = git(['rev-parse', `${head}^{tree}`])
  const tree = treeResult.status === 0 ? treeResult.stdout.trim() : ''
  if (!/^[0-9a-f]{40}$/.test(tree)) refuse('cannot resolve exact checkout/profile identity')
  const branch = git(['branch', '--show-current']).stdout?.trim() ?? ''
  const status = git(['status', '--porcelain=v1', '--untracked-files=all'])
  if (status.status !== 0) refuse('cannot resolve exact checkout/profile identity')
  const clean = status.stdout.trim() === ''

  const stateRoot = path.resolve(options.stateRoot)
  const artifactRoot = path.resolve(options.artifactRoot !== '' ? options.artifactRoot : path.join(stateRoot, 'artifacts'))
  const manifestPath = path.resolve(options.manifestPath !== '' ? options.manifestPath : path.join(stateRoot, 'agent-integration.json'))
  const profileSha256 = sha256(profileBytes)

  if (options.checkOnly) {
    printJson({
      schemaVersion: 'toadaid.agent-capabilities-install-check.v1',
      status: 'CHECK_OK',
      distribution: 'CHECKOUT_LOCAL_TO_LOCAL_TARBALL',
      checkoutRoot: REPO_ROOT,
      branch,
      head,
      tree,
      checkoutClean: clean,
      packageName: pkg.name,
      packageVersion: pkg.version,
      packagePrivate: pkg.private === true,
      profile: options.profile,
      profileSha256,
      stateRoot,
      artifactRoot,
      manifestPath,
      installationGrantsAuthority: false,
      activationDefault: 'OFF',
      capabilityGrants: [],
      npmPublicationPerformed: false,
      hostMutationPerformed: false,
    })
    return
  }

  if (!clean) refuse('refusing artifact installation from a dirty checkout; commit/review or use --check-only')

  const installDirectories = [stateRoot, artifactRoot, path.dirname(manifestPath)]
  try {
    for (const directory of installDirectories) fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  } catch {
    refuse('cannot create host-owned state/artifact directories')
  }
  for (const directory of installDirectories) {
    let stat = null
    try {
      stat = fs.lstatSync(directory)
    } catch {
      stat = null
    }
    if (stat === null || stat.isSymbolicLink() || !stat.isDirectory()) {
      refuse(`installation directory must be a real directory: ${directory}`)
    }
  }

  let tmpRoot
  try {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-capabilities-install.'))
  } catch {
    refuse('cannot create temporary staging root')
  }

  try {
    const stage = path.join(tmpRoot, 'package')
    const packOut = path.join(tmpRoot, 'pack')
    try {
      fs.mkdirSync(path.join(stage, 'dist'), { recursive: true })
      fs.mkdirSync(packOut, { recursive: true })
    } catch {
      refuse('cannot create package staging directories')
    }

    // Staged metadata comes from the pinned commit. The staged package.json
    // carries NO lifecycle scripts (npm 10 runs `prepare` for `npm pack <dir>`
    // despite --ignore-scripts, which stays as defense in depth only).
    try {
      const stagedPkg = { ...pkg }
      delete stagedPkg.scripts
      fs.writeFileSync(path.join(stage, 'package.json'), `${JSON.stringify(stagedPkg, null, 2)}\n`, { flag: 'wx' })
      for (const file of ['README.md', 'LICENSE']) {
        const bytes = readPinnedBlob(head, file)
        if (bytes === null) throw new Error(`missing ${file}`)
        fs.writeFileSync(path.join(stage, file), bytes, { flag: 'wx' })
      }
      if (Object.hasOwn(parseJson(fs.readFileSync(path.join(stage, 'package.json'))) ?? { scripts: true }, 'scripts')) {
        throw new Error('staged package.json still carries scripts')
      }
    } catch {
      refuse('cannot stage package metadata')
    }

    // Out-of-tree build of the clean (== pinned) checkout. Source maps are not
    // part of the published surface (they point at src/, which is never
    // packed) and would embed checkout-relative paths, so the artifact build
    // emits none. tsc output goes to stderr so stdout stays pure JSON.
    const build = spawnSync(
      tscBin,
      ['-p', 'tsconfig.build.json', '--outDir', path.join(stage, 'dist'), '--sourceMap', 'false'],
      { cwd: REPO_ROOT, stdio: ['ignore', process.stderr, process.stderr] },
    )
    if (build.status !== 0) refuse('out-of-tree TypeScript build failed')

    const missing = []
    for (const entry of Object.values(pkg.exports ?? {})) {
      for (const key of ['types', 'import']) {
        const rel = entry?.[key]
        if (typeof rel === 'string' && !fs.existsSync(path.join(stage, rel))) missing.push(rel)
      }
    }
    if (missing.length > 0) {
      process.stderr.write(`missing export targets: ${missing.join(', ')}\n`)
      refuse('staged package export verification failed')
    }

    const pack = spawnSync('npm', ['pack', stage, '--ignore-scripts', '--pack-destination', packOut, '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    })
    const packedName = pack.status === 0 ? (parseJson(Buffer.from(pack.stdout ?? ''))?.[0]?.filename ?? '') : ''
    if (packedName === '' || !fs.existsSync(path.join(packOut, packedName))) {
      refuse('local package artifact creation failed')
    }

    const artifactName = `toadaid-agent-capabilities-${pkg.version}-${head.slice(0, 12)}.tgz`
    const artifactTarget = path.join(artifactRoot, artifactName)
    const artifactTemp = path.join(tmpRoot, artifactName)
    try {
      fs.renameSync(path.join(packOut, packedName), artifactTemp)
    } catch {
      refuse('cannot stage exact artifact')
    }

    let artifactSha256
    try {
      artifactSha256 = sha256(fs.readFileSync(artifactTemp))
    } catch {
      refuse('cannot hash package artifact')
    }

    writeExact(artifactTarget, 0o600, artifactTemp)

    const manifestTemp = path.join(tmpRoot, 'agent-integration.json')
    try {
      fs.writeFileSync(
        manifestTemp,
        `${JSON.stringify(
          {
            schemaVersion: 'toadaid.agent-capabilities-integration-manifest.v1',
            distribution: 'LOCAL_TARBALL_FROM_EXACT_CHECKOUT',
            checkout: {
              root: REPO_ROOT,
              branch,
              head,
              tree,
              cleanAtInstall: true,
            },
            package: {
              name: pkg.name,
              version: pkg.version,
              private: true,
              artifactPath: artifactTarget,
              artifactSha256,
            },
            requestedProfile: {
              profileId: options.profile,
              profileSha256,
              requestedCapabilities: [...SAFE_OBSERVE_CAPABILITIES],
            },
            activation: 'OFF',
            capabilityGrants: [],
            providerBindings: {},
            authorityOwner: 'HOST',
            installationGrantsAuthority: false,
            hostPolicyChanged: false,
            hostRuntimeChanged: false,
            hostSecretsChanged: false,
            npmPublicationPerformed: false,
            manifestPath,
          },
          null,
          2,
        )}\n`,
        { flag: 'wx' },
      )
    } catch {
      refuse('cannot generate integration manifest')
    }

    writeExact(manifestPath, 0o600, manifestTemp)

    printJson({
      schemaVersion: 'toadaid.agent-capabilities-install-result.v1',
      status: 'READY_FOR_HOST_WIRING',
      artifactPath: artifactTarget,
      artifactSha256,
      manifestPath,
      requestedProfile: options.profile,
      activation: 'OFF',
      capabilityGrants: [],
      installationGrantsAuthority: false,
      hostMutationPerformed: false,
      npmPublicationPerformed: false,
    })
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true })
  }
}

try {
  install(process.argv.slice(2))
} catch (error) {
  if (!(error instanceof Refusal)) throw error
  process.stderr.write(`${PROGRAM}: ${error.message}\n`)
  process.exitCode = 2
}
