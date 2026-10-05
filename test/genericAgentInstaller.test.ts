import assert from 'node:assert/strict'
import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import zlib from 'node:zlib'

const root = process.cwd()
const installer = path.join(root, 'bin', 'toadaid-capabilities-install-agent')
/** CAP-WIN-P2: the ONE installer policy lives in this Node core; entrypoints only invoke it. */
const installerCore = path.join(root, 'bin', 'toadaid-capabilities-install-agent.mjs')
const profilePath = path.join(root, 'profiles', 'safe-observe.json')

const SAFE_OBSERVE_IDS = [
  'browser:evidence',
  'workspace:snapshot',
  'workspace:diff',
  'host:process-read',
]

/**
 * CAP-WIN-P1: in CI the installer E2E must execute or FAIL. It may only be
 * skipped (explicitly, never silently passed) on a local, uncommitted checkout.
 */
const installerE2ERequired =
  process.env.TOADAID_REQUIRE_INSTALLER_E2E === '1' || process.env.CI === 'true'

const readJson = <T>(file: string): T => JSON.parse(fs.readFileSync(file, 'utf8')) as T

const sha256 = (bytes: Buffer): string => crypto.createHash('sha256').update(bytes).digest('hex')

function gitStatus(cwd: string): string {
  const status = spawnSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd,
    encoding: 'utf8',
  })
  assert.equal(status.status, 0, status.stderr)
  return status.stdout.trim()
}

function runInstaller(
  script: string,
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
): SpawnSyncReturns<string> {
  return spawnSync('bash', [script, ...args], { cwd: root, encoding: 'utf8', env })
}

/** Minimal ustar reader: every regular file name + bytes in a .tgz. */
function readTgz(tgzPath: string): Map<string, Buffer> {
  const tar = zlib.gunzipSync(fs.readFileSync(tgzPath))
  const entries = new Map<string, Buffer>()
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const field = (start: number, end: number): string =>
      header.subarray(start, end).toString('latin1').replace(/\0.*$/s, '')
    const prefix = field(345, 500)
    const name = prefix ? `${prefix}/${field(0, 100)}` : field(0, 100)
    const size = Number.parseInt(field(124, 136).trim() || '0', 8)
    entries.set(name, Buffer.from(tar.subarray(offset + 512, offset + 512 + size)))
    offset += 512 + Math.ceil(size / 512) * 512
  }
  return entries
}

function readTgzEntry(tgzPath: string, entryName: string): Buffer | null {
  return readTgz(tgzPath).get(entryName) ?? null
}

function gitHead(cwd: string): string {
  return spawnSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).stdout.trim()
}

function gitBlob(cwd: string, spec: string): Buffer {
  const blob = spawnSync('git', ['cat-file', 'blob', spec], { cwd })
  assert.equal(blob.status, 0, String(blob.stderr))
  return blob.stdout
}

/**
 * A scratch clone of the canonical HEAD carrying the working-tree installer
 * entrypoints and sharing the canonical node_modules (ignored locally in the
 * scratch clone only, so the clone itself stays clean).
 */
function scratchCheckout(prefix: string): { scratch: string; checkout: string } {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  const checkout = path.join(scratch, 'checkout')
  const cloned = spawnSync('git', ['clone', '-q', '--no-hardlinks', root, checkout], { encoding: 'utf8' })
  assert.equal(cloned.status, 0, cloned.stderr)
  fs.symlinkSync(path.join(root, 'node_modules'), path.join(checkout, 'node_modules'), 'dir')
  fs.appendFileSync(path.join(checkout, '.git', 'info', 'exclude'), '\nnode_modules\n')
  return { scratch, checkout }
}

function copyWorkingInstaller(checkout: string): void {
  for (const file of ['toadaid-capabilities-install-agent', 'toadaid-capabilities-install-agent.mjs']) {
    fs.copyFileSync(path.join(root, 'bin', file), path.join(checkout, 'bin', file))
  }
}

/**
 * Puts a recording `npm` first on PATH. It forwards every call to the real
 * npm unchanged and, for `npm pack`, records argv, the staged package.json as
 * it existed at pack time, and npm's stderr (where lifecycle banners appear).
 */
function createNpmShim(): { dir: string; logDir: string; env: NodeJS.ProcessEnv } {
  const located = spawnSync('bash', ['-c', 'command -v npm'], { encoding: 'utf8' })
  assert.equal(located.status, 0, 'npm must be on PATH')
  const realNpm = located.stdout.trim()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-npm-shim-'))
  const logDir = path.join(dir, 'log')
  fs.mkdirSync(logDir)
  const shim = path.join(dir, 'bin', 'npm')
  fs.mkdirSync(path.dirname(shim))
  fs.writeFileSync(
    shim,
    [
      '#!/usr/bin/env bash',
      'if [[ "$1" == "pack" ]]; then',
      '  printf \'%s\\n\' "$@" >>"$SHIM_LOG_DIR/pack-argv.txt"',
      '  if [[ -f "$2/package.json" ]]; then cp "$2/package.json" "$SHIM_LOG_DIR/staged-package.json"; fi',
      '  "$REAL_NPM" "$@" 2>>"$SHIM_LOG_DIR/pack-stderr.txt"',
      '  exit $?',
      'fi',
      'exec "$REAL_NPM" "$@"',
      '',
    ].join('\n'),
    { mode: 0o755 },
  )
  return {
    dir,
    logDir,
    env: {
      ...process.env,
      PATH: `${path.dirname(shim)}${path.delimiter}${process.env.PATH ?? ''}`,
      REAL_NPM: realNpm,
      SHIM_LOG_DIR: logDir,
    },
  }
}

test('safe-observe profile is a zero-authority request bundle', () => {
  const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8')) as {
    schemaVersion: string
    profileId: string
    activationDefault: string
    installationGrantsAuthority: boolean
    capabilityGrants: unknown[]
    requestedCapabilities: Array<{ capabilityId: string }>
  }

  assert.equal(profile.schemaVersion, 'toadaid.agent-capability-profile.v1')
  assert.equal(profile.profileId, 'safe-observe')
  assert.equal(profile.activationDefault, 'OFF')
  assert.equal(profile.installationGrantsAuthority, false)
  assert.deepEqual(profile.capabilityGrants, [])
  assert.deepEqual(
    profile.requestedCapabilities.map((entry) => entry.capabilityId),
    SAFE_OBSERVE_IDS,
  )
})

test('generic installer has valid shell syntax and bounded help surface', () => {
  const syntax = spawnSync('bash', ['-n', installer], {
    cwd: root,
    encoding: 'utf8',
  })
  assert.equal(syntax.status, 0, syntax.stderr)

  const help = spawnSync('bash', [installer, '--help'], {
    cwd: root,
    encoding: 'utf8',
  })
  assert.equal(help.status, 0, help.stderr)
  assert.match(help.stdout, /installation makes capability code available; it grants NO authority/i)
  assert.match(help.stdout, /--check-only/)
  assert.match(help.stdout, /safe-observe/)
})

test('check-only reports OFF and zero grants without persistent writes', () => {
  const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-check-'))
  fs.rmSync(stateRoot, { recursive: true, force: true })

  const checked = spawnSync(
    'bash',
    [
      installer,
      '--check-only',
      '--profile',
      'safe-observe',
      '--state-root',
      stateRoot,
    ],
    {
      cwd: root,
      encoding: 'utf8',
    },
  )

  assert.equal(checked.status, 0, checked.stderr)
  const payload = JSON.parse(checked.stdout) as {
    status: string
    activationDefault: string
    capabilityGrants: unknown[]
    installationGrantsAuthority: boolean
    hostMutationPerformed: boolean
    npmPublicationPerformed: boolean
  }

  assert.equal(payload.status, 'CHECK_OK')
  assert.equal(payload.activationDefault, 'OFF')
  assert.deepEqual(payload.capabilityGrants, [])
  assert.equal(payload.installationGrantsAuthority, false)
  assert.equal(payload.hostMutationPerformed, false)
  assert.equal(payload.npmPublicationPerformed, false)
  assert.equal(fs.existsSync(stateRoot), false)
})

test('unknown profile refuses rather than widening scope', () => {
  const refused = spawnSync(
    'bash',
    [installer, '--check-only', '--profile', 'coding-superuser'],
    {
      cwd: root,
      encoding: 'utf8',
    },
  )

  assert.notEqual(refused.status, 0)
  assert.match(refused.stderr, /unsupported profile/i)
})

test('CAP-WIN-P1: package-lock.json is tracked and matches the declared dependency graph', () => {
  const tracked = spawnSync('git', ['ls-files', '--error-unmatch', 'package-lock.json'], {
    cwd: root,
    encoding: 'utf8',
  })
  assert.equal(tracked.status, 0, `package-lock.json must be tracked: ${tracked.stderr}`)

  const pkg = readJson<{
    name: string
    version: string
    devDependencies: Record<string, string>
    peerDependencies: Record<string, string>
  }>(path.join(root, 'package.json'))
  const lock = readJson<{
    name: string
    version: string
    lockfileVersion: number
    packages: Record<
      string,
      {
        version?: string
        resolved?: string
        integrity?: string
        devDependencies?: Record<string, string>
        peerDependencies?: Record<string, string>
      }
    >
  }>(path.join(root, 'package-lock.json'))

  assert.equal(lock.name, pkg.name)
  assert.equal(lock.version, pkg.version)
  assert.equal(lock.lockfileVersion, 3)
  const rootEntry = lock.packages['']
  assert.ok(rootEntry, 'lockfile root entry missing')
  assert.deepEqual(rootEntry.devDependencies, pkg.devDependencies)
  assert.deepEqual(rootEntry.peerDependencies, pkg.peerDependencies)

  for (const [name, version] of Object.entries(pkg.devDependencies)) {
    const locked = lock.packages[`node_modules/${name}`]
    assert.ok(locked, `${name} missing from lockfile`)
    assert.equal(locked.version, version, `${name} must be locked at its exact declared version`)
    assert.match(locked.resolved ?? '', /^https:\/\/registry\.npmjs\.org\//, `${name} must resolve from the npm registry`)
    assert.match(locked.integrity ?? '', /^sha512-/, `${name} must carry sha512 integrity`)
  }
})

test('CAP-WIN-P1: CI installs with npm ci --include=dev under NODE_ENV=production and requires the E2E', () => {
  const ci = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(ci, /npm ci --include=dev/)
  assert.match(ci, /NODE_ENV:\s*production/)
  assert.match(ci, /TOADAID_REQUIRE_INSTALLER_E2E:\s*"1"/)
  assert.match(ci, /INSTALLER_E2E_EXECUTED = YES/)
  assert.doesNotMatch(ci, /run:\s*npm install\b/)

  for (const doc of ['INSTALL_AGENT.md', path.join('docs', 'GENERIC_AGENT_INTEGRATION.md')]) {
    const text = fs.readFileSync(path.join(root, doc), 'utf8')
    assert.match(text, /npm ci --include=dev/, `${doc} must document the canonical dependency install`)
    assert.doesNotMatch(text, /^npm ci$/m, `${doc} must not document bare npm ci`)
  }
})

test('CAP-WIN-P1: dirty checkout still refuses artifact installation (fail-closed)', () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-dirty-'))
  try {
    const checkout = path.join(scratch, 'checkout')
    const cloned = spawnSync('git', ['clone', '-q', '--no-hardlinks', root, checkout], { encoding: 'utf8' })
    assert.equal(cloned.status, 0, cloned.stderr)
    // test the working-tree installer + profile, not whatever HEAD holds
    copyWorkingInstaller(checkout)
    fs.copyFileSync(profilePath, path.join(checkout, 'profiles', 'safe-observe.json'))
    fs.symlinkSync(path.join(root, 'node_modules'), path.join(checkout, 'node_modules'), 'dir')
    fs.writeFileSync(path.join(checkout, 'UNCOMMITTED.txt'), 'dirty\n')
    assert.notEqual(gitStatus(checkout), '')

    const stateRoot = path.join(scratch, 'state')
    const refused = runInstaller(path.join(checkout, 'bin', 'toadaid-capabilities-install-agent'), [
      '--profile',
      'safe-observe',
      '--state-root',
      stateRoot,
    ])
    assert.equal(refused.status, 2, refused.stderr)
    assert.match(refused.stderr, /refusing artifact installation from a dirty checkout/)
    assert.equal(refused.stdout, '')
    assert.equal(fs.existsSync(stateRoot), false, 'a refused install must not create state')
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test('CAP-WIN-P2: bash entrypoint is a thin transport wrapper around the ONE Node installer core', () => {
  assert.equal(fs.existsSync(installerCore), true, 'Node installer core must exist')
  const wrapper = fs
    .readFileSync(installer, 'utf8')
    .split('\n')
    .filter((line) => line.trim() !== '' && !line.trim().startsWith('#'))
  assert.ok(wrapper.length <= 30, `wrapper must stay thin (${wrapper.length} code lines)`)
  const code = wrapper.join('\n')
  assert.match(code, /toadaid-capabilities-install-agent\.mjs/)
  for (const policy of ['safe-observe', 'npm pack', 'activation', 'capabilityGrants', 'sha256', 'manifest', 'git ', 'chmod', 'mktemp', 'tsc']) {
    assert.equal(code.includes(policy), false, `wrapper must not own installer policy: ${policy}`)
  }

  const viaWrapper = spawnSync('bash', [installer, '--help'], { cwd: root, encoding: 'utf8' })
  const viaCore = spawnSync(process.execPath, [installerCore, '--help'], { cwd: root, encoding: 'utf8' })
  assert.equal(viaWrapper.status, 0, viaWrapper.stderr)
  assert.equal(viaCore.status, 0, viaCore.stderr)
  assert.equal(viaWrapper.stdout, viaCore.stdout, 'wrapper and core must expose identical behavior')
  assert.match(viaCore.stdout, /--expect-commit/)

  const refusedViaWrapper = spawnSync('bash', [installer, '--check-only', '--profile', 'coding-superuser'], { cwd: root, encoding: 'utf8' })
  const refusedViaCore = spawnSync(process.execPath, [installerCore, '--check-only', '--profile', 'coding-superuser'], { cwd: root, encoding: 'utf8' })
  assert.equal(refusedViaWrapper.status, 2)
  assert.equal(refusedViaCore.status, 2)
  assert.equal(refusedViaWrapper.stderr, refusedViaCore.stderr)
})

test('CAP-WIN-P2: --expect-commit pins the exact checkout and fails closed', () => {
  const head = gitHead(root)
  const stateRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-pin-')), 'state')
  try {
    const accepted = runInstaller(installer, ['--check-only', '--expect-commit', head, '--state-root', stateRoot])
    assert.equal(accepted.status, 0, accepted.stderr)
    assert.equal((JSON.parse(accepted.stdout) as { head: string; status: string }).head, head)

    const acceptedUpper = runInstaller(installer, ['--check-only', '--expect-commit', head.toUpperCase(), '--state-root', stateRoot])
    assert.equal(acceptedUpper.status, 0, acceptedUpper.stderr)

    const wrong = `${head.slice(0, 39)}${head.endsWith('0') ? '1' : '0'}`
    for (const mode of [['--check-only'], []]) {
      const refused = runInstaller(installer, [...mode, '--expect-commit', wrong, '--state-root', stateRoot])
      assert.equal(refused.status, 2, refused.stderr)
      assert.match(refused.stderr, /does not match --expect-commit/)
      assert.equal(refused.stdout, '')
    }

    for (const malformed of [head.slice(0, 12), 'main', 'HEAD', `${head}0`, `g${head.slice(1)}`]) {
      const refused = runInstaller(installer, ['--check-only', '--expect-commit', malformed, '--state-root', stateRoot])
      assert.equal(refused.status, 2, malformed)
      assert.match(refused.stderr, /--expect-commit must be a full 40-character hex commit id/, malformed)
    }

    const missing = runInstaller(installer, ['--check-only', '--expect-commit'])
    assert.equal(missing.status, 2)
    assert.match(missing.stderr, /--expect-commit requires a value/)

    assert.equal(fs.existsSync(stateRoot), false, 'pin refusals must not write state')
  } finally {
    fs.rmSync(path.dirname(stateRoot), { recursive: true, force: true })
  }
})

test('CAP-WIN-P2: package/profile metadata is read from the pinned git blob, not the working tree', () => {
  const { scratch, checkout } = scratchCheckout('toadaid-cap-blob-')
  try {
    copyWorkingInstaller(checkout)
    const head = gitHead(checkout)
    const blobProfile = gitBlob(checkout, `${head}:profiles/safe-observe.json`)
    // mutate the WORKING TREE only: CRLF line endings (autocrlf-style) + an invalid grant
    const mutated = JSON.parse(blobProfile.toString('utf8')) as Record<string, unknown>
    mutated.activationDefault = 'ALLOW'
    fs.writeFileSync(
      path.join(checkout, 'profiles', 'safe-observe.json'),
      JSON.stringify(mutated, null, 2).replace(/\n/g, '\r\n'),
    )
    const pkgWork = fs.readFileSync(path.join(checkout, 'package.json'), 'utf8')
    fs.writeFileSync(path.join(checkout, 'package.json'), pkgWork.replace(/\n/g, '\r\n'))

    const checked = runInstaller(path.join(checkout, 'bin', 'toadaid-capabilities-install-agent'), [
      '--check-only',
      '--state-root',
      path.join(scratch, 'state'),
    ])
    assert.equal(checked.status, 0, checked.stderr)
    const payload = JSON.parse(checked.stdout) as { profileSha256: string; checkoutClean: boolean; head: string }
    assert.equal(payload.head, head)
    assert.equal(payload.checkoutClean, false)
    assert.equal(payload.profileSha256, sha256(blobProfile), 'profile identity must come from the pinned blob')
    assert.notEqual(payload.profileSha256, sha256(fs.readFileSync(path.join(checkout, 'profiles', 'safe-observe.json'))))
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})

test('CAP-WIN-P1: installer E2E executes from the clean canonical checkout (never silently skipped)', async (t) => {
  const dirty = gitStatus(root)
  if (dirty !== '') {
    if (installerE2ERequired) {
      assert.fail(
        `INSTALLER_E2E_EXECUTED = NO: the installer E2E is required here but the checkout is dirty:\n${dirty}`,
      )
    }
    t.diagnostic('INSTALLER_E2E_EXECUTED = NO (local uncommitted checkout; CI requires execution)')
    t.skip('INSTALLER_E2E_EXECUTED = NO: local checkout has uncommitted changes')
    return
  }

  const shim = createNpmShim()
  const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-install-'))
  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim()
  const repoPkg = readJson<Record<string, unknown>>(path.join(root, 'package.json'))
  const npmVersion = spawnSync('bash', ['-c', 'npm --version'], { encoding: 'utf8' }).stdout.trim()

  try {
    const installed = runInstaller(installer, ['--profile', 'safe-observe', '--state-root', stateRoot], shim.env)
    assert.equal(installed.status, 0, installed.stderr)

    type InstallResult = {
      status: string
      artifactPath: string
      artifactSha256: string
      manifestPath: string
      activation: string
      capabilityGrants: unknown[]
      installationGrantsAuthority: boolean
      hostMutationPerformed: boolean
      npmPublicationPerformed: boolean
    }
    const result = JSON.parse(installed.stdout) as InstallResult

    await t.test('installer reaches READY_FOR_HOST_WIRING', () => {
      assert.equal(result.status, 'READY_FOR_HOST_WIRING')
      assert.equal(result.hostMutationPerformed, false)
      assert.equal(result.npmPublicationPerformed, false)
    })

    await t.test('P1-9 #9: installer generates the exact artifact', () => {
      assert.equal(fs.existsSync(result.artifactPath), true)
      assert.equal(path.basename(result.artifactPath), `toadaid-agent-capabilities-${String(repoPkg.version)}-${head.slice(0, 12)}.tgz`)
      assert.match(result.artifactSha256, /^[0-9a-f]{64}$/)
      assert.equal(sha256(fs.readFileSync(result.artifactPath)), result.artifactSha256)
    })

    await t.test('P1-9 #10-13: manifest generated; OFF, [] grants, no installation authority', () => {
      assert.equal(fs.existsSync(result.manifestPath), true)
      const manifest = readJson<{
        checkout: { head: string; cleanAtInstall: boolean }
        package: { private: boolean; artifactSha256: string; artifactPath: string }
        requestedProfile: { profileId: string; requestedCapabilities: string[] }
        activation: string
        capabilityGrants: unknown[]
        providerBindings: Record<string, unknown>
        authorityOwner: string
        installationGrantsAuthority: boolean
      }>(result.manifestPath)
      assert.equal(manifest.checkout.head, head)
      assert.equal(manifest.checkout.cleanAtInstall, true)
      assert.equal(manifest.package.private, true)
      assert.equal(manifest.package.artifactSha256, result.artifactSha256)
      assert.equal(manifest.package.artifactPath, result.artifactPath)
      assert.equal(manifest.requestedProfile.profileId, 'safe-observe')
      assert.deepEqual(manifest.requestedProfile.requestedCapabilities, SAFE_OBSERVE_IDS)
      assert.equal(manifest.activation, 'OFF')
      assert.equal(result.activation, 'OFF')
      assert.deepEqual(manifest.capabilityGrants, [])
      assert.deepEqual(result.capabilityGrants, [])
      assert.deepEqual(manifest.providerBindings, {})
      assert.equal(manifest.authorityOwner, 'HOST')
      assert.equal(manifest.installationGrantsAuthority, false)
      assert.equal(result.installationGrantsAuthority, false)
    })

    await t.test('P1-9 #5/#6: npm pack received a staged package.json with NO scripts, and succeeded', () => {
      const argv = fs.readFileSync(path.join(shim.logDir, 'pack-argv.txt'), 'utf8').split('\n')
      assert.equal(argv[0], 'pack')
      assert.ok(argv.includes('--ignore-scripts'), '--ignore-scripts kept as defense in depth')
      const staged = readJson<Record<string, unknown>>(path.join(shim.logDir, 'staged-package.json'))
      assert.equal(Object.hasOwn(staged, 'scripts'), false, 'staged package.json must not contain scripts')
      const { scripts: _scripts, ...expectedStaged } = repoPkg
      assert.deepEqual(staged, expectedStaged, 'only scripts may be removed from the staged package.json')
      assert.ok(Object.hasOwn(repoPkg, 'scripts'), 'repository package.json keeps its scripts')
      t.diagnostic(`npm --version used for the artifact pack: ${npmVersion}`)
    })

    await t.test('P1-9 #7: the repository prepare/build hook is not invoked by the artifact pack', () => {
      const stderrLog = path.join(shim.logDir, 'pack-stderr.txt')
      const packStderr = fs.existsSync(stderrLog) ? fs.readFileSync(stderrLog, 'utf8') : ''
      assert.doesNotMatch(packStderr, /^> .+ (prepare|prepack|postpack|build)$/m, packStderr)
      assert.doesNotMatch(packStderr, /tsc -p tsconfig\.build\.json/, packStderr)
    })

    await t.test('P1-9 #5: the generated .tgz package.json contains no scripts field', () => {
      const packed = readTgzEntry(result.artifactPath, 'package/package.json')
      assert.ok(packed, 'artifact must contain package/package.json')
      const packedPkg = JSON.parse(packed.toString('utf8')) as Record<string, unknown>
      assert.equal(Object.hasOwn(packedPkg, 'scripts'), false)
      assert.equal(packedPkg.name, repoPkg.name)
      assert.equal(packedPkg.version, repoPkg.version)
      assert.equal(packedPkg.private, true)
      assert.deepEqual(packedPkg.exports, repoPkg.exports)
    })

    await t.test('P2: the artifact carries no source maps; declarations and exports are intact', () => {
      const entries = readTgz(result.artifactPath)
      const names = [...entries.keys()]
      assert.deepEqual(names.filter((name) => name.endsWith('.map')), [], 'no .map files in the install artifact')
      for (const [name, bytes] of entries) {
        if (name.endsWith('.js')) assert.equal(bytes.includes('sourceMappingURL'), false, `${name} must not reference a source map`)
      }
      const exportsMap = repoPkg.exports as Record<string, { types: string; import: string }>
      for (const [key, target] of Object.entries(exportsMap)) {
        assert.ok(entries.has(`package/${target.types.replace(/^\.\//, '')}`), `${key} types present`)
        assert.ok(entries.has(`package/${target.import.replace(/^\.\//, '')}`), `${key} import present`)
      }
      for (const name of names) {
        assert.equal(name.includes(root), false, `${name} must not embed the checkout path`)
        assert.equal(entries.get(name)?.includes(root), false, `${name} content must not embed the checkout path`)
      }
    })

    await t.test('P2: manifest profile identity is the pinned git blob', () => {
      const manifest = readJson<{ requestedProfile: { profileSha256: string } }>(result.manifestPath)
      assert.equal(manifest.requestedProfile.profileSha256, sha256(gitBlob(root, `${head}:profiles/safe-observe.json`)))
    })

    await t.test('P2: the same commit installed from a different checkout path yields the identical artifact sha256', () => {
      const { scratch, checkout } = scratchCheckout('toadaid-cap-second-path-')
      try {
        assert.equal(gitStatus(checkout), '', 'second checkout must be clean')
        assert.equal(gitHead(checkout), head)
        const second = runInstaller(
          path.join(checkout, 'bin', 'toadaid-capabilities-install-agent'),
          ['--profile', 'safe-observe', '--expect-commit', head, '--state-root', path.join(scratch, 'state')],
        )
        assert.equal(second.status, 0, second.stderr)
        const secondResult = JSON.parse(second.stdout) as InstallResult
        assert.equal(secondResult.artifactSha256, result.artifactSha256)
        assert.equal(path.basename(secondResult.artifactPath), path.basename(result.artifactPath))
      } finally {
        fs.rmSync(scratch, { recursive: true, force: true })
      }
    })

    await t.test('P1-9 #16: identical rerun is idempotent (P2: pinned with --expect-commit)', () => {
      const artifactBefore = fs.readFileSync(result.artifactPath)
      const manifestBefore = fs.readFileSync(result.manifestPath)
      const rerun = runInstaller(installer, ['--profile', 'safe-observe', '--expect-commit', head, '--state-root', stateRoot], shim.env)
      assert.equal(rerun.status, 0, rerun.stderr)
      const again = JSON.parse(rerun.stdout) as InstallResult
      assert.equal(again.artifactSha256, result.artifactSha256)
      assert.equal(again.artifactPath, result.artifactPath)
      assert.ok(fs.readFileSync(result.artifactPath).equals(artifactBefore))
      assert.ok(fs.readFileSync(result.manifestPath).equals(manifestBefore))
    })

    await t.test('P1-9 #17: conflicting existing output is refused (exit 2) and left untouched', () => {
      const conflicting = Buffer.concat([fs.readFileSync(result.manifestPath), Buffer.from('\n')])
      fs.writeFileSync(result.manifestPath, conflicting)
      const refused = runInstaller(installer, ['--profile', 'safe-observe', '--state-root', stateRoot], shim.env)
      assert.equal(refused.status, 2, refused.stderr)
      assert.match(refused.stderr, /refusing to overwrite different existing file/)
      assert.ok(fs.readFileSync(result.manifestPath).equals(conflicting))
    })

    await t.test('the canonical checkout is still clean after the installer ran', () => {
      assert.equal(gitStatus(root), '')
    })

    t.diagnostic('INSTALLER_E2E_EXECUTED = YES')
    console.log('INSTALLER_E2E_EXECUTED = YES')
  } finally {
    fs.rmSync(stateRoot, { recursive: true, force: true })
    fs.rmSync(shim.dir, { recursive: true, force: true })
  }
})
