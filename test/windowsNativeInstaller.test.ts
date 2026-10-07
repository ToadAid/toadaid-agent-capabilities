import assert from 'node:assert/strict'
import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import zlib from 'node:zlib'

/**
 * CAP-WIN-P3: native Windows proof of the ONE installer core through the ONE
 * native transport, bin\toadaid-capabilities-install-agent.cmd.
 *
 * - runs only on native win32 (cmd.exe; no Git Bash, no WSL, no PowerShell script);
 * - in CI (CI=true or TOADAID_REQUIRE_INSTALLER_E2E=1) it must execute or FAIL;
 * - on other platforms it is an explicit skip and never prints the E2E sentinel.
 */

const root = process.cwd()
const wrapper = path.join(root, 'bin', 'toadaid-capabilities-install-agent.cmd')
const core = path.join(root, 'bin', 'toadaid-capabilities-install-agent.mjs')
const installerE2ERequired =
  process.env.TOADAID_REQUIRE_INSTALLER_E2E === '1' || process.env.CI === 'true'

const sha256 = (bytes: Buffer): string => crypto.createHash('sha256').update(bytes).digest('hex')

type CheckResult = { status: string; head: string; stateRoot: string; artifactRoot: string; manifestPath: string; checkoutClean: boolean }
type InstallResult = {
  status: string
  artifactPath: string
  artifactSha256: string
  manifestPath: string
  activation: string
  capabilityGrants: unknown[]
  installationGrantsAuthority: boolean
}

function git(cwd: string, args: string[]): string {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  return result.stdout.trim()
}

/** process.env copy with the given keys removed case-insensitively (Windows env keys are case-insensitive). */
function envWithout(...keys: string[]): Record<string, string> {
  const drop = new Set(keys.map((key) => key.toLowerCase()))
  const env: Record<string, string> = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !drop.has(key.toLowerCase())) env[key] = value
  }
  return env
}

/**
 * Invoke a .cmd entrypoint natively through cmd.exe. Node refuses to spawn
 * .cmd files without a shell, so the test (never the installer) launches
 * cmd.exe explicitly with a fully quoted, test-controlled command line.
 */
function runCmd(entrypoint: string, args: string[], env: Record<string, string>, cwd = root): SpawnSyncReturns<string> {
  for (const arg of [entrypoint, ...args]) assert.doesNotMatch(arg, /["%^&|<>]/, `test argument must not need cmd escaping: ${arg}`)
  const line = [entrypoint, ...args].map((arg) => `"${arg}"`).join(' ')
  return spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `"${line}"`], {
    cwd,
    env,
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  })
}

function tarModes(tgzPath: string): string[] {
  const tar = zlib.gunzipSync(fs.readFileSync(tgzPath))
  const modes: string[] = []
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const field = (start: number, end: number): string =>
      header.subarray(start, end).toString('latin1').replace(/\0.*$/s, '')
    modes.push(field(100, 108).trim())
    const size = Number.parseInt(field(124, 136).trim() || '0', 8)
    offset += 512 + Math.ceil(size / 512) * 512
  }
  return modes
}

function listTree(dir: string): string[] {
  if (!fs.existsSync(dir)) return []
  return fs.readdirSync(dir, { recursive: true }).map(String).sort()
}

test('CAP-WIN-P3: native Windows installer through the .cmd entrypoint (never silently skipped)', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('native Windows only (this platform runs the POSIX proof in genericAgentInstaller.test)')
    return
  }
  const dirty = spawnSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root, encoding: 'utf8' }).stdout.trim()
  if (dirty !== '') {
    if (installerE2ERequired) assert.fail(`INSTALLER_E2E_EXECUTED = NO: native Windows E2E required but the checkout is dirty:\n${dirty}`)
    t.diagnostic('INSTALLER_E2E_EXECUTED = NO (local uncommitted checkout; CI requires execution)')
    t.skip('INSTALLER_E2E_EXECUTED = NO: local checkout has uncommitted changes')
    return
  }

  const head = git(root, ['rev-parse', 'HEAD'])
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-win-'))
  const localAppData = path.join(scratch, 'Local App Data')
  const temptingXdg = path.join(scratch, 'tempting-xdg-state')
  fs.mkdirSync(localAppData)
  const nativeEnv = { ...envWithout('HOME', 'XDG_STATE_HOME', 'LOCALAPPDATA'), LOCALAPPDATA: localAppData, XDG_STATE_HOME: temptingXdg }
  const defaultStateRoot = path.join(localAppData, 'toadaid-agent-capabilities')
  const junctions: string[] = []

  try {
    await t.test('.cmd and core expose identical help and identical refusals', () => {
      const helpCmd = runCmd(wrapper, ['--help'], nativeEnv)
      const helpCore = spawnSync(process.execPath, [core, '--help'], { cwd: root, env: nativeEnv, encoding: 'utf8' })
      assert.equal(helpCmd.status, 0, helpCmd.stderr)
      assert.equal(helpCmd.stdout, helpCore.stdout)
      const refusedCmd = runCmd(wrapper, ['--check-only', '--profile', 'coding-superuser'], nativeEnv)
      const refusedCore = spawnSync(process.execPath, [core, '--check-only', '--profile', 'coding-superuser'], { cwd: root, env: nativeEnv, encoding: 'utf8' })
      assert.equal(refusedCmd.status, 2, 'exit code 2 must survive the .cmd transport')
      assert.equal(refusedCore.status, 2)
      assert.equal(refusedCmd.stderr, refusedCore.stderr)
    })

    await t.test('--check-only with HOME absent uses LOCALAPPDATA, ignores XDG_STATE_HOME, writes nothing', () => {
      const checked = runCmd(wrapper, ['--check-only'], nativeEnv)
      assert.equal(checked.status, 0, checked.stderr)
      const payload = JSON.parse(checked.stdout) as CheckResult
      assert.equal(payload.status, 'CHECK_OK')
      assert.equal(payload.head, head)
      assert.equal(payload.checkoutClean, true)
      assert.equal(payload.stateRoot, defaultStateRoot)
      assert.deepEqual(listTree(localAppData), [], 'check-only writes nothing')
      assert.equal(fs.existsSync(temptingXdg), false)
    })

    await t.test('--expect-commit: exact pin accepted; wrong pin refused without state', () => {
      const pinned = runCmd(wrapper, ['--check-only', '--expect-commit', head], nativeEnv)
      assert.equal(pinned.status, 0, pinned.stderr)
      const wrong = `${head.slice(0, 39)}${head.endsWith('0') ? '1' : '0'}`
      const wrongState = path.join(scratch, 'wrong-pin-state')
      for (const mode of [['--check-only'], []]) {
        const refused = runCmd(wrapper, [...mode, '--expect-commit', wrong, '--state-root', wrongState], nativeEnv)
        assert.equal(refused.status, 2, refused.stderr)
        assert.match(refused.stderr, /does not match --expect-commit/)
        assert.equal(refused.stdout, '')
      }
      const refusedDefault = runCmd(wrapper, ['--expect-commit', wrong], nativeEnv)
      assert.equal(refusedDefault.status, 2)
      assert.equal(fs.existsSync(wrongState), false)
      assert.deepEqual(listTree(localAppData), [], 'a refused pin creates no state')
    })

    await t.test('missing LOCALAPPDATA refuses clearly when no --state-root override exists', () => {
      const noLocal = envWithout('HOME', 'XDG_STATE_HOME', 'LOCALAPPDATA')
      noLocal.XDG_STATE_HOME = temptingXdg
      for (const mode of [['--check-only'], []]) {
        const refused = runCmd(wrapper, mode, noLocal)
        assert.equal(refused.status, 2, refused.stderr)
        assert.match(refused.stderr, /LOCALAPPDATA must be set on Windows unless --state-root is given/)
        assert.equal(refused.stdout, '')
      }
      const helped = runCmd(wrapper, ['--help'], noLocal)
      assert.equal(helped.status, 0, 'help needs no state location')
      assert.equal(fs.existsSync(temptingXdg), false, 'XDG_STATE_HOME is never a fallback on Windows')
    })

    await t.test('explicit --state-root wins over LOCALAPPDATA and works without LOCALAPPDATA', () => {
      const explicit = path.join(scratch, 'explicit state')
      const overridden = runCmd(wrapper, ['--check-only', '--state-root', explicit], nativeEnv)
      assert.equal(overridden.status, 0, overridden.stderr)
      assert.equal((JSON.parse(overridden.stdout) as CheckResult).stateRoot, explicit)
      const noLocal = envWithout('HOME', 'XDG_STATE_HOME', 'LOCALAPPDATA')
      const withoutLocal = runCmd(wrapper, ['--check-only', '--state-root', explicit], noLocal)
      assert.equal(withoutLocal.status, 0, withoutLocal.stderr)
      assert.equal((JSON.parse(withoutLocal.stdout) as CheckResult).stateRoot, explicit)
      assert.equal(fs.existsSync(explicit), false)
    })

    // ---- real artifact install, default (LOCALAPPDATA) state root
    const installed = runCmd(wrapper, ['--expect-commit', head], nativeEnv)
    assert.equal(installed.status, 0, installed.stderr)
    const result = JSON.parse(installed.stdout) as InstallResult

    await t.test('real install: HOME absent + tempting XDG_STATE_HOME -> state under LOCALAPPDATA only', () => {
      assert.equal(result.status, 'READY_FOR_HOST_WIRING')
      assert.equal(result.manifestPath, path.join(defaultStateRoot, 'agent-integration.json'))
      assert.equal(path.dirname(result.artifactPath), path.join(defaultStateRoot, 'artifacts'))
      assert.equal(path.basename(result.artifactPath), `toadaid-agent-capabilities-${JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version}-${head.slice(0, 12)}.tgz`)
      assert.equal(fs.existsSync(temptingXdg), false, 'XDG path untouched')
      assert.equal(sha256(fs.readFileSync(result.artifactPath)), result.artifactSha256)
    })

    await t.test('real install: OFF, [] grants, {} providers, no installation authority', () => {
      const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8')) as {
        checkout: { head: string; cleanAtInstall: boolean }
        package: { artifactSha256: string }
        activation: string
        capabilityGrants: unknown[]
        providerBindings: Record<string, unknown>
        authorityOwner: string
        installationGrantsAuthority: boolean
      }
      assert.equal(manifest.checkout.head, head)
      assert.equal(manifest.checkout.cleanAtInstall, true)
      assert.equal(manifest.package.artifactSha256, result.artifactSha256)
      assert.equal(manifest.activation, 'OFF')
      assert.equal(result.activation, 'OFF')
      assert.deepEqual(manifest.capabilityGrants, [])
      assert.deepEqual(result.capabilityGrants, [])
      assert.deepEqual(manifest.providerBindings, {})
      assert.equal(manifest.authorityOwner, 'HOST')
      assert.equal(manifest.installationGrantsAuthority, false)
      assert.equal(result.installationGrantsAuthority, false)
    })

    await t.test('real install: canonical staged modes (every entry 0644)', () => {
      const modes = tarModes(result.artifactPath)
      assert.ok(modes.length > 0)
      assert.deepEqual([...new Set(modes)], ['000644'])
    })

    await t.test('identical rerun through .cmd is idempotent', () => {
      const before = fs.readFileSync(result.manifestPath)
      const rerun = runCmd(wrapper, ['--expect-commit', head], nativeEnv)
      assert.equal(rerun.status, 0, rerun.stderr)
      assert.equal((JSON.parse(rerun.stdout) as InstallResult).artifactSha256, result.artifactSha256)
      assert.ok(fs.readFileSync(result.manifestPath).equals(before))
    })

    await t.test('paths containing spaces: checkout, entrypoint and state root -> identical artifact sha256', () => {
      const spacedRoot = path.join(scratch, 'toadaid p3 spaced')
      const checkout = path.join(spacedRoot, 'check out')
      fs.mkdirSync(spacedRoot)
      git(spacedRoot, ['clone', '-q', '--no-hardlinks', root, checkout])
      fs.symlinkSync(path.join(root, 'node_modules'), path.join(checkout, 'node_modules'), 'junction')
      junctions.push(path.join(checkout, 'node_modules'))
      fs.appendFileSync(path.join(checkout, '.git', 'info', 'exclude'), '\nnode_modules\n')
      assert.equal(git(checkout, ['status', '--porcelain=v1', '--untracked-files=all']), '')
      const spacedState = path.join(spacedRoot, 'state with spaces')
      const spaced = runCmd(path.join(checkout, 'bin', 'toadaid-capabilities-install-agent.cmd'), ['--expect-commit', head, '--state-root', spacedState], nativeEnv, checkout)
      assert.equal(spaced.status, 0, spaced.stderr)
      const spacedResult = JSON.parse(spaced.stdout) as InstallResult
      assert.equal(spacedResult.status, 'READY_FOR_HOST_WIRING')
      assert.equal(path.dirname(spacedResult.artifactPath), path.join(spacedState, 'artifacts'))
      assert.equal(spacedResult.artifactSha256, result.artifactSha256, 'artifact identity is path-independent on Windows')

      fs.writeFileSync(path.join(checkout, 'UNCOMMITTED.txt'), 'dirty\n')
      const dirtyState = path.join(spacedRoot, 'dirty state')
      const refused = runCmd(path.join(checkout, 'bin', 'toadaid-capabilities-install-agent.cmd'), ['--state-root', dirtyState], nativeEnv, checkout)
      assert.equal(refused.status, 2, refused.stderr)
      assert.match(refused.stderr, /refusing artifact installation from a dirty checkout/)
      assert.equal(fs.existsSync(dirtyState), false)
    })

    await t.test('the canonical checkout is still clean after the native installer ran', () => {
      assert.equal(git(root, ['status', '--porcelain=v1', '--untracked-files=all']), '')
    })

    t.diagnostic(`WINDOWS_ARTIFACT_SHA256 = ${result.artifactSha256}`)
    t.diagnostic('INSTALLER_E2E_EXECUTED = YES')
    console.log('INSTALLER_E2E_EXECUTED = YES')
  } finally {
    // remove the node_modules junction itself first so cleanup can never reach the shared tree
    for (const junction of junctions) {
      try {
        fs.rmdirSync(junction)
      } catch {
        // already gone
      }
    }
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})
