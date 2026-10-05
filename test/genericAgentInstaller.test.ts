import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

const root = process.cwd()
const installer = path.join(root, 'bin', 'toadaid-capabilities-install-agent')
const profilePath = path.join(root, 'profiles', 'safe-observe.json')

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
    [
      'browser:evidence',
      'workspace:snapshot',
      'workspace:diff',
      'host:process-read',
    ],
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

test('clean CI checkout can produce a local artifact without host authority', () => {
  const gitStatus = spawnSync(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: root, encoding: 'utf8' },
  )
  assert.equal(gitStatus.status, 0, gitStatus.stderr)

  // Local source-cut runs are intentionally dirty before commit, so this
  // end-to-end install assertion activates only once CI checks the committed
  // tree (or any other genuinely clean checkout).
  if (gitStatus.stdout.trim() !== '') return

  const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'toadaid-cap-install-'))
  try {
    const installed = spawnSync(
      'bash',
      [
        installer,
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
    assert.equal(installed.status, 0, installed.stderr)

    const result = JSON.parse(installed.stdout) as {
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

    assert.equal(result.status, 'READY_FOR_HOST_WIRING')
    assert.equal(result.activation, 'OFF')
    assert.deepEqual(result.capabilityGrants, [])
    assert.equal(result.installationGrantsAuthority, false)
    assert.equal(result.hostMutationPerformed, false)
    assert.equal(result.npmPublicationPerformed, false)
    assert.match(result.artifactSha256, /^[0-9a-f]{64}$/)
    assert.equal(fs.existsSync(result.artifactPath), true)
    assert.equal(fs.existsSync(result.manifestPath), true)

    const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8')) as {
      activation: string
      capabilityGrants: unknown[]
      providerBindings: Record<string, unknown>
      installationGrantsAuthority: boolean
      package: { private: boolean; artifactSha256: string }
    }

    assert.equal(manifest.activation, 'OFF')
    assert.deepEqual(manifest.capabilityGrants, [])
    assert.deepEqual(manifest.providerBindings, {})
    assert.equal(manifest.installationGrantsAuthority, false)
    assert.equal(manifest.package.private, true)
    assert.equal(manifest.package.artifactSha256, result.artifactSha256)
  } finally {
    fs.rmSync(stateRoot, { recursive: true, force: true })
  }
})
