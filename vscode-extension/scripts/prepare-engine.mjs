import { spawnSync } from 'node:child_process'
import { access, copyFile, cp, mkdir, mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(extensionRoot, '..')
const pythonVersions = ['3.10', '3.11', '3.12', '3.13', '3.14']
const runtimeTargets = [
  { id: 'win32-x64', platform: 'x86_64-pc-windows-msvc', cryptography: '50.0.1' },
  { id: 'linux-x64', platform: 'x86_64-manylinux_2_17', cryptography: '50.0.1' },
  { id: 'linux-arm64', platform: 'aarch64-unknown-linux-gnu', cryptography: '50.0.1' },
  { id: 'linux-x64-musl', platform: 'x86_64-unknown-linux-musl', cryptography: '50.0.1' },
  { id: 'linux-arm64-musl', platform: 'aarch64-unknown-linux-musl', cryptography: '50.0.1' },
  { id: 'darwin-arm64', platform: 'aarch64-apple-darwin', cryptography: '50.0.1' },
  { id: 'darwin-x64', platform: 'x86_64-apple-darwin', cryptography: '48.0.0' },
]
const files = [
  'backend/__init__.py',
  'backend/app/__init__.py',
  'backend/app/detector.py',
  'backend/app/dependencies.py',
  'backend/app/risk.py',
  'backend/app/recommendations.py',
  'backend/app/vscode_bridge.py',
  'backend/app/scanner.py',
  'backend/app/openssl_inspector.py',
  'backend/app/container_tools.py',
]

function runUv(target, version, destination) {
  const command = process.env.ECDAT_UV_PATH || 'uv'
  const packages = [
    `cryptography==${target.cryptography}`,
    'cffi==2.1.1',
    'pycparser==3.0',
    'typing-extensions==4.16.0',
  ]
  const result = spawnSync(command, [
    'pip', 'install', '--no-progress', '--target', destination,
    '--python-platform', target.platform,
    '--python-version', version,
    '--only-binary=:all:',
    ...packages,
  ], { env: process.env, stdio: 'inherit' })
  if (result.error || result.status !== 0) {
    throw new Error(`Could not prepare ${target.id} Python ${version} runtime. Install uv or set ECDAT_UV_PATH.`)
  }
}

async function copyPackage(sourceRoot, destinationRoot, packageName) {
  const source = join(sourceRoot, packageName)
  try {
    await access(source)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  const filter = sourcePath => !sourcePath.split(sep).includes('__pycache__')
  await cp(source, join(destinationRoot, packageName), { recursive: true, filter })
}

async function copyRuntimeTarget(target, temporaryRoot) {
  const targetRoot = join(temporaryRoot, target.id)
  const baseRoot = join(targetRoot, 'py312')
  const destination = join(extensionRoot, 'engine', 'runtime', target.id)
  await mkdir(destination, { recursive: true })
  for (const packageName of ['cryptography', 'cffi', 'pycparser', 'typing_extensions.py']) {
    await copyPackage(baseRoot, destination, packageName)
  }
  const baseEntries = await readdir(baseRoot, { withFileTypes: true })
  for (const entry of baseEntries) {
    if (entry.isDirectory() && /^(?:cryptography|cffi|pycparser|typing_extensions)-.*\.dist-info$/.test(entry.name)) {
      await copyPackage(baseRoot, destination, entry.name)
    }
  }
  for (const version of pythonVersions) {
    const sourceRoot = join(targetRoot, `py${version.replaceAll('.', '')}`)
    const entries = await readdir(sourceRoot, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.isFile() && /^_cffi_backend.*\.(?:pyd|so|dylib)$/.test(entry.name)) {
        const destinationName = target.id.endsWith('-musl')
          ? entry.name.replace(/linux-gnu\.so$/, 'linux-musl.so')
          : entry.name
        await copyFile(join(sourceRoot, entry.name), join(destination, destinationName))
      }
    }
  }
}

await rm(join(extensionRoot, 'engine'), { recursive: true, force: true })
await mkdir(join(extensionRoot, 'engine', 'backend', 'app'), { recursive: true })
for (const relative of files) {
  const source = join(repositoryRoot, relative)
  const destination = join(extensionRoot, 'engine', relative)
  await mkdir(dirname(destination), { recursive: true })
  await copyFile(source, destination)
}
const temporaryRoot = await mkdtemp(join(tmpdir(), 'ecdat-vscode-runtime-'))
try {
  for (const target of runtimeTargets) {
    const targetRoot = join(temporaryRoot, target.id)
    for (const version of pythonVersions) {
      runUv(target, version, join(targetRoot, `py${version.replaceAll('.', '')}`))
    }
    await copyRuntimeTarget(target, temporaryRoot)
    console.log(`Bundled Python runtime: ${target.id}`)
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true })
}
console.log('Bundled the local ECDAT Python engine for Windows, Linux and macOS.')
