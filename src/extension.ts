import * as vscode from 'vscode'
import { ChildProcessWithoutNullStreams, spawn } from 'node:child_process'
import * as path from 'node:path'
import * as fs from 'node:fs'

type QuantumDetail = {
  level: string
  reason: string
  x: number | null
  y: number | null
  z: number
  margin: number | null
}

type Finding = {
  id: string
  category: string
  name: string
  file: string
  line: number
  evidence: string
  confidence?: number
  confidence_level?: string
  metadata?: Record<string, unknown>
  version?: string | null
  risk: string
  reason: string
  quantum_risk: string
  quantum: QuantumDetail
  mosca?: QuantumDetail
  recommendation: string
  recommendation_details?: Record<string, unknown>
}

type FileResult = { uri: vscode.Uri; findings: Finding[] }
type SidebarNode = {
  label: string
  description?: string
  tooltip?: string
  icon?: vscode.ThemeIcon
  command?: vscode.Command
  contextValue?: string
  collapsibleState?: vscode.TreeItemCollapsibleState
  children?: SidebarNode[]
}
type EngineResponse = {
  findings: Finding[]
  engines?: Record<string, { available?: boolean; version?: string; provider?: string; scan?: string }>
  input_type?: string
  files_scanned?: number
  files_skipped?: number
  analysis?: { engine_version?: string; schema?: string; python?: string }
}
type EngineProgress = {
  phase: string
  count: number
  total: number
  message: string
}

class ScanCancelledError extends Error {
  constructor() {
    super('Periperi scan cancelled.')
  }
}

const FALLBACK_SCHEMA = 'ECDAT CBOM Prototype 1.1'

const supportedExtensions = new Set([
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs',
  '.php', '.rb', '.cs', '.kt', '.swift', '.yaml', '.yml', '.json', '.xml', '.conf', '.config',
  '.ini', '.env', '.txt', '.md', '.toml', '.properties', '.gradle', '.lock', '.sh', '.ps1',
  '.pem', '.crt', '.cer', '.der', '.key', '.jks', '.keystore', '.mod'
])

const excludedGlob = '**/{.git,.gradle,.cache,.next,.idea,.vscode,node_modules,venv,.venv,__pycache__,target,dist,build,out,bin,obj,coverage,vendor}/**'
const diagnostics = vscode.languages.createDiagnosticCollection('ecdat')
const results = new Map<string, FileResult>()
const findingUris = new WeakMap<Finding, vscode.Uri>()
let statusItem: vscode.StatusBarItem
let outputChannel: vscode.OutputChannel
let sidebarProvider: SidebarTreeProvider
let reportPanel: vscode.WebviewPanel | undefined
let lastEngines: EngineResponse['engines'] = {}
let lastAnalysis: EngineResponse['analysis'] = {}
let lastInputType = 'source-file'
let lastScanCompleted = false
let scanState = 'Ready to scan'
let scanGeneration = 0
const activeFileScans = new Set<string>()

class SidebarTreeProvider implements vscode.TreeDataProvider<SidebarNode>, vscode.Disposable {
  private readonly changeEmitter = new vscode.EventEmitter<SidebarNode | undefined>()
  readonly onDidChangeTreeData = this.changeEmitter.event

  getTreeItem(node: SidebarNode): vscode.TreeItem {
    const item = new vscode.TreeItem(node.label, node.collapsibleState)
    item.description = node.description
    item.tooltip = node.tooltip
    item.iconPath = node.icon
    item.command = node.command
    item.contextValue = node.contextValue
    return item
  }

  getChildren(node?: SidebarNode): SidebarNode[] {
    return node?.children || buildSidebarNodes()
  }

  refresh(): void {
    this.changeEmitter.fire(undefined)
  }

  dispose(): void {
    this.changeEmitter.dispose()
  }
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Periperi')
  sidebarProvider = new SidebarTreeProvider()
  const sidebar = vscode.window.createTreeView('periperi.sidebar', {
    treeDataProvider: sidebarProvider,
    showCollapseAll: true,
  })
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90)
  statusItem.command = 'periperi.openSidebar'
  statusItem.text = '$(shield) Periperi ready'
  statusItem.tooltip = 'Open the Periperi sidebar'
  statusItem.show()

  context.subscriptions.push(
    diagnostics,
    outputChannel,
    sidebarProvider,
    sidebar,
    statusItem,
    vscode.commands.registerCommand('ecdat.scanCurrentFile', scanActiveEditor),
    vscode.commands.registerCommand('ecdat.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('ecdat.scanArtifact', scanArtifact),
    vscode.commands.registerCommand('ecdat.showReport', showReport),
    vscode.commands.registerCommand('ecdat.exportCbom', exportCbom),
    vscode.commands.registerCommand('ecdat.clearDiagnostics', clearAll),
    vscode.commands.registerCommand('periperi.openSidebar', () => vscode.commands.executeCommand('workbench.view.extension.periperi')),
    vscode.commands.registerCommand('periperi.openOutput', () => outputChannel.show()),
    vscode.commands.registerCommand('periperi.openFinding', openFinding),
    vscode.workspace.onDidChangeTextDocument(event => invalidateEditedResults(event.document.uri)),
    vscode.workspace.onDidChangeWorkspaceFolders(() => invalidateWorkspaceResults()),
    vscode.workspace.onDidSaveTextDocument(document => {
      if (vscode.workspace.getConfiguration('ecdat').get('scanOnSave', true)) {
        void scanDocument(document, false)
      }
    })
  )
}

async function scanActiveEditor(): Promise<void> {
  const editor = vscode.window.activeTextEditor
  if (!editor) {
    void vscode.window.showInformationMessage('Periperi: Open a supported source file first.')
    return
  }
  await scanDocument(editor.document, true)
}

async function scanDocument(document: vscode.TextDocument, announce: boolean): Promise<Finding[]> {
  if (document.uri.scheme !== 'file' || !isSupported(document.uri.fsPath)) {
    if (announce) void vscode.window.showInformationMessage('Periperi: This file type is not supported.')
    return []
  }
  if (Buffer.byteLength(document.getText(), 'utf8') > 2 * 1024 * 1024) {
    if (announce) void vscode.window.showWarningMessage('Periperi: Files larger than 2 MB are skipped.')
    return []
  }

  const generation = ++scanGeneration
  if (clearResultsForDocument(document.uri)) refreshReport()
  const uriKey = document.uri.toString()
  activeFileScans.add(uriKey)
  lastScanCompleted = false
  scanState = 'Scanning current file'
  setStatus('$(loading~spin) Periperi scanning')
  outputChannel.appendLine(`Scanning file: ${vscode.workspace.asRelativePath(document.uri, false)}`)
  try {
    const response = await runEngine(document.uri, document.getText())
    if (generation !== scanGeneration) {
      activeFileScans.delete(uriKey)
      outputChannel.appendLine('Discarded file scan results because the workspace or source changed.')
      return []
    }
    activeFileScans.delete(uriKey)
    const findings = response.findings
    lastEngines = response.engines || lastEngines
    lastAnalysis = response.analysis || lastAnalysis
    lastInputType = response.input_type || 'source-file'
    lastScanCompleted = true
    scanState = `Completed · ${findings.length} finding${findings.length === 1 ? '' : 's'}`
    results.set(document.uri.toString(), { uri: document.uri, findings })
    for (const finding of findings) findingUris.set(finding, document.uri)
    diagnostics.set(document.uri, findings.map(toDiagnostic))
    updateStatus()
    refreshReport()
    if (announce) {
      void vscode.window.showInformationMessage(`Periperi: Found ${findings.length} cryptographic item${findings.length === 1 ? '' : 's'}.`)
    }
    outputChannel.appendLine(`Scan completed: ${findings.length} finding${findings.length === 1 ? '' : 's'}.`)
    return findings
  } catch (error) {
    activeFileScans.delete(uriKey)
    if (generation !== scanGeneration) {
      outputChannel.appendLine(`Discarded failed file scan after the source changed: ${error instanceof Error ? error.message : String(error)}`)
      return []
    }
    lastScanCompleted = false
    scanState = 'Scan failed'
    outputChannel.appendLine(`Scan failed: ${error instanceof Error ? error.message : String(error)}`)
    setStatus('$(error) Periperi error')
    void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'Periperi scan failed.')
    return []
  }
}

async function scanWorkspace(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0]
  if (!folder) {
    void vscode.window.showInformationMessage('Periperi: Open a workspace folder first.')
    return
  }
  const generation = ++scanGeneration
  results.clear()
  diagnostics.clear()
  refreshReport()
  lastScanCompleted = false
  scanState = 'Scanning workspace'
  setStatus('$(loading~spin) Periperi scanning workspace')
  outputChannel.appendLine(`Scanning workspace: ${folder.name}`)
  try {
    const response = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'Periperi workspace scan · source, binaries, certificates and keys',
      cancellable: true,
    }, (progress, token) => {
      const reportProgress = createProgressReporter(progress)
      reportProgress({ phase: 'preparing', count: 0, total: 0, message: 'Preparing workspace scan' })
      const maxFiles = vscode.workspace.getConfiguration('ecdat').get<number>('maxWorkspaceFiles', 2000)
      return runEngineRequest(
        { ...engineOptions(), mode: 'workspace', path: folder.uri.fsPath, max_files: maxFiles },
        reportProgress,
        token
      )
    })
    if (generation !== scanGeneration) {
      outputChannel.appendLine('Discarded workspace scan results because the workspace or source changed.')
      return
    }
    results.set(folder.uri.toString(), { uri: folder.uri, findings: response.findings })
    lastEngines = response.engines || {}
    lastAnalysis = response.analysis || lastAnalysis
    lastInputType = response.input_type || 'workspace'
    lastScanCompleted = true
    scanState = `Completed · ${response.findings.length} finding${response.findings.length === 1 ? '' : 's'}`
    const byFile = new Map<string, Finding[]>()
    for (const finding of response.findings) {
      if (!finding.line || finding.file === 'container-image') continue
      const candidate = path.resolve(folder.uri.fsPath, finding.file)
      const relative = path.relative(path.resolve(folder.uri.fsPath), candidate)
      if (relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(candidate)) continue
      const items = byFile.get(candidate) || []
      items.push(finding)
      byFile.set(candidate, items)
      findingUris.set(finding, vscode.Uri.file(candidate))
    }
    for (const [filePath, findings] of byFile) diagnostics.set(vscode.Uri.file(filePath), findings.map(toDiagnostic))
    updateStatus()
    refreshReport()
    outputChannel.appendLine(`Workspace scan completed: ${response.files_scanned || 0} files scanned, ${response.findings.length} findings.`)
    void vscode.window.showInformationMessage(`Periperi: Scanned ${response.files_scanned || 0} files and found ${response.findings.length} items.`)
  } catch (error) {
    if (generation !== scanGeneration) {
      outputChannel.appendLine(`Discarded failed workspace scan after the workspace changed: ${error instanceof Error ? error.message : String(error)}`)
      return
    }
    if (error instanceof ScanCancelledError) {
      lastScanCompleted = false
      scanState = 'Scan cancelled'
      outputChannel.appendLine(error.message)
      setStatus('$(circle-slash) Periperi cancelled')
      return
    }
    lastScanCompleted = false
    scanState = 'Scan failed'
    outputChannel.appendLine(`Workspace scan failed: ${error instanceof Error ? error.message : String(error)}`)
    setStatus('$(error) Periperi error')
    void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'Periperi workspace scan failed.')
  }
}

async function scanArtifact(): Promise<void> {
  const selected = await vscode.window.showOpenDialog({
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    openLabel: 'Scan with Periperi',
    filters: {
      'Periperi inputs': ['zip', 'tar', 'gz', 'tgz', 'exe', 'dll', 'so', 'dylib', 'jar', 'war', 'apk', 'pem', 'crt', 'cer', 'der', 'key', 'p12', 'pfx'],
      'All files': ['*'],
    },
  })
  if (!selected?.[0]) return
  const generation = ++scanGeneration
  lastScanCompleted = false
  scanState = 'Scanning artifact'
  results.clear()
  diagnostics.clear()
  refreshReport()
  setStatus('$(loading~spin) Periperi scanning artifact')
  outputChannel.appendLine(`Scanning artifact: ${selected[0].fsPath}`)
  try {
    const response = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: `Periperi scanning ${path.basename(selected[0].fsPath)}`,
      cancellable: true,
    }, (progress, token) => {
      const reportProgress = createProgressReporter(progress)
      reportProgress({ phase: 'preparing', count: 0, total: 0, message: 'Preparing artifact scan' })
      return runEngineRequest(
        { ...engineOptions(), mode: 'artifact', path: selected[0].fsPath },
        reportProgress,
        token
      )
    })
    if (generation !== scanGeneration) {
      outputChannel.appendLine('Discarded artifact scan results because the workspace changed.')
      return
    }
    results.set(selected[0].toString(), { uri: selected[0], findings: response.findings })
    lastEngines = response.engines || {}
    lastAnalysis = response.analysis || lastAnalysis
    lastInputType = response.input_type || 'artifact'
    lastScanCompleted = true
    scanState = `Completed · ${response.findings.length} finding${response.findings.length === 1 ? '' : 's'}`
    updateStatus()
    refreshReport()
    outputChannel.appendLine(`Artifact scan completed: ${response.findings.length} findings.`)
    void vscode.window.showInformationMessage(`Periperi: Found ${response.findings.length} cryptographic items.`)
  } catch (error) {
    if (generation !== scanGeneration) {
      outputChannel.appendLine(`Discarded failed artifact scan after the workspace changed: ${error instanceof Error ? error.message : String(error)}`)
      return
    }
    if (error instanceof ScanCancelledError) {
      lastScanCompleted = false
      scanState = 'Scan cancelled'
      outputChannel.appendLine(error.message)
      setStatus('$(circle-slash) Periperi cancelled')
      return
    }
    lastScanCompleted = false
    scanState = 'Scan failed'
    outputChannel.appendLine(`Artifact scan failed: ${error instanceof Error ? error.message : String(error)}`)
    setStatus('$(error) Periperi error')
    void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'Periperi artifact scan failed.')
  }
}

function engineOptions(): Record<string, string | number> {
  const config = vscode.workspace.getConfiguration('ecdat')
  return {
    sensitivity: config.get('dataSensitivity', 'pii'),
    migration_complexity: config.get('migrationComplexity', 'standard_application'),
    threat_timeline: config.get('threatTimeline', 15),
  }
}

function createProgressReporter(
  progress: vscode.Progress<{ message?: string; increment?: number }>
): (event: EngineProgress) => void {
  let lastPercent = 0
  return event => {
    const total = event.total > 0 ? event.total : 0
    const percent = total ? Math.min(100, Math.round(event.count / total * 100)) : 0
    const increment = total ? Math.max(0, percent - lastPercent) : undefined
    lastPercent = Math.max(lastPercent, percent)
    const counter = total ? ` (${event.count}/${event.total})` : ''
    progress.report({ message: `${event.message}${counter}`, increment })
    setStatus(`$(loading~spin) Periperi ${event.message.toLowerCase()}`)
  }
}

function parseProgressLine(line: string): EngineProgress | undefined {
  const prefix = 'ECDAT_PROGRESS '
  if (!line.startsWith(prefix)) return undefined
  try {
    const value = JSON.parse(line.slice(prefix.length)) as Partial<EngineProgress>
    if (
      typeof value.phase === 'string'
      && typeof value.message === 'string'
      && typeof value.count === 'number'
      && typeof value.total === 'number'
      && Number.isFinite(value.count)
      && Number.isFinite(value.total)
      && value.count >= 0
      && value.total >= 0
    ) return value as EngineProgress
  } catch {
    return undefined
  }
  return undefined
}

function runEngine(uri: vscode.Uri, text: string): Promise<EngineResponse> {
  return runEngineRequest({ ...engineOptions(), mode: 'text', path: vscode.workspace.asRelativePath(uri, false).replaceAll('\\', '/'), text })
}

function runEngineRequest(
  payloadObject: Record<string, unknown>,
  onProgress?: (event: EngineProgress) => void,
  cancellationToken?: vscode.CancellationToken
): Promise<EngineResponse> {
  const config = vscode.workspace.getConfiguration('ecdat')
  const extensionRoot = path.resolve(__dirname, '..')
  const configuredRoot = config.get<string>('engineRoot', '').trim()
  const bundledRoot = path.join(extensionRoot, 'engine')
  const hasBundledEngine = fs.existsSync(path.join(bundledRoot, 'backend', 'app', 'vscode_bridge.py'))
  const repositoryRoot = configuredRoot || (hasBundledEngine ? bundledRoot : path.resolve(extensionRoot, '..'))
  const python = config.get<string>('pythonPath', 'python')
  const payload = JSON.stringify(payloadObject)
  const searchPaths = [repositoryRoot]
  const runtimeRoot = path.join(bundledRoot, 'runtime')
  const runtimeReport = process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined
  const isMusl = process.platform === 'linux' && !runtimeReport?.header?.glibcVersionRuntime
  const runtimeNames = [
    isMusl ? `linux-${process.arch}-musl` : '',
    `${process.platform}-${process.arch}`,
    process.platform,
    process.platform === 'win32' && process.arch === 'x64' ? 'win32-x64' : '',
    process.platform === 'darwin' && process.arch === 'x64' ? 'darwin-x64' : '',
    process.platform === 'linux' && process.arch === 'x64' ? 'linux-x64' : '',
  ].filter(Boolean)
  const bundledRuntime = runtimeNames
    .map(name => path.join(runtimeRoot, name))
    .find(candidate => fs.existsSync(path.join(candidate, 'cryptography')))
    || (fs.existsSync(path.join(runtimeRoot, 'cryptography')) ? runtimeRoot : undefined)
  const dependencyCandidates = [
    ...(bundledRuntime ? [bundledRuntime] : []),
    path.join(repositoryRoot, '.runtime', 'python'),
    path.resolve(extensionRoot, '..', '.runtime', 'python'),
  ]
  const localDependencies = dependencyCandidates.find(candidate => fs.existsSync(path.join(candidate, 'cryptography')))
  if (localDependencies) searchPaths.push(localDependencies)
  const bootstrap = `import sys; sys.path[:0]=${JSON.stringify(searchPaths)}; from backend.app.vscode_bridge import main; main()`

  return new Promise((resolve, reject) => {
    if (cancellationToken?.isCancellationRequested) {
      reject(new ScanCancelledError())
      return
    }
    const child: ChildProcessWithoutNullStreams = spawn(
      python,
      ['-c', bootstrap],
      { cwd: repositoryRoot, windowsHide: true }
    )
    let output = ''
    let errors = ''
    let stderrBuffer = ''
    let cancelled = false
    const cancellation = cancellationToken?.onCancellationRequested(() => {
      cancelled = true
      child.kill()
    })
    const consumeErrors = (chunk: string) => {
      stderrBuffer += chunk
      const lines = stderrBuffer.split(/\r?\n/)
      stderrBuffer = lines.pop() || ''
      for (const line of lines) {
        const event = parseProgressLine(line)
        if (event) onProgress?.(event)
        else if (line.trim()) errors = `${errors}${line}\n`.slice(-8000)
      }
    }
    child.stdout.setEncoding('utf8').on('data', chunk => { output += chunk })
    child.stderr.setEncoding('utf8').on('data', consumeErrors)
    child.on('error', error => {
      cancellation?.dispose()
      outputChannel.appendLine(`Could not start Python: ${error.message}`)
      reject(new Error('Periperi could not start Python. Check the ecdat.pythonPath setting.'))
    })
    child.on('close', code => {
      cancellation?.dispose()
      if (cancelled) {
        reject(new ScanCancelledError())
        return
      }
      if (stderrBuffer.trim()) {
        const event = parseProgressLine(stderrBuffer)
        if (event) onProgress?.(event)
        else errors = `${errors}${stderrBuffer}\n`.slice(-8000)
      }
      try {
        const response = JSON.parse(output) as EngineResponse & { error?: string }
        if (code !== 0 || response.error) reject(new Error(response.error || errors || 'Periperi engine returned an error.'))
        else resolve({ ...response, findings: response.findings || [] })
      } catch {
        const dependencyHint = errors.includes("No module named 'cryptography'") || errors.includes('_cffi_backend')
          ? 'Periperi could not load its bundled Python runtime. Reinstall the latest VSIX or set ecdat.pythonPath to a compatible CPython 3.10-3.14 executable.'
          : errors
        reject(new Error(dependencyHint || 'Periperi returned an unreadable result. Check the engine path.'))
      }
    })
    child.stdin.end(payload)
  })
}

function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const line = Math.max(0, finding.line - 1)
  const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER)
  const diagnostic = new vscode.Diagnostic(
    range,
    `${finding.name}: ${finding.reason} Recommendation: ${finding.recommendation}`,
    severityFor(finding.risk)
  )
  diagnostic.source = 'Periperi'
  diagnostic.code = finding.quantum_risk === 'not_applicable'
    ? finding.risk.toUpperCase()
    : `${finding.risk.toUpperCase()} / Quantum ${finding.quantum_risk.toUpperCase()}`
  return diagnostic
}

function severityFor(risk: string): vscode.DiagnosticSeverity {
  if (risk === 'critical' || risk === 'high') return vscode.DiagnosticSeverity.Error
  if (risk === 'medium') return vscode.DiagnosticSeverity.Warning
  if (risk === 'low') return vscode.DiagnosticSeverity.Information
  return vscode.DiagnosticSeverity.Hint
}

function isSupported(filePath: string): boolean {
  const fileName = path.basename(filePath).toLowerCase()
  return supportedExtensions.has(path.extname(fileName)) || fileName === 'dockerfile' || fileName === 'requirements.txt'
}

function isProbablyBinary(bytes: Uint8Array): boolean {
  const sampleLength = Math.min(bytes.byteLength, 8192)
  if (!sampleLength) return false
  let controlBytes = 0
  for (let index = 0; index < sampleLength; index += 1) {
    const value = bytes[index]
    if (value === 0) return true
    if (value < 9 || (value > 13 && value < 32)) controlBytes += 1
  }
  return controlBytes / sampleLength > 0.1
}

function allFindings(): Finding[] {
  return [...results.values()].flatMap(item => item.findings)
}

function buildSidebarNodes(): SidebarNode[] {
  const findings = allFindings()
  const workspaceName = vscode.workspace.name || 'No workspace open'
  const overview: SidebarNode = {
    label: 'Overview',
    icon: new vscode.ThemeIcon('home'),
    collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
    children: [
      {
        label: workspaceName,
        description: 'Workspace',
        icon: new vscode.ThemeIcon('folder'),
      },
      {
        label: scanState,
        icon: new vscode.ThemeIcon(
          scanState.startsWith('Scanning') ? 'loading~spin'
            : scanState === 'Scan failed' ? 'error'
              : scanState === 'Scan cancelled' ? 'circle-slash'
                : lastScanCompleted ? 'check' : 'circle-outline'
        ),
      },
      sidebarAction('Scan Workspace', 'ecdat.scanWorkspace', 'run'),
      sidebarAction('Scan Current File', 'ecdat.scanCurrentFile', 'file-code'),
      sidebarAction('Scan Artifact', 'ecdat.scanArtifact', 'package'),
      sidebarAction('Open Report', 'ecdat.showReport', 'open-preview'),
      sidebarAction('Export CBOM', 'ecdat.exportCbom', 'export'),
      sidebarAction('Open Output', 'periperi.openOutput', 'output'),
    ],
  }
  const byFile = new Map<string, Finding[]>()
  for (const finding of findings) {
    const items = byFile.get(finding.file) || []
    items.push(finding)
    byFile.set(finding.file, items)
  }
  const findingChildren: SidebarNode[] = byFile.size
    ? [...byFile.entries()].sort(([first], [second]) => first.localeCompare(second)).map(([file, fileFindings]) => ({
      label: file || 'Unknown location',
      description: String(fileFindings.length),
      icon: new vscode.ThemeIcon('file'),
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      children: fileFindings.map(finding => ({
        label: finding.name,
        description: `${finding.risk.toUpperCase()}${finding.line > 0 ? ` · line ${finding.line}` : ''}`,
        tooltip: `${finding.name}\n${finding.reason}\nEvidence: ${finding.evidence}\nRecommendation: ${finding.recommendation}`,
        icon: new vscode.ThemeIcon(findingIcon(finding.risk)),
        contextValue: 'periperi.finding',
        command: {
          command: 'periperi.openFinding',
          title: 'Open Finding',
          arguments: [finding],
        },
      })),
    }))
    : [{
      label: lastScanCompleted ? 'No findings in the latest scan' : 'Run a scan to see findings',
      description: lastScanCompleted ? undefined : 'No scan results yet',
      icon: new vscode.ThemeIcon(lastScanCompleted ? 'check' : 'info'),
    }]
  return [
    overview,
    {
      label: `Findings${findings.length ? ` (${findings.length})` : ''}`,
      icon: new vscode.ThemeIcon('list-tree'),
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      children: findingChildren,
    },
  ]
}

function sidebarAction(label: string, commandId: string, icon: string): SidebarNode {
  return {
    label,
    icon: new vscode.ThemeIcon(icon),
    command: { command: commandId, title: label },
  }
}

function findingIcon(risk: string): string {
  if (risk === 'critical' || risk === 'high') return 'error'
  if (risk === 'medium') return 'warning'
  if (risk === 'low') return 'info'
  return 'circle-outline'
}

async function openFinding(finding: Finding): Promise<void> {
  const uri = findingUris.get(finding)
  if (!uri || finding.line < 1) {
    showReport()
    return
  }
  try {
    const document = await vscode.workspace.openTextDocument(uri)
    const line = Math.min(finding.line - 1, document.lineCount - 1)
    const position = new vscode.Position(line, 0)
    const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.Active)
    editor.selection = new vscode.Selection(position, position)
    editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenterIfOutsideViewport)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    outputChannel.appendLine(`Could not open finding source ${uri.fsPath}: ${message}`)
    void vscode.window.showErrorMessage(`Periperi could not open the finding source: ${message}`)
  }
}

function inventoryByCategory(findings: Finding[], category: string): string[] {
  return [...new Set(findings.filter(item => item.category === category && item.name).map(item => item.name))].sort()
}

function dependencyInventory(findings: Finding[]): Record<string, unknown>[] {
  return findings
    .filter(item => (item.version !== null && item.version !== undefined && item.version !== '') || item.metadata?.source === 'manifest')
    .map(item => {
      const source = String(item.metadata?.source || '')
      const version = String(item.version || 'unspecified')
      return {
        name: item.name,
        version,
        declared_version: version,
        resolved_version: source === 'syft' || source === 'trivy' ? version : null,
        version_type: source === 'syft' || source === 'trivy' ? 'resolved' : 'declared',
        ecosystem: String(item.metadata?.ecosystem || 'unknown'),
        scope: String(item.metadata?.scope || 'runtime'),
        manifest: String(item.metadata?.manifest || item.file || 'unknown'),
        crypto_relevant: item.category === 'Library',
      }
    })
}

function recommendationInventory(findings: Finding[]): Record<string, unknown>[] {
  return findings.map(item => ({
    action: item.recommendation,
    ...(item.recommendation_details || {}),
    finding_id: item.id,
    finding: item.name,
    risk: item.risk,
    quantum_risk: item.quantum_risk,
  }))
}

function highestLevel(distribution: Record<string, number>, quantum = false): string | null {
  const levels = quantum ? ['critical', 'high', 'medium', 'low'] : ['critical', 'high', 'medium', 'low', 'info']
  return levels.find(level => (distribution[level] || 0) > 0) || null
}

function buildCbomReport(findings: Finding[]): Record<string, unknown> {
  const riskDistribution = findings.reduce<Record<string, number>>((counts, item) => {
    counts[item.risk] = (counts[item.risk] || 0) + 1
    return counts
  }, {})
  const quantumDistribution = findings.reduce<Record<string, number>>((counts, item) => {
    counts[item.quantum_risk] = (counts[item.quantum_risk] || 0) + 1
    return counts
  }, {})
  const categoryDistribution = findings.reduce<Record<string, number>>((counts, item) => {
    const category = item.category.toLowerCase()
    counts[category] = (counts[category] || 0) + 1
    return counts
  }, {})
  return {
    specification: lastAnalysis?.schema || FALLBACK_SCHEMA,
    generated_at: new Date().toISOString(),
    workspace: vscode.workspace.name || 'workspace',
    input_type: lastInputType,
    engine: {
      version: lastAnalysis?.engine_version || null,
      python: lastAnalysis?.python || null,
      schema: lastAnalysis?.schema || FALLBACK_SCHEMA,
    },
    engines: lastEngines,
    files_with_findings: results.size,
    findings_count: findings.length,
    risk: highestLevel(riskDistribution),
    risk_distribution: riskDistribution,
    quantum_risk: highestLevel(quantumDistribution, true),
    quantum_risk_distribution: quantumDistribution,
    category_distribution: categoryDistribution,
    inventory: {
      algorithms: inventoryByCategory(findings, 'Algorithm'),
      libraries: inventoryByCategory(findings, 'Library'),
      certificates: inventoryByCategory(findings, 'Certificate'),
      keys: inventoryByCategory(findings, 'Key'),
      hsms: inventoryByCategory(findings, 'HSM'),
      key_management_services: inventoryByCategory(findings, 'Key Management'),
      protocols: inventoryByCategory(findings, 'Protocol'),
      versions: dependencyInventory(findings),
      containers: [],
    },
    recommendations: recommendationInventory(findings),
    findings,
    disclaimer: 'Rule-based prototype inventory; validate findings before security decisions.',
  }
}

function updateStatus(): void {
  const findings = allFindings()
  const urgent = findings.filter(item => item.risk === 'critical' || item.risk === 'high').length
  statusItem.text = urgent
    ? `$(warning) Periperi ${findings.length} findings · ${urgent} urgent`
    : `$(shield) Periperi ${findings.length} findings`
  sidebarProvider.refresh()
}

function setStatus(text: string): void {
  statusItem.text = text
  sidebarProvider.refresh()
}

function clearAll(): void {
  scanGeneration += 1
  results.clear()
  diagnostics.clear()
  lastEngines = {}
  lastAnalysis = {}
  lastInputType = 'source-file'
  lastScanCompleted = false
  scanState = 'Ready to scan'
  updateStatus()
  refreshReport()
}

function clearResultsForDocument(uri: vscode.Uri): boolean {
  const key = uri.toString()
  let changed = false
  for (const [resultKey, result] of results) {
    const remaining = result.findings.filter(finding => findingUris.get(finding)?.toString() !== key)
    if (remaining.length !== result.findings.length || resultKey === key) {
      changed = true
      if (resultKey === key) results.delete(resultKey)
      else results.set(resultKey, { ...result, findings: remaining })
    }
  }
  if (diagnostics.has(uri)) {
    diagnostics.delete(uri)
    changed = true
  }
  return changed
}

function invalidateEditedResults(uri: vscode.Uri): void {
  if (uri.scheme !== 'file') return
  const hasWorkspaceResults = lastInputType === 'workspace'
    && results.size > 0
    && Boolean(vscode.workspace.getWorkspaceFolder(uri))
  const workspaceScanInProgress = scanState === 'Scanning workspace'
    && Boolean(vscode.workspace.getWorkspaceFolder(uri))
  const activeFileScan = activeFileScans.delete(uri.toString())
  if (hasWorkspaceResults || workspaceScanInProgress) {
    results.clear()
    diagnostics.clear()
  } else if (!activeFileScan && !clearResultsForDocument(uri)) {
    return
  }
  scanGeneration += 1
  lastScanCompleted = false
  scanState = 'Results stale · scan again'
  outputChannel.appendLine(`Invalidated scan results after source changes: ${uri.fsPath}`)
  updateStatus()
  refreshReport()
}

function invalidateWorkspaceResults(): void {
  const sourceScanInProgress = scanState === 'Scanning workspace' || activeFileScans.size > 0
  if (!sourceScanInProgress && (results.size === 0 || lastInputType === 'artifact')) return
  scanGeneration += 1
  results.clear()
  diagnostics.clear()
  lastScanCompleted = false
  scanState = 'Workspace changed · scan again'
  outputChannel.appendLine('Invalidated scan results after workspace folders changed.')
  updateStatus()
  refreshReport()
}

function showReport(): void {
  if (!reportPanel) {
    reportPanel = vscode.window.createWebviewPanel('ecdatReport', 'Periperi Report', vscode.ViewColumn.Beside, { enableScripts: false })
    reportPanel.onDidDispose(() => { reportPanel = undefined })
  }
  refreshReport()
  reportPanel.reveal(vscode.ViewColumn.Beside)
}

function refreshReport(): void {
  if (!reportPanel) return
  const findings = allFindings().sort((a, b) => riskRank(a.risk) - riskRank(b.risk))
  const count = (risk: string) => findings.filter(item => item.risk === risk).length
  const engineLabels = Object.entries(lastEngines || {}).map(([name, detail]) => {
    const state = detail.available === false ? 'unavailable' : detail.scan || detail.version || detail.provider || 'ready'
    return `${name}: ${state}`
  }).join(' · ')
  const rows = findings.map(item => `
    <tr>
      <td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.category)}</small></td>
      <td>${escapeHtml(item.file)}${item.line > 0 ? `:${item.line}` : ''}</td>
      <td><span class="badge ${escapeHtml(item.risk)}">${escapeHtml(item.risk)}</span></td>
      <td>${escapeHtml(item.quantum_risk.replace('_', ' '))}</td>
      <td>${escapeHtml(item.recommendation)}</td>
    </tr>`).join('')
  const cbom = buildCbomReport(findings)
  const cbomPreview = escapeHtml(JSON.stringify({
    specification: cbom.specification,
    generated_at: cbom.generated_at,
    workspace: cbom.workspace,
    input_type: cbom.input_type,
    files_with_findings: cbom.files_with_findings,
    findings_count: cbom.findings_count,
    risk: cbom.risk,
    risk_distribution: cbom.risk_distribution,
    quantum_risk: cbom.quantum_risk,
    quantum_risk_distribution: cbom.quantum_risk_distribution,
    category_distribution: cbom.category_distribution,
    inventory: cbom.inventory,
    recommendations: Array.isArray(cbom.recommendations) ? cbom.recommendations.slice(0, 20) : [],
    findings: findings.slice(0, 20),
  }, null, 2) || '')

  reportPanel.webview.html = `<!doctype html><html><head><meta charset="UTF-8"><style>
    :root{color-scheme:light dark}body{font-family:var(--vscode-font-family);padding:24px;line-height:1.5;color:var(--vscode-foreground);background:var(--vscode-editor-background)}
    h1{font-size:26px;margin:0 0 4px}.sub{opacity:.7;margin:0 0 24px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:22px}
    .metric{border:1px solid var(--vscode-panel-border);padding:14px}.metric b{display:block;font-size:25px}.metric span{font-size:11px;opacity:.7;text-transform:uppercase}
    table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid var(--vscode-panel-border);padding:10px;text-align:left;vertical-align:top}th{font-size:10px;text-transform:uppercase;opacity:.75}
    td small{display:block;opacity:.65;margin-top:3px}.badge{text-transform:uppercase;font-size:10px;font-weight:700}.critical,.high{color:var(--vscode-errorForeground)}.medium{color:var(--vscode-editorWarning-foreground)}.low{color:var(--vscode-testing-iconPassed)}.info{color:var(--vscode-textLink-foreground)}
    .cbom-report{border:1px solid var(--vscode-panel-border);margin:0 0 22px;padding:16px}.cbom-report h2{font-size:17px;margin:0 0 4px}.cbom-report p{opacity:.7;margin:0 0 12px;font-size:12px}.cbom-report pre{background:var(--vscode-textCodeBlock-background);padding:12px;max-height:360px;overflow:auto;font-size:11px;white-space:pre-wrap;word-break:break-word}
    .empty{padding:45px 0;text-align:center;opacity:.7}@media(max-width:800px){.metrics{grid-template-columns:repeat(2,1fr)}table{display:block;overflow:auto}}
  </style></head><body>
    <h1>Periperi Report</h1><p class="sub">${escapeHtml(lastInputType.replaceAll('-', ' '))}${lastAnalysis?.engine_version ? ` · engine ${escapeHtml(lastAnalysis.engine_version)}` : ''}${engineLabels ? ` · ${escapeHtml(engineLabels)}` : ''}</p>
    <div class="metrics"><div class="metric"><b>${findings.length}</b><span>Total findings</span></div><div class="metric"><b>${count('critical')}</b><span>Critical</span></div><div class="metric"><b>${count('high')}</b><span>High</span></div><div class="metric"><b>${results.size}</b><span>Files with findings</span></div></div>
    <section class="cbom-report"><h2>CBOM report</h2><p>Preview of the generated CBOM. Run <strong>Periperi: Export CBOM</strong> to save the complete report as JSON.</p><pre>${cbomPreview}</pre></section>
    ${findings.length ? `<table><thead><tr><th>Finding</th><th>Location</th><th>Risk</th><th>Quantum</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="empty">Run a Periperi file or workspace scan to populate this report.</div>'}
  </body></html>`
}

async function exportCbom(): Promise<void> {
  if (!lastScanCompleted) {
    void vscode.window.showInformationMessage('Periperi: Run a scan before exporting a CBOM.')
    return
  }
  const findings = allFindings()
  const target = await vscode.window.showSaveDialog({
    defaultUri: vscode.workspace.workspaceFolders?.[0]
      ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'periperi-cbom.json')
      : undefined,
    filters: { JSON: ['json'] },
    saveLabel: 'Export Periperi CBOM',
  })
  if (!target) return
  const report = buildCbomReport(findings)
  await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(report, null, 2), 'utf8'))
  outputChannel.appendLine(`CBOM exported to ${target.fsPath}`)
  void vscode.window.showInformationMessage('Periperi: CBOM exported successfully.')
}

function riskRank(risk: string): number {
  return ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 } as Record<string, number>)[risk] ?? 5
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character] || character))
}
