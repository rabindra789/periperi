"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const node_child_process_1 = require("node:child_process");
const path = __importStar(require("node:path"));
const fs = __importStar(require("node:fs"));
const supportedExtensions = new Set([
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs',
    '.php', '.rb', '.cs', '.kt', '.swift', '.yaml', '.yml', '.json', '.xml', '.conf', '.config',
    '.ini', '.env', '.txt', '.md', '.toml', '.properties', '.gradle', '.lock', '.sh', '.ps1',
    '.pem', '.crt', '.cer', '.der', '.key', '.jks', '.keystore'
]);
const excludedGlob = '**/{.git,.gradle,.cache,.next,.idea,.vscode,node_modules,venv,.venv,__pycache__,target,dist,build,out,bin,obj,coverage,vendor}/**';
const diagnostics = vscode.languages.createDiagnosticCollection('ecdat');
const results = new Map();
let statusItem;
let reportPanel;
function activate(context) {
    statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
    statusItem.command = 'ecdat.showReport';
    statusItem.text = '$(shield) ECDAT ready';
    statusItem.tooltip = 'Open the ECDAT cryptographic report';
    statusItem.show();
    context.subscriptions.push(diagnostics, statusItem, vscode.commands.registerCommand('ecdat.scanCurrentFile', scanActiveEditor), vscode.commands.registerCommand('ecdat.scanWorkspace', scanWorkspace), vscode.commands.registerCommand('ecdat.showReport', showReport), vscode.commands.registerCommand('ecdat.exportCbom', exportCbom), vscode.commands.registerCommand('ecdat.clearDiagnostics', clearAll), vscode.workspace.onDidSaveTextDocument(document => {
        if (vscode.workspace.getConfiguration('ecdat').get('scanOnSave', true)) {
            void scanDocument(document, false);
        }
    }));
}
function deactivate() {
    diagnostics.dispose();
    statusItem.dispose();
}
async function scanActiveEditor() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showInformationMessage('ECDAT: Open a supported source file first.');
        return;
    }
    await scanDocument(editor.document, true);
}
async function scanDocument(document, announce) {
    if (document.uri.scheme !== 'file' || !isSupported(document.uri.fsPath)) {
        if (announce)
            void vscode.window.showInformationMessage('ECDAT: This file type is not supported.');
        return [];
    }
    if (Buffer.byteLength(document.getText(), 'utf8') > 2 * 1024 * 1024) {
        if (announce)
            void vscode.window.showWarningMessage('ECDAT: Files larger than 2 MB are skipped.');
        return [];
    }
    setStatus('$(loading~spin) ECDAT scanning');
    try {
        const findings = await runEngine(document.uri, document.getText());
        results.set(document.uri.toString(), { uri: document.uri, findings });
        diagnostics.set(document.uri, findings.map(toDiagnostic));
        updateStatus();
        refreshReport();
        if (announce) {
            void vscode.window.showInformationMessage(`ECDAT: Found ${findings.length} cryptographic item${findings.length === 1 ? '' : 's'}.`);
        }
        return findings;
    }
    catch (error) {
        setStatus('$(error) ECDAT error');
        void vscode.window.showErrorMessage(error instanceof Error ? error.message : 'ECDAT scan failed.');
        return [];
    }
}
async function scanWorkspace() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
        void vscode.window.showInformationMessage('ECDAT: Open a workspace folder first.');
        return;
    }
    const maximum = vscode.workspace.getConfiguration('ecdat').get('maxWorkspaceFiles', 2000);
    const searchRoot = new vscode.RelativePattern(folder, '**/*');
    const uris = (await vscode.workspace.findFiles(searchRoot, excludedGlob, maximum)).filter(uri => isSupported(uri.fsPath));
    results.clear();
    diagnostics.clear();
    let completed = 0;
    let skipped = 0;
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'ECDAT workspace scan',
        cancellable: true,
    }, async (progress, token) => {
        for (const uri of uris) {
            if (token.isCancellationRequested)
                break;
            try {
                const bytes = await vscode.workspace.fs.readFile(uri);
                if (bytes.byteLength > 2 * 1024 * 1024 || isProbablyBinary(bytes)) {
                    skipped += 1;
                }
                else {
                    const findings = await runEngine(uri, Buffer.from(bytes).toString('utf8'));
                    results.set(uri.toString(), { uri, findings });
                    diagnostics.set(uri, findings.map(toDiagnostic));
                }
            }
            catch {
                skipped += 1;
            }
            completed += 1;
            progress.report({ message: `${completed} of ${uris.length} files`, increment: uris.length ? 100 / uris.length : 100 });
        }
    });
    updateStatus();
    showReport();
    if (skipped) {
        void vscode.window.showInformationMessage(`ECDAT: Scan completed; ${skipped} unreadable or binary file${skipped === 1 ? '' : 's'} skipped.`);
    }
}
function runEngine(uri, text) {
    const config = vscode.workspace.getConfiguration('ecdat');
    const extensionRoot = path.resolve(__dirname, '..');
    const configuredRoot = config.get('engineRoot', '').trim();
    const bundledRoot = path.join(extensionRoot, 'engine');
    const hasBundledEngine = fs.existsSync(path.join(bundledRoot, 'backend', 'app', 'vscode_bridge.py'));
    const repositoryRoot = configuredRoot || (hasBundledEngine ? bundledRoot : path.resolve(extensionRoot, '..'));
    const python = config.get('pythonPath', 'python');
    const relativePath = vscode.workspace.asRelativePath(uri, false).replaceAll('\\', '/');
    const payload = JSON.stringify({
        path: relativePath,
        text,
        sensitivity: config.get('dataSensitivity', 'pii'),
        migration_complexity: config.get('migrationComplexity', 'standard_application'),
        threat_timeline: config.get('threatTimeline', 15),
    });
    return new Promise((resolve, reject) => {
        const child = (0, node_child_process_1.spawn)(python, ['-m', 'backend.app.vscode_bridge'], { cwd: repositoryRoot, windowsHide: true });
        let output = '';
        let errors = '';
        child.stdout.setEncoding('utf8').on('data', chunk => { output += chunk; });
        child.stderr.setEncoding('utf8').on('data', chunk => { errors += chunk; });
        child.on('error', () => reject(new Error('ECDAT could not start Python. Check the ecdat.pythonPath setting.')));
        child.on('close', code => {
            try {
                const response = JSON.parse(output);
                if (code !== 0 || response.error)
                    reject(new Error(response.error || errors || 'ECDAT engine returned an error.'));
                else
                    resolve(response.findings || []);
            }
            catch {
                reject(new Error(errors || 'ECDAT returned an unreadable result. Check the engine path.'));
            }
        });
        child.stdin.end(payload);
    });
}
function toDiagnostic(finding) {
    const line = Math.max(0, finding.line - 1);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const diagnostic = new vscode.Diagnostic(range, `${finding.name}: ${finding.reason} Recommendation: ${finding.recommendation}`, severityFor(finding.risk));
    diagnostic.source = 'ECDAT';
    diagnostic.code = finding.quantum_risk === 'not_applicable'
        ? finding.risk.toUpperCase()
        : `${finding.risk.toUpperCase()} / Quantum ${finding.quantum_risk.toUpperCase()}`;
    return diagnostic;
}
function severityFor(risk) {
    if (risk === 'critical' || risk === 'high')
        return vscode.DiagnosticSeverity.Error;
    if (risk === 'medium')
        return vscode.DiagnosticSeverity.Warning;
    if (risk === 'low')
        return vscode.DiagnosticSeverity.Information;
    return vscode.DiagnosticSeverity.Hint;
}
function isSupported(filePath) {
    const fileName = path.basename(filePath).toLowerCase();
    return supportedExtensions.has(path.extname(fileName)) || fileName === 'dockerfile' || fileName === 'requirements.txt';
}
function isProbablyBinary(bytes) {
    const sampleLength = Math.min(bytes.byteLength, 8192);
    if (!sampleLength)
        return false;
    let controlBytes = 0;
    for (let index = 0; index < sampleLength; index += 1) {
        const value = bytes[index];
        if (value === 0)
            return true;
        if (value < 9 || (value > 13 && value < 32))
            controlBytes += 1;
    }
    return controlBytes / sampleLength > 0.1;
}
function allFindings() {
    return [...results.values()].flatMap(item => item.findings);
}
function updateStatus() {
    const findings = allFindings();
    const urgent = findings.filter(item => item.risk === 'critical' || item.risk === 'high').length;
    statusItem.text = urgent
        ? `$(warning) ECDAT ${findings.length} findings · ${urgent} urgent`
        : `$(shield) ECDAT ${findings.length} findings`;
}
function setStatus(text) {
    statusItem.text = text;
}
function clearAll() {
    results.clear();
    diagnostics.clear();
    updateStatus();
    refreshReport();
}
function showReport() {
    if (!reportPanel) {
        reportPanel = vscode.window.createWebviewPanel('ecdatReport', 'ECDAT Cryptographic Report', vscode.ViewColumn.Beside, { enableScripts: false });
        reportPanel.onDidDispose(() => { reportPanel = undefined; });
    }
    refreshReport();
    reportPanel.reveal(vscode.ViewColumn.Beside);
}
function refreshReport() {
    if (!reportPanel)
        return;
    const findings = allFindings().sort((a, b) => riskRank(a.risk) - riskRank(b.risk));
    const count = (risk) => findings.filter(item => item.risk === risk).length;
    const rows = findings.map(item => `
    <tr>
      <td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.category)}</small></td>
      <td>${escapeHtml(item.file)}:${item.line}</td>
      <td><span class="badge ${escapeHtml(item.risk)}">${escapeHtml(item.risk)}</span></td>
      <td>${escapeHtml(item.quantum_risk.replace('_', ' '))}</td>
      <td>${escapeHtml(item.recommendation)}</td>
    </tr>`).join('');
    reportPanel.webview.html = `<!doctype html><html><head><meta charset="UTF-8"><style>
    :root{color-scheme:light dark}body{font-family:var(--vscode-font-family);padding:24px;line-height:1.5}
    h1{font-size:26px;margin:0 0 4px}.sub{opacity:.7;margin:0 0 24px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:22px}
    .metric{border:1px solid var(--vscode-panel-border);padding:14px}.metric b{display:block;font-size:25px}.metric span{font-size:11px;opacity:.7;text-transform:uppercase}
    table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid var(--vscode-panel-border);padding:10px;text-align:left;vertical-align:top}th{font-size:10px;text-transform:uppercase;opacity:.75}
    td small{display:block;opacity:.65;margin-top:3px}.badge{text-transform:uppercase;font-size:10px;font-weight:700}.critical,.high{color:#e05c63}.medium{color:#d7a13d}.low{color:#47a884}.info{color:#6fa7c7}
    .empty{padding:45px 0;text-align:center;opacity:.7}@media(max-width:800px){.metrics{grid-template-columns:repeat(2,1fr)}table{display:block;overflow:auto}}
  </style></head><body>
    <h1>ECDAT Cryptographic Report</h1><p class="sub">Local rule-based assessment. Validate findings before production security decisions.</p>
    <div class="metrics"><div class="metric"><b>${findings.length}</b><span>Total findings</span></div><div class="metric"><b>${count('critical')}</b><span>Critical</span></div><div class="metric"><b>${count('high')}</b><span>High</span></div><div class="metric"><b>${results.size}</b><span>Files with findings</span></div></div>
    ${findings.length ? `<table><thead><tr><th>Finding</th><th>Location</th><th>Risk</th><th>Quantum</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="empty">Run an ECDAT file or workspace scan to populate this report.</div>'}
  </body></html>`;
}
async function exportCbom() {
    const findings = allFindings();
    if (!findings.length) {
        void vscode.window.showInformationMessage('ECDAT: Run a scan before exporting a CBOM.');
        return;
    }
    const target = await vscode.window.showSaveDialog({
        defaultUri: vscode.workspace.workspaceFolders?.[0]
            ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'ecdat-cbom.json')
            : undefined,
        filters: { JSON: ['json'] },
        saveLabel: 'Export ECDAT CBOM',
    });
    if (!target)
        return;
    const riskDistribution = findings.reduce((counts, item) => {
        counts[item.risk] = (counts[item.risk] || 0) + 1;
        return counts;
    }, {});
    const report = {
        specification: 'ECDAT CBOM Prototype 1.0',
        generated_at: new Date().toISOString(),
        workspace: vscode.workspace.name || 'workspace',
        files_with_findings: results.size,
        findings_count: findings.length,
        risk_distribution: riskDistribution,
        findings,
        disclaimer: 'Rule-based prototype inventory; validate findings before security decisions.',
    };
    await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(report, null, 2), 'utf8'));
    void vscode.window.showInformationMessage('ECDAT: CBOM exported successfully.');
}
function riskRank(risk) {
    return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[risk] ?? 5;
}
function escapeHtml(value) {
    return value.replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character] || character));
}
//# sourceMappingURL=extension.js.map