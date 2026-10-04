import { RuleEngine } from '@ide-ext/core';
import { createTreeSitterHost, DiagnosticsController, loadRulePackFiles, registerCliCommands, watchRulePackFiles } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';
import { analyzePuf, assessEntropy, runRestartTest } from './entropy/commands';
import { ESP32_RULES } from './esp32Rules';
import { scaCandidate } from './sca/heuristics';
import { DEF_TAG, ScaCodeLens, ScaCompletion, ScaIndex, ScaNavigation, tagDiagnostics } from './sca/tags';
import { ScaTreeProvider } from './sca/tree';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // Command-line tool bundled in dist/cli (Install … Command in PATH).
  registerCliCommands(context, 'hwSecurity', [{ name: 'jest-hw', script: 'dist/cli/jest-hw.js' }, { name: 'jest-embedded', script: 'dist/cli/jest-hw.js' }]);
  const output = vscode.window.createOutputChannel('HW Security');
  context.subscriptions.push(output);
  const config = () => vscode.workspace.getConfiguration('hwSecurity');

  // ---- ESP32 / ESPHome firmware linter
  const engine = new RuleEngine(createTreeSitterHost(context));
  const diagnostics = new DiagnosticsController({ name: 'HW Security', engine, onTypeSetting: 'hwSecurity.lint.onType' });
  const applyRules = async () => {
    const disabled = new Set(config().get<string[]>('lint.disabledRules', []));
    const user = await loadRulePackFiles(config().get<string[]>('lint.rulePacks', []), output);
    engine.setRules(config().get<boolean>('lint.enable', true) ? [...ESP32_RULES, scaCandidate, ...user.rules].filter((r) => !disabled.has(r.id)) : []);
    diagnostics.refreshOpen();
  };
  await applyRules();
  context.subscriptions.push(
    diagnostics,
    vscode.workspace.onDidChangeConfiguration((e) => e.affectsConfiguration('hwSecurity.lint') && void applyRules()),
    watchRulePackFiles(() => config().get<string[]>('lint.rulePacks', []), () => void applyRules()),
    vscode.commands.registerCommand('hwSecurity.scanWorkspace', async () => {
      const n = await diagnostics.scanWorkspace('**/{*.c,*.h,*.cpp,*.hpp,*.cc,*.ino,sdkconfig,sdkconfig.*,*.yaml,*.yml}', '**/{node_modules,build,managed_components,.pio}/**');
      void vscode.window.showInformationMessage(`HW Security: ${n} finding(s). See the Problems panel.`);
      return n;
    }),
  );

  // ---- Side-channel tags: @sca(id, "desc") in firmware ↔ @sca-ref(id) in ChipWhisperer scripts
  const sca = new ScaIndex();
  const scaDiagnostics = vscode.languages.createDiagnosticCollection('HW Security SCA');
  const selector: vscode.DocumentSelector = [{ language: 'c' }, { language: 'cpp' }, { language: 'python' }, { language: 'arm' }];
  const nav = new ScaNavigation(sca);
  context.subscriptions.push(
    sca,
    scaDiagnostics,
    sca.onDidChange(() => tagDiagnostics(sca, scaDiagnostics)),
    vscode.languages.registerDefinitionProvider(selector, nav),
    vscode.languages.registerReferenceProvider(selector, nav),
    vscode.languages.registerCodeLensProvider(selector, new ScaCodeLens(sca)),
    vscode.languages.registerCompletionItemProvider(selector, new ScaCompletion(sca), '(', ','),
    vscode.window.createTreeView('hwSecurity.scaPoints', { treeDataProvider: new ScaTreeProvider(sca), showCollapseAll: true }),
    vscode.commands.registerCommand('hwSecurity.refreshSca', () => sca.scan()),
    vscode.commands.registerCommand('hwSecurity.insertScaTag', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        return;
      }
      const python = editor.document.languageId === 'python';
      const ids = sca.points().filter((p) => p.defs.length).map((p) => p.id);
      if (python) {
        const id = await vscode.window.showQuickPick(ids, { title: 'Reference which side-channel point?' });
        if (id) {
          await editor.insertSnippet(new vscode.SnippetString(`# @${DEF_TAG}-ref(${id})`));
        }
        return;
      }
      await editor.insertSnippet(new vscode.SnippetString(`// @${DEF_TAG}(\${1:point-id}, "\${2:what leaks, e.g. S-box lookup indexed by key ^ pt}")`));
    }),
  );
  void sca.scan();

  // ---- Entropy source / PUF analysis
  context.subscriptions.push(
    vscode.commands.registerCommand('hwSecurity.assessEntropy', (uri?: vscode.Uri, opts?: { wordSize?: number }) => assessEntropy(context, output, uri, opts)),
    vscode.commands.registerCommand('hwSecurity.restartTest', (uri?: vscode.Uri, opts?: { wordSize?: number; hI?: number }) => runRestartTest(context, uri, opts)),
    vscode.commands.registerCommand('hwSecurity.analyzePuf', (uri?: vscode.Uri) => analyzePuf(context, uri)),
  );
}

export function deactivate(): void {}
