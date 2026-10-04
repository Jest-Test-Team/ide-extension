import { RuleEngine } from '@ide-ext/core';
import { createTreeSitterHost, DiagnosticsController, loadRulePackFiles, watchRulePackFiles } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';
import { ESP32_RULES } from './esp32Rules';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const output = vscode.window.createOutputChannel('HW Security');
  context.subscriptions.push(output);
  const config = () => vscode.workspace.getConfiguration('hwSecurity');

  // ---- ESP32 / ESPHome firmware linter
  const engine = new RuleEngine(createTreeSitterHost(context));
  const diagnostics = new DiagnosticsController({ name: 'HW Security', engine, onTypeSetting: 'hwSecurity.lint.onType' });
  const applyRules = async () => {
    const disabled = new Set(config().get<string[]>('lint.disabledRules', []));
    const user = await loadRulePackFiles(config().get<string[]>('lint.rulePacks', []), output);
    engine.setRules(config().get<boolean>('lint.enable', true) ? [...ESP32_RULES, ...user.rules].filter((r) => !disabled.has(r.id)) : []);
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
}

export function deactivate(): void {}
