import { RuleEngine, type Rule } from '@ide-ext/core';
import { createTreeSitterHost, DiagnosticsController, loadRulePackFiles, watchRulePackFiles } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';
import { API_LANGUAGES, ApiCompletionProvider, ApiHoverProvider, ApiSignatureHelpProvider } from './apiProviders';
import { API_RULES } from './apiRules';

/** Rule groups that can be toggled as a whole. */
const RULE_GROUPS: { setting: string; rules: () => Rule[] }[] = [{ setting: 'apiRules.enable', rules: () => API_RULES }];

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const output = vscode.window.createOutputChannel('Endpoint Security');
  context.subscriptions.push(output);
  const config = () => vscode.workspace.getConfiguration('endpointSecurity');

  const engine = new RuleEngine(createTreeSitterHost(context));
  const diagnostics = new DiagnosticsController({ name: 'Endpoint Security', engine, onTypeSetting: 'endpointSecurity.lintOnType' });
  const applyRules = async () => {
    const disabled = new Set(config().get<string[]>('disabledRules', []));
    const user = await loadRulePackFiles(config().get<string[]>('rulePacks', []), output);
    const builtIn = RULE_GROUPS.filter((g) => config().get<boolean>(g.setting, true)).flatMap((g) => g.rules());
    engine.setRules([...builtIn, ...user.rules].filter((r) => !disabled.has(r.id)));
    diagnostics.refreshOpen();
  };
  await applyRules();

  context.subscriptions.push(
    diagnostics,
    vscode.workspace.onDidChangeConfiguration((e) => e.affectsConfiguration('endpointSecurity') && void applyRules()),
    watchRulePackFiles(() => config().get<string[]>('rulePacks', []), () => void applyRules()),
    vscode.languages.registerHoverProvider(API_LANGUAGES, new ApiHoverProvider()),
    vscode.languages.registerSignatureHelpProvider(API_LANGUAGES, new ApiSignatureHelpProvider(), '(', ','),
    vscode.languages.registerCompletionItemProvider(API_LANGUAGES, new ApiCompletionProvider()),
    vscode.commands.registerCommand('endpointSecurity.scanWorkspace', async () => {
      const n = await diagnostics.scanWorkspace(
        '**/*.{c,h,cc,cpp,hpp,m,mm,rs,go,ts,tsx,js,jsx,mjs,cjs}',
        '**/{node_modules,target,build,dist,out,vendor,.git}/**',
      );
      void vscode.window.showInformationMessage(`Endpoint Security: ${n} finding(s). See the Problems panel.`);
      return n;
    }),
  );
}

export function deactivate(): void {}
