import { RuleEngine, toMarkdownReport, toSarif, type Finding, type Rule } from '@ide-ext/core';
import { createTreeSitterHost, DiagnosticsController, loadRulePackFiles, watchRulePackFiles } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';
import { API_LANGUAGES, ApiCompletionProvider, ApiHoverProvider, ApiSignatureHelpProvider } from './apiProviders';
import { join } from 'node:path';
import { API_RULES } from './apiRules';
import { COMPLIANCE_CUSTOM_RULES } from './complianceRules';
import { SCENARIO_SELECTOR, SCENARIO_TEMPLATE, SimulateCodeLens, Simulator } from './ptree/commands';
import { loadBuiltInPacks, rulesOf } from './rulePacks';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const packs = loadBuiltInPacks(join(context.extensionPath, 'dist', 'rules'));
  const complianceRules = [...rulesOf(packs), ...COMPLIANCE_CUSTOM_RULES];
  /** Rule groups that can be toggled as a whole. */
  const RULE_GROUPS: { setting: string; rules: () => Rule[] }[] = [
    { setting: 'apiRules.enable', rules: () => API_RULES },
    { setting: 'compliance.enable', rules: () => complianceRules },
  ];
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
    vscode.commands.registerCommand('endpointSecurity.exportReport', async (target?: vscode.Uri, opts?: { scan?: boolean }) => {
      if (opts?.scan ?? true) {
        await vscode.commands.executeCommand('endpointSecurity.scanWorkspace');
      }
      const isCompliance = (f: Finding) => /^(pci|ccsp)\//.test(f.ruleId);
      const findings = new Map<string, Finding[]>();
      for (const [uri, list] of diagnostics.allFindings()) {
        const relevant = list.filter(isCompliance);
        if (relevant.length) {
          findings.set(vscode.workspace.asRelativePath(vscode.Uri.parse(uri), false), relevant);
        }
      }
      const dest =
        target ??
        (await vscode.window.showSaveDialog({
          defaultUri: vscode.workspace.workspaceFolders?.[0] && vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'compliance-report.sarif'),
          filters: { SARIF: ['sarif'], Markdown: ['md'] },
        }));
      if (!dest) {
        return undefined;
      }
      const version = (context.extension.packageJSON as { version: string }).version;
      const content = dest.path.endsWith('.md')
        ? toMarkdownReport(`Compliance report (${packs.map((p) => p.title).join(', ')})`, complianceRules, findings)
        : JSON.stringify(
            toSarif({
              toolName: 'Endpoint Security & Compliance Toolkit',
              toolVersion: version,
              informationUri: 'https://github.com/Jest-Test-Team/ide-extension',
              rules: complianceRules,
              findings,
            }),
            null,
            2,
          );
      await vscode.workspace.fs.writeFile(dest, new TextEncoder().encode(content));
      void vscode.window.showInformationMessage(`Wrote ${vscode.workspace.asRelativePath(dest)} (${[...findings.values()].flat().length} finding(s)).`);
      return dest;
    }),
  );

  // ---- Process-tree simulation (data-only replay through the local / remote agent)
  const simulator = new Simulator(context);
  context.subscriptions.push(
    simulator,
    vscode.languages.registerCodeLensProvider(SCENARIO_SELECTOR, new SimulateCodeLens()),
    vscode.commands.registerCommand('endpointSecurity.simulateScenario', (uri?: vscode.Uri) => simulator.simulate(uri)),
    vscode.commands.registerCommand('endpointSecurity.newScenario', async () => {
      const doc = await vscode.workspace.openTextDocument({ language: 'yaml', content: SCENARIO_TEMPLATE });
      await vscode.window.showTextDocument(doc);
      void vscode.window.showInformationMessage('Save the scenario as <name>.ptree.yaml to enable the ▶ Simulate CodeLens.');
    }),
  );
}

export function deactivate(): void {}
