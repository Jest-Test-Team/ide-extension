import { openWebview } from '@ide-ext/core/vscode';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as vscode from 'vscode';
import { AgentClient, AgentError } from './agentClient';
import type { SimulationResult } from './engine';

export const SCENARIO_SELECTOR: vscode.DocumentSelector = [{ pattern: '**/*.ptree.{yaml,yml}' }];

export class Simulator implements vscode.Disposable {
  readonly agent: AgentClient;
  readonly diagnostics = vscode.languages.createDiagnosticCollection('Process Tree Simulation');
  private readonly defaultRules: string;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.agent = new AgentClient(join(context.extensionPath, 'dist', 'ptreeAgent.js'), () =>
      vscode.workspace.getConfiguration('endpointSecurity').get<string>('simulation.agentUrl'),
    );
    this.defaultRules = readFileSync(join(context.extensionPath, 'dist', 'ptree', 'default-rules.yaml'), 'utf8');
  }

  private async ruleTexts(): Promise<string[]> {
    const cfg = vscode.workspace.getConfiguration('endpointSecurity');
    const texts = cfg.get<boolean>('simulation.useDefaultRules', true) ? [this.defaultRules] : [];
    for (const rel of cfg.get<string[]>('simulation.ruleFiles', [])) {
      for (const f of vscode.workspace.workspaceFolders ?? []) {
        try {
          texts.push(new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(f.uri, rel))));
          break;
        } catch {
          // try the next folder
        }
      }
    }
    return texts;
  }

  async simulate(uri?: vscode.Uri): Promise<SimulationResult | undefined> {
    const target = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (!target) {
      return undefined;
    }
    const doc = await vscode.workspace.openTextDocument(target);
    this.diagnostics.delete(target);
    let result: SimulationResult;
    try {
      result = await this.agent.simulate(doc.getText(), await this.ruleTexts());
    } catch (err) {
      const line = err instanceof AgentError && err.line ? err.line - 1 : 0;
      const d = new vscode.Diagnostic(doc.lineAt(Math.min(line, doc.lineCount - 1)).range, (err as Error).message, vscode.DiagnosticSeverity.Error);
      d.source = 'Process Tree Simulation';
      this.diagnostics.set(target, [d]);
      void vscode.window.showErrorMessage(`Simulation failed: ${(err as Error).message}`);
      return undefined;
    }
    this.diagnostics.set(
      target,
      result.warnings.map((w) => {
        const line = Number(/^line (\d+)/.exec(w)?.[1] ?? 1) - 1;
        const d = new vscode.Diagnostic(doc.lineAt(Math.min(line, doc.lineCount - 1)).range, w, vscode.DiagnosticSeverity.Warning);
        d.source = 'Process Tree Simulation';
        return d;
      }),
    );
    openWebview<{ type: string; line?: number }>({
      context: this.context,
      viewType: 'endpointSecurity.ptree',
      title: `Simulation — ${result.scenario}`,
      script: 'ptree.js',
      key: target.toString(),
      initialMessage: { type: 'simulation', file: vscode.workspace.asRelativePath(target), result },
      onMessage: (msg) => {
        if (msg.type === 'reveal' && msg.line) {
          const pos = new vscode.Position(msg.line - 1, 0);
          void vscode.window.showTextDocument(target, { selection: new vscode.Range(pos, pos), viewColumn: vscode.ViewColumn.One });
        }
      },
    });
    return result;
  }

  dispose(): void {
    this.agent.dispose();
    this.diagnostics.dispose();
  }
}

export class SimulateCodeLens implements vscode.CodeLensProvider {
  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    const events = (doc.getText().match(/^\s*-\s*\{?\s*(t:|type:)/gm) ?? []).length;
    return [
      new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), { title: '▶ Simulate', command: 'endpointSecurity.simulateScenario', arguments: [doc.uri] }),
      new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), { title: `${events} event(s)`, command: '' }),
    ];
  }
}

export const SCENARIO_TEMPLATE = `scenario: New scenario
description: Describe the behaviour being modelled.
processes:
  - { id: explorer, image: 'C:\\\\Windows\\\\explorer.exe', user: alice }
events:
  - { t: 0, type: spawn, process: p1, parent: explorer, image: 'C:\\\\Windows\\\\System32\\\\cmd.exe', cmdline: 'cmd.exe /c whoami' }
  - { t: 100, type: terminate, process: p1 }
rules: []
`;
