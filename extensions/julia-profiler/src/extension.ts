import { openLocation, openWebview } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';
import { analyze, createWorkload } from './analyze';
import { InvalidationTreeProvider } from './invalidationTree';
import { summarize } from './profile';
import { ProfileStore } from './store';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const output = vscode.window.createOutputChannel('Julia Profiler');
  const store = new ProfileStore(context);
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'juliaProfiler.showInvalidations';
  context.subscriptions.push(output, store, status);

  const refreshStatus = () => {
    const p = store.profile;
    if (!p) {
      status.hide();
      return;
    }
    const s = summarize(p);
    status.text = `$(flame) ${s.invalidated} invalidated`;
    status.tooltip = `Julia profile from ${p.createdAt}\n${s.trees} invalidation tree(s)` +
      (s.inferenceTime !== undefined ? `\n${s.inferenceTime.toFixed(2)} s inference` : '');
    status.show();
  };
  context.subscriptions.push(store.onDidChange(refreshStatus));

  const tree = new InvalidationTreeProvider(store);
  const showReport = () =>
    openWebview({
      context,
      viewType: 'juliaProfiler.report',
      title: 'Julia Compiler Profile',
      script: 'report.js',
      initialMessage: { type: 'profile', profile: store.profile ?? null },
    });
  context.subscriptions.push(
    vscode.window.createTreeView('juliaProfiler.invalidations', { treeDataProvider: tree, showCollapseAll: true }),
    store.onDidChange((profile) => {
      // Keep an open report in sync without stealing focus.
      void vscode.commands.executeCommand('setContext', 'juliaProfiler.hasProfile', !!profile);
    }),
    vscode.commands.registerCommand('juliaProfiler.showInvalidations', () =>
      vscode.commands.executeCommand('juliaProfiler.invalidations.focus'),
    ),
    vscode.commands.registerCommand('juliaProfiler.showFlameGraph', showReport),
    vscode.commands.registerCommand('juliaProfiler.openLocation', (loc: { file: string; line: number }) => openLocation(loc)),
    vscode.commands.registerCommand('juliaProfiler.filterInvalidations', async () => {
      const text = await vscode.window.showInputBox({ prompt: 'Filter invalidation roots by method, module, signature or file' });
      if (text !== undefined) {
        tree.setFilter(text);
      }
    }),
    vscode.commands.registerCommand('juliaProfiler.clearFilter', () => tree.setFilter('')),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('juliaProfiler.analyze', () => analyze(context, store, output)),
    vscode.commands.registerCommand('juliaProfiler.createWorkload', () => createWorkload()),
    vscode.commands.registerCommand('juliaProfiler.openProfile', async (uri?: vscode.Uri) => {
      const target = uri ?? (await vscode.window.showOpenDialog({ filters: { 'Profiler JSON': ['json'] }, canSelectMany: false }))?.[0];
      if (!target) {
        return undefined;
      }
      try {
        const profile = await store.load(target);
        void vscode.commands.executeCommand('juliaProfiler.showInvalidations');
        return profile;
      } catch (err) {
        void vscode.window.showErrorMessage(`Cannot load profile: ${(err as Error).message}`);
        return undefined;
      }
    }),
    vscode.commands.registerCommand('juliaProfiler.clearProfile', () => store.set(undefined)),
  );

  await store.restore();
  refreshStatus();
  void vscode.commands.executeCommand('setContext', 'juliaProfiler.hasProfile', !!store.profile);
}

export function deactivate(): void {}
