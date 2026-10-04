import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('juliaProfiler.hello', () => {
      void vscode.window.showInformationMessage('Julia Invalidation & Compiler Profiler is active.');
    }),
  );
}

export function deactivate(): void {}
