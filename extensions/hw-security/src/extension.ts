import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('hwSecurity.hello', () => {
      void vscode.window.showInformationMessage('Embedded Hardware Security Workbench is active.');
    }),
  );
}

export function deactivate(): void {}
