import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('endpointSecurity.hello', () => {
      void vscode.window.showInformationMessage('Endpoint Security & Compliance Toolkit is active.');
    }),
  );
}

export function deactivate(): void {}
