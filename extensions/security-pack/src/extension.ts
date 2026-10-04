import { registerCliCommands } from '@ide-ext/core/vscode';
import type * as vscode from 'vscode';

/** The pack's only code: the combined `jest-security` command-line tool (dist/cli/jest-security.js). */
export function activate(context: vscode.ExtensionContext): void {
  registerCliCommands(context, 'securityPack', [{ name: 'jest-security', script: 'dist/cli/jest-security.js' }]);
}

export function deactivate(): void {}
