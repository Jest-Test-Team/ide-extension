import { join } from 'node:path';
import type * as vscode from 'vscode';
import { TreeSitterHost } from '../parsing/treeSitter';

export * from './convert';
export * from './diagnostics';
export * from './webview';
export * from './proc';

/** Tree-sitter host reading `tree-sitter.wasm` and grammar files from `dist/grammars`. */
export function createTreeSitterHost(context: vscode.ExtensionContext): TreeSitterHost {
  const host = new TreeSitterHost(join(context.extensionPath, 'dist', 'grammars'));
  context.subscriptions.push({ dispose: () => host.dispose() });
  return host;
}
