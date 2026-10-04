import * as vscode from 'vscode';
import { parseRulePack } from '../rules/load';
import type { Rule } from '../rules/schema';

/**
 * Loads user rule packs (YAML/JSON) named by workspace-relative or absolute paths, typically from
 * a `*.rulePacks` setting. Problems are written to `output` and returned.
 */
export async function loadRulePackFiles(paths: readonly string[], output?: vscode.OutputChannel): Promise<{ rules: Rule[]; errors: string[] }> {
  const rules: Rule[] = [];
  const errors: string[] = [];
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const p of paths) {
    const candidates = /^([a-z]:)?[\\/]/i.test(p) ? [vscode.Uri.file(p)] : folders.map((f) => vscode.Uri.joinPath(f.uri, p));
    let loaded = false;
    for (const uri of candidates) {
      let text: string;
      try {
        text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
      } catch {
        continue;
      }
      const res = parseRulePack(text, uri.fsPath);
      rules.push(...(res.pack?.rules ?? []));
      errors.push(...res.errors);
      loaded = true;
      break;
    }
    if (!loaded) {
      errors.push(`Rule pack not found: ${p}`);
    }
  }
  errors.forEach((e) => output?.appendLine(`[rules] ${e}`));
  return { rules, errors };
}

/** Re-runs `load` when any of the watched rule-pack files change on disk. */
export function watchRulePackFiles(paths: () => readonly string[], onChange: () => void): vscode.Disposable {
  const watcher = vscode.workspace.createFileSystemWatcher('**/*.{yaml,yml,json}');
  const handler = (uri: vscode.Uri) => {
    const rel = vscode.workspace.asRelativePath(uri, false);
    if (paths().some((p) => p === rel || uri.fsPath === p)) {
      onChange();
    }
  };
  watcher.onDidChange(handler);
  watcher.onDidCreate(handler);
  watcher.onDidDelete(handler);
  return watcher;
}
