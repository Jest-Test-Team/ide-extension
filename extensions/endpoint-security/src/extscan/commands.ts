import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import * as vscode from 'vscode';
import { parseRemovedPackages, REMOVED_PACKAGES_URL, toSnapshot } from './knownBad';
import { toExtensionMarkdown, toExtensionSarif } from './report';
import { ExtensionScanner, type ExtResult } from './scanner';
import { ExtScanTreeProvider, type ExtScanItem } from './tree';

const SECTION = 'endpointSecurity.extensionScan';
const KNOWN_BAD_MAX_AGE_MS = 7 * 24 * 3600 * 1000;

/** Plain summary returned by the scan command (used by tests and other extensions). */
export interface ScanSummary {
  id: string;
  version: string;
  level: string;
  score: number;
  signals: string[];
}

const summary = (r: ExtResult): ScanSummary => ({ id: r.ext.id, version: r.ext.version, level: r.risk.level, score: r.risk.score, signals: r.risk.signals.map((s) => s.id) });

/** Downloads RemovedPackages.md into global storage. Sends no information about installed extensions. */
async function updateKnownBadList(scanner: ExtensionScanner, output: vscode.OutputChannel): Promise<number> {
  const res = await fetch(REMOVED_PACKAGES_URL);
  if (!res.ok) {
    throw new Error(`GET ${REMOVED_PACKAGES_URL}: HTTP ${res.status}`);
  }
  const entries = parseRemovedPackages(await res.text());
  if (entries.length < 100) {
    throw new Error(`only ${entries.length} entries parsed; the list format may have changed`);
  }
  await mkdir(dirname(scanner.knownBadPath), { recursive: true });
  await writeFile(scanner.knownBadPath, JSON.stringify(toSnapshot(entries)));
  output.appendLine(`[extensions] known-bad list updated: ${entries.length} entries`);
  return entries.length;
}

async function knownBadIsStale(scanner: ExtensionScanner): Promise<boolean> {
  try {
    const st = await vscode.workspace.fs.stat(vscode.Uri.file(scanner.knownBadPath));
    return Date.now() - st.mtime > KNOWN_BAD_MAX_AGE_MS;
  } catch {
    return true;
  }
}

export function registerExtensionScan(context: vscode.ExtensionContext, output: vscode.OutputChannel): ExtensionScanner {
  const scanner = new ExtensionScanner(context, output);
  const tree = new ExtScanTreeProvider(scanner);
  const view = vscode.window.createTreeView('endpointSecurity.extensions', { treeDataProvider: tree, showCollapseAll: true });
  const config = () => vscode.workspace.getConfiguration(SECTION);
  const extOf = (item?: ExtScanItem) => item?.result.ext;

  const updateBadge = () => {
    const high = scanner.latest.filter((r) => r.risk.level === 'high').length;
    view.badge = high ? { value: high, tooltip: `${high} high-risk extension(s)` } : undefined;
  };

  const setAllowlist = async (id: string, add: boolean) => {
    const list = config().get<string[]>('allowlist', []);
    const lower = id.toLowerCase();
    const next = add ? [...list, id] : list.filter((e) => e.toLowerCase().split('@')[0] !== lower);
    await config().update('allowlist', [...new Set(next)], vscode.ConfigurationTarget.Global);
  };

  context.subscriptions.push(
    scanner,
    view,
    scanner.onDidChange(updateBadge),
    vscode.commands.registerCommand('endpointSecurity.scanExtensions', async (opts?: { force?: boolean }): Promise<ScanSummary[]> => {
      if (config().get<boolean>('updateKnownBadList', false) && (await knownBadIsStale(scanner))) {
        await updateKnownBadList(scanner, output).catch((err: Error) => output.appendLine(`[extensions] known-bad list update failed: ${err.message}`));
      }
      const results = await scanner.scan({ force: opts?.force });
      const high = results.filter((r) => r.risk.level === 'high');
      if (high.length) {
        void vscode.window
          .showWarningMessage(`Extension scan: ${high.length} high-risk extension(s): ${high.map((r) => r.ext.id).join(', ')}.`, 'Show')
          .then((pick) => pick && view.reveal({ kind: 'ext', result: high[0] }, { focus: true }));
      }
      return results.map(summary);
    }),
    vscode.commands.registerCommand('endpointSecurity.exportExtensionReport', async (target?: vscode.Uri) => {
      const results = scanner.latest.length ? scanner.latest : await scanner.scan();
      const dest =
        target ??
        (await vscode.window.showSaveDialog({
          defaultUri: vscode.workspace.workspaceFolders?.[0] && vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'extension-risk.sarif'),
          filters: { SARIF: ['sarif'], Markdown: ['md'] },
        }));
      if (!dest) {
        return undefined;
      }
      const version = (context.extension.packageJSON as { version: string }).version;
      const content = dest.path.endsWith('.md') ? toExtensionMarkdown(results, scanner.codeRules) : JSON.stringify(toExtensionSarif(results, scanner.codeRules, version), null, 2);
      await vscode.workspace.fs.writeFile(dest, new TextEncoder().encode(content));
      void vscode.window.showInformationMessage(`Wrote ${vscode.workspace.asRelativePath(dest)} (${results.length} extension(s)).`);
      return dest;
    }),
    vscode.commands.registerCommand('endpointSecurity.extensionScan.allowlist', async (item?: ExtScanItem) => {
      const ext = extOf(item);
      if (!ext) {
        return;
      }
      const pick = await vscode.window.showQuickPick(
        [
          { label: `Trust ${ext.id}@${ext.version} only`, description: 'An update is scored again', value: `${ext.id}@${ext.version}` },
          { label: `Trust every version of ${ext.id}`, value: ext.id },
        ],
        { title: `Allowlist ${ext.displayName ?? ext.id}` },
      );
      if (pick) {
        await setAllowlist(pick.value, true);
      }
    }),
    vscode.commands.registerCommand('endpointSecurity.extensionScan.unallowlist', async (item?: ExtScanItem) => {
      const ext = extOf(item);
      if (ext) {
        await setAllowlist(ext.id, false);
      }
    }),
    vscode.commands.registerCommand('endpointSecurity.extensionScan.openInMarketplace', async (item?: ExtScanItem) => {
      const ext = extOf(item);
      if (!ext) {
        return;
      }
      try {
        await vscode.commands.executeCommand('extension.open', ext.id);
      } catch {
        await vscode.commands.executeCommand('workbench.extensions.search', `@id:${ext.id}`);
      }
    }),
    vscode.commands.registerCommand('endpointSecurity.extensionScan.revealFolder', async (item?: ExtScanItem) => {
      const ext = extOf(item);
      if (ext) {
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(ext.path));
      }
    }),
    vscode.commands.registerCommand('endpointSecurity.extensionScan.updateKnownBadList', async () => {
      try {
        const n = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Downloading the Marketplace removed-extensions list' }, () =>
          updateKnownBadList(scanner, output),
        );
        void vscode.window.showInformationMessage(`Known-bad list updated (${n} entries).`);
        if (scanner.latest.length) {
          await scanner.scan({ quiet: true });
        }
        return n;
      } catch (err) {
        void vscode.window.showErrorMessage(`Could not update the known-bad list: ${(err as Error).message}`);
        return undefined;
      }
    }),
  );
  return scanner;
}
