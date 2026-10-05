import type { Rule } from '@ide-ext/core';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import * as vscode from 'vscode';
import { loadCodeRules, type CodeScanOptions, type CodeScanResult } from './codeScan';
import { loadManifestOptions } from './data';
import { inventory } from './inventory';
import { manifestSignals, type ExtInfo } from './manifest';
import { combinedSignals, deepManifestSignals } from './manifestDeep';
import { isAllowlisted, scoreExtension, type RiskScore } from './score';
import type { Signal } from './signals';
import type { ScanWorkerRequest, ScanWorkerResponse } from './worker';

export interface ExtResult {
  ext: Omit<ExtInfo, 'packageJSON' | 'packageJsonText'>;
  risk: RiskScore;
}

/** Extra signals per extension from an optional source (the opt-in Marketplace lookup). */
export type SignalProvider = (exts: ExtInfo[], token: vscode.CancellationToken) => Promise<Map<string, Signal[]>>;

interface CacheFile {
  version: 1;
  entries: Record<string, CodeScanResult>;
}

const RANK = { high: 2, medium: 1, low: 0 } as const;
export const KNOWN_BAD_FILE = 'removed-packages.json';

/** Runs scans (code in a worker thread, cached per extension version) and holds the latest results. */
export class ExtensionScanner implements vscode.Disposable {
  private results: ExtResult[] = [];
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.emitter.event;
  readonly codeRules: Rule[];
  private readonly rulesVersion: string;
  private running: Promise<ExtResult[]> | undefined;
  private scannedOnce = false;
  private readonly disposables: vscode.Disposable[] = [this.emitter];
  extraSignals: SignalProvider | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly output: vscode.OutputChannel,
  ) {
    const loaded = loadCodeRules(this.dataDir);
    this.codeRules = loaded.rules;
    this.rulesVersion = loaded.version;
    this.disposables.push(
      // Install / uninstall / update: rescan quietly (cached extensions are not re-read).
      vscode.extensions.onDidChange(() => this.scannedOnce && void this.scan({ quiet: true })),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (this.scannedOnce && (e.affectsConfiguration('endpointSecurity.extensionScan.allowlist') || e.affectsConfiguration('endpointSecurity.extensionScan.trustedPublishers'))) {
          void this.scan({ quiet: true });
        }
      }),
    );
  }

  private get dataDir(): string {
    return join(this.context.extensionPath, 'dist', 'extscan');
  }

  private get config() {
    return vscode.workspace.getConfiguration('endpointSecurity.extensionScan');
  }

  get knownBadPath(): string {
    return join(this.context.globalStorageUri.fsPath, KNOWN_BAD_FILE);
  }

  get latest(): readonly ExtResult[] {
    return this.results;
  }

  /** Scans (or rescans) every installed extension. Concurrent calls share one run. */
  scan(opts: { quiet?: boolean; force?: boolean } = {}): Promise<ExtResult[]> {
    this.running ??= this.run(opts).finally(() => (this.running = undefined));
    return this.running;
  }

  private async run(opts: { quiet?: boolean; force?: boolean }): Promise<ExtResult[]> {
    const cfg = this.config;
    const all = inventory().filter((e) => cfg.get<boolean>('includeBuiltin', false) || !e.builtin);
    const codeOpts: CodeScanOptions = {
      includeNodeModules: cfg.get<boolean>('includeNodeModules', true),
      maxFileSizeMB: cfg.get<number>('maxFileSizeMB', 10),
      maxFiles: cfg.get<number>('maxFilesPerExtension', 2000),
    };
    const manifestOpts = loadManifestOptions(this.dataDir, cfg.get<string[]>('trustedPublishers', []), this.knownBadPath);
    const allowlist = cfg.get<string[]>('allowlist', []);
    const optsKey = createHash('sha256').update(JSON.stringify(codeOpts)).digest('hex').slice(0, 8);
    const keyOf = (e: ExtInfo) => `${e.id}@${e.version}|${e.path}|${this.rulesVersion}|${optsKey}`;

    const cache = opts.force ? { version: 1 as const, entries: {} } : await this.readCache();
    const results = await vscode.window.withProgress(
      {
        location: opts.quiet ? vscode.ProgressLocation.Window : vscode.ProgressLocation.Notification,
        title: 'Scanning installed extensions',
        cancellable: !opts.quiet,
      },
      async (progress, token) => {
        const extra = this.extraSignals ? await this.extraSignals(all, token).catch((err: Error) => this.warn('Marketplace lookup failed', err)) : undefined;
        const todo = all.filter((e) => !cache.entries[keyOf(e)]);
        const worker = todo.length ? new ScanWorker(join(this.context.extensionPath, 'dist', 'extScanWorker.js')) : undefined;
        // Stop at once, even in the middle of a large file.
        const cancel = token.onCancellationRequested(() => worker?.dispose());
        try {
          let done = 0;
          for (const e of todo) {
            if (token.isCancellationRequested) {
              break;
            }
            progress.report({ message: `${e.displayName ?? e.id} (${++done}/${todo.length})`, increment: 100 / todo.length });
            try {
              cache.entries[keyOf(e)] = await worker!.scan(e.path, e.packageJSON, codeOpts);
            } catch (err) {
              if (!token.isCancellationRequested) {
                this.warn(`Could not scan ${e.id}`, err as Error);
              }
            }
          }
        } finally {
          cancel.dispose();
          worker?.dispose();
        }
        // Keep cache entries for installed extensions only.
        const live = new Set(all.map(keyOf));
        await this.writeCache({ version: 1, entries: Object.fromEntries(Object.entries(cache.entries).filter(([k]) => live.has(k))) });

        return all.map((e): ExtResult => {
          const base = [...manifestSignals(e, manifestOpts), ...deepManifestSignals(e, manifestOpts), ...(cache.entries[keyOf(e)]?.signals ?? []), ...(extra?.get(e.id.toLowerCase()) ?? [])];
          const signals = [...base, ...combinedSignals(e, base)];
          const ext = { id: e.id, version: e.version, displayName: e.displayName, path: e.path, builtin: e.builtin, source: e.source };
          return { ext, risk: scoreExtension(signals, { allowlisted: isAllowlisted(e.id, e.version, allowlist) }) };
        });
      },
    );
    results.sort((a, b) => RANK[b.risk.level] - RANK[a.risk.level] || b.risk.score - a.risk.score || a.ext.id.localeCompare(b.ext.id));
    this.results = results;
    this.scannedOnce = true;
    this.emitter.fire();
    const counts = results.reduce((m, r) => ({ ...m, [r.risk.level]: (m[r.risk.level] ?? 0) + 1 }), {} as Record<string, number>);
    this.output.appendLine(`[extensions] scanned ${results.length}: ${counts.high ?? 0} high, ${counts.medium ?? 0} medium, ${counts.low ?? 0} low (known-bad list from ${manifestOpts.knownBadFetched.slice(0, 10)})`);
    return results;
  }

  private warn(what: string, err: Error): undefined {
    this.output.appendLine(`[extensions] ${what}: ${err.message}`);
    return undefined;
  }

  private get cacheUri(): vscode.Uri {
    return vscode.Uri.joinPath(this.context.globalStorageUri, 'extscan-cache.json');
  }

  private async readCache(): Promise<CacheFile> {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(await vscode.workspace.fs.readFile(this.cacheUri))) as CacheFile;
      if (parsed.version === 1 && parsed.entries) {
        return parsed;
      }
    } catch {
      // first run or unreadable cache
    }
    return { version: 1, entries: {} };
  }

  private async writeCache(cache: CacheFile): Promise<void> {
    try {
      await vscode.workspace.fs.createDirectory(this.context.globalStorageUri);
      await vscode.workspace.fs.writeFile(this.cacheUri, new TextEncoder().encode(JSON.stringify(cache)));
    } catch (err) {
      this.warn('Could not write the scan cache', err as Error);
    }
  }

  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }
}

/** One worker thread for a scan run; requests are answered in order. */
class ScanWorker {
  private readonly worker: Worker;
  private seq = 0;
  private readonly pending = new Map<number, { resolve: (r: CodeScanResult) => void; reject: (e: Error) => void }>();

  constructor(script: string) {
    this.worker = new Worker(script);
    this.worker.on('message', (m: ScanWorkerResponse) => {
      const p = this.pending.get(m.seq);
      this.pending.delete(m.seq);
      if (m.type === 'result') {
        p?.resolve(m.result);
      } else {
        p?.reject(new Error(m.message));
      }
    });
    this.worker.on('error', (err) => this.failAll(err));
    this.worker.on('exit', (code) => this.failAll(new Error(`scan worker exited (${code})`)));
  }

  scan(dir: string, pkg: Record<string, unknown>, opts: CodeScanOptions): Promise<CodeScanResult> {
    const seq = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(seq, { resolve, reject });
      this.worker.postMessage({ type: 'scan', seq, dir, pkg, opts } satisfies ScanWorkerRequest);
    });
  }

  private failAll(err: Error): void {
    this.pending.forEach((p) => p.reject(err));
    this.pending.clear();
  }

  dispose(): void {
    void this.worker.terminate();
  }
}
