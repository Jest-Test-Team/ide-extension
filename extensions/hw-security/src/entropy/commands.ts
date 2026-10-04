import { openWebview, runProcess } from '@ide-ext/core/vscode';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import * as vscode from 'vscode';
import { parsePufCsv, parseSamples } from './parse';
import { blockFailureProbability, pufMetrics, requiredCorrection } from './puf';
import type { RestartResult } from './restart';
import { ESTIMATORS, type EstimatorId, type NonIidResult } from './sp80090b';
import type { WorkerRequest } from './worker';

function runWorker<T>(context: vscode.ExtensionContext, req: WorkerRequest, token: vscode.CancellationToken, onProgress?: (id: string) => void): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(join(context.extensionPath, 'dist', 'entropyWorker.js'));
    const sub = token.onCancellationRequested(() => {
      void worker.terminate();
      resolve(undefined);
    });
    worker.on('message', (m: { type: string; id?: string; result?: T; message?: string }) => {
      if (m.type === 'progress') {
        onProgress?.(m.id!);
      } else {
        sub.dispose();
        void worker.terminate();
        if (m.type === 'done') {
          resolve(m.result);
        } else {
          reject(new Error(m.message));
        }
      }
    });
    worker.on('error', (e) => {
      sub.dispose();
      reject(e);
    });
    worker.postMessage(req);
  });
}

async function pickFile(uri: vscode.Uri | undefined, title: string, filters: Record<string, string[]>): Promise<vscode.Uri | undefined> {
  return uri ?? (await vscode.window.showOpenDialog({ title, filters, canSelectMany: false }))?.[0];
}

async function pickWordSize(preset?: number): Promise<number | undefined> {
  if (preset !== undefined) {
    return preset;
  }
  const pick = await vscode.window.showQuickPick(
    [{ label: 'Auto', description: 'infer from the largest sample value', n: 0 }, ...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ label: `${n}`, description: 'bits per sample', n }))],
    { title: 'Bits per sample' },
  );
  return pick?.n;
}

const LABEL: Record<string, string> = Object.fromEntries(ESTIMATORS.map((e) => [e.id, `${e.section} ${e.title}`]));

/** Parses `ea_non_iid -o` JSON into per-estimator values (for the optional cross-check). */
function parseNistJson(text: string): { literal: Record<string, number>; bitstring: Record<string, number>; hAssessed?: number } {
  const map: Record<string, EstimatorId> = {
    'Most Common Value': 'mcv',
    'Collision Test (for bit strings only)': 'collision',
    'Markov Test (for bit strings only)': 'markov',
    'Compression Test (for bit strings only)': 'compression',
    'Multi Most Common in Window Test': 'multiMcw',
    'Lag Prediction Test': 'lag',
    'Multi Markov Model with Counting Test (MultiMMC)': 'multiMmc',
    'LZ78Y Test': 'lz78y',
  };
  const literal: Record<string, number> = {};
  const bitstring: Record<string, number> = {};
  let hAssessed: number | undefined;
  for (const t of (JSON.parse(text) as { testCases: Record<string, unknown>[] }).testCases) {
    const d = String(t.testCaseDesc);
    if (d === 'Overall') {
      hAssessed = Number(t.hAssessed);
    } else if (d === 'T-Tuple Test' || d === 'LRS Test') {
      const id = d === 'T-Tuple Test' ? 'tTuple' : 'lrs';
      const lit = Number(t[id === 'tTuple' ? 'tTupleRes' : 'lrsRes']);
      const bin = Number(t[id === 'tTuple' ? 'binTTupleRes' : 'binLrsRes']);
      if (lit >= 0) literal[id] = lit;
      if (bin >= 0) bitstring[id] = bin;
    } else if (map[d]) {
      if (t.hOriginal !== undefined) literal[map[d]] = Number(t.hOriginal);
      if (t.hBitstring !== undefined) bitstring[map[d]] = Number(t.hBitstring);
    }
  }
  return { literal, bitstring, hAssessed };
}

export async function assessEntropy(
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
  uri?: vscode.Uri,
  opts: { wordSize?: number } = {},
): Promise<NonIidResult | undefined> {
  const file = await pickFile(uri, 'Raw noise-source samples', { Samples: ['bin', 'dat', 'raw', 'txt', 'csv'] });
  if (!file) {
    return undefined;
  }
  const wordSize = await pickWordSize(opts.wordSize);
  if (wordSize === undefined) {
    return undefined;
  }
  const name = vscode.workspace.asRelativePath(file);
  let data: Uint8Array;
  try {
    data = parseSamples(file.fsPath, await vscode.workspace.fs.readFile(file));
  } catch (err) {
    void vscode.window.showErrorMessage(`Cannot read samples: ${(err as Error).message}`);
    return undefined;
  }
  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `SP 800-90B assessment of ${name}`, cancellable: true },
    async (progress, token) => {
      try {
        return await runWorker<NonIidResult>(context, { kind: 'nonIid', data, wordSize, initialEntropy: true, allBits: false }, token, (id) =>
          progress.report({ message: LABEL[id], increment: 10 }),
        );
      } catch (err) {
        void vscode.window.showErrorMessage(`Assessment failed: ${(err as Error).message}`);
        return undefined;
      }
    },
  );
  if (!result) {
    return undefined;
  }
  // Optional cross-check against NIST's reference tool.
  let nist: ReturnType<typeof parseNistJson> | undefined;
  const tool = vscode.workspace.getConfiguration('hwSecurity').get<string>('nist.eaNonIidPath')?.trim();
  if (tool && /\.(bin|dat|raw)$/i.test(file.fsPath)) {
    const out = join(context.globalStorageUri.fsPath, `ea-${Date.now()}.json`);
    await vscode.workspace.fs.createDirectory(context.globalStorageUri);
    try {
      const res = await runProcess(tool, ['-o', out, file.fsPath, String(result.wordSize)], { output });
      if (res.code === 0) {
        nist = parseNistJson(new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.file(out))));
      }
    } catch (err) {
      output.appendLine(`ea_non_iid failed: ${(err as Error).message}`);
    }
  }
  openWebview({
    context,
    viewType: 'hwSecurity.entropy',
    title: `Entropy — ${name.split('/').pop()}`,
    script: 'report.js',
    key: file.toString(),
    initialMessage: { type: 'entropy', name, result, nist, histogram: histogram(data, result.wordSize) },
    onMessage: (msg) => void handleExport(msg),
  });
  return result;
}

function histogram(data: Uint8Array, wordSize: number): number[] {
  const h = new Array<number>(1 << wordSize).fill(0);
  const mask = (1 << wordSize) - 1;
  for (const v of data) {
    h[v & mask]++;
  }
  return h;
}

export async function runRestartTest(context: vscode.ExtensionContext, uri?: vscode.Uri, opts: { wordSize?: number; hI?: number } = {}): Promise<RestartResult | undefined> {
  const file = await pickFile(uri, 'Restart data (1000 restarts × 1000 samples, row-major)', { Samples: ['bin', 'dat', 'raw'] });
  if (!file) {
    return undefined;
  }
  const wordSize = await pickWordSize(opts.wordSize);
  if (wordSize === undefined) {
    return undefined;
  }
  const hIText = opts.hI !== undefined ? String(opts.hI) : await vscode.window.showInputBox({ prompt: 'Initial entropy estimate H_I (bits per sample) to validate', validateInput: (v) => (Number(v) > 0 ? undefined : 'Enter a positive number') });
  if (!hIText) {
    return undefined;
  }
  const data = await vscode.workspace.fs.readFile(file);
  const rounds = vscode.workspace.getConfiguration('hwSecurity').get<number>('restart.simulationRounds', 200_000);
  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'SP 800-90B restart test', cancellable: true },
    async (_p, token) => {
      try {
        return await runWorker<RestartResult>(context, { kind: 'restart', data, wordSize, hI: Number(hIText), simulationRounds: rounds }, token);
      } catch (err) {
        void vscode.window.showErrorMessage(`Restart test failed: ${(err as Error).message}`);
        return undefined;
      }
    },
  );
  if (result) {
    openWebview({
      context,
      viewType: 'hwSecurity.restart',
      title: `Restart test — ${file.path.split('/').pop()}`,
      script: 'report.js',
      key: file.toString(),
      initialMessage: { type: 'restart', name: vscode.workspace.asRelativePath(file), result },
      onMessage: (msg) => void handleExport(msg),
    });
  }
  return result;
}

export async function analyzePuf(context: vscode.ExtensionContext, uri?: vscode.Uri) {
  const file = await pickFile(uri, 'PUF responses (CSV: device,read,response)', { CSV: ['csv', 'txt'] });
  if (!file) {
    return undefined;
  }
  let report;
  try {
    report = pufMetrics(parsePufCsv(new TextDecoder().decode(await vscode.workspace.fs.readFile(file))));
  } catch (err) {
    void vscode.window.showErrorMessage(`Cannot analyse PUF data: ${(err as Error).message}`);
    return undefined;
  }
  const cfg = vscode.workspace.getConfiguration('hwSecurity');
  const n = cfg.get<number>('puf.eccBlockBits', 255);
  const target = cfg.get<number>('puf.targetFailureRate', 1e-6);
  const t = requiredCorrection(n, report.bitErrorRate, target);
  const ecc = { n, target, t, failureAtT: t === undefined ? undefined : blockFailureProbability(n, t, report.bitErrorRate) };
  openWebview({
    context,
    viewType: 'hwSecurity.puf',
    title: `PUF — ${file.path.split('/').pop()}`,
    script: 'report.js',
    key: file.toString(),
    initialMessage: { type: 'puf', name: vscode.workspace.asRelativePath(file), report, ecc },
    onMessage: (msg) => void handleExport(msg),
  });
  return { report, ecc };
}

async function handleExport(msg: { type: string; format?: string; content?: string; suggestedName?: string }): Promise<void> {
  if (msg.type !== 'export' || !msg.content) {
    return;
  }
  const target = await vscode.window.showSaveDialog({
    defaultUri: vscode.workspace.workspaceFolders?.[0] ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, msg.suggestedName ?? 'report.md') : undefined,
    filters: msg.format === 'json' ? { JSON: ['json'] } : { Markdown: ['md'] },
  });
  if (target) {
    await vscode.workspace.fs.writeFile(target, new TextEncoder().encode(msg.content));
    void vscode.window.showInformationMessage(`Saved ${vscode.workspace.asRelativePath(target)}`);
  }
}
