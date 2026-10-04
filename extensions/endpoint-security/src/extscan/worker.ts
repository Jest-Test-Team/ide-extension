// worker_threads entry: scans installed extensions' code off the extension host thread.
// One worker serves a whole scan run; requests are handled one at a time.
import { RuleEngine, TreeSitterHost } from '@ide-ext/core';
import { join } from 'node:path';
import { parentPort } from 'node:worker_threads';
import { loadCodeRules, scanExtensionCode, type CodeScanOptions, type CodeScanResult } from './codeScan';

export type ScanWorkerRequest = { type: 'scan'; seq: number; dir: string; pkg: Record<string, unknown>; opts: CodeScanOptions };
export type ScanWorkerResponse = { type: 'result'; seq: number; result: CodeScanResult } | { type: 'error'; seq: number; message: string };

// dist/extScanWorker.js sits next to dist/grammars and dist/extscan.
const host = new TreeSitterHost(join(__dirname, 'grammars'));
const engine = new RuleEngine(host, loadCodeRules(join(__dirname, 'extscan')).rules);

let queue = Promise.resolve();
parentPort?.on('message', (req: ScanWorkerRequest) => {
  queue = queue.then(async () => {
    try {
      const result = await scanExtensionCode(engine, host, req.dir, req.pkg, req.opts);
      parentPort!.postMessage({ type: 'result', seq: req.seq, result } satisfies ScanWorkerResponse);
    } catch (err) {
      parentPort!.postMessage({ type: 'error', seq: req.seq, message: (err as Error).message } satisfies ScanWorkerResponse);
    }
  });
});
