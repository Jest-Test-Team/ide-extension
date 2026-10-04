// worker_threads entry: runs the CPU-heavy SP 800-90B computations off the extension host thread.
import { parentPort } from 'node:worker_threads';
import { restartTest } from './restart';
import { nonIidAssessment } from './sp80090b';

export type WorkerRequest =
  | { kind: 'nonIid'; data: Uint8Array; wordSize: number; initialEntropy: boolean; allBits: boolean }
  | { kind: 'restart'; data: Uint8Array; wordSize: number; hI: number; simulationRounds: number };

parentPort?.on('message', (req: WorkerRequest) => {
  try {
    if (req.kind === 'nonIid') {
      const result = nonIidAssessment(req.data, {
        wordSize: req.wordSize,
        initialEntropy: req.initialEntropy,
        allBits: req.allBits,
        onProgress: (id) => parentPort!.postMessage({ type: 'progress', id }),
      });
      parentPort!.postMessage({ type: 'done', result });
    } else {
      parentPort!.postMessage({
        type: 'done',
        result: restartTest(req.data, req.hI, { wordSize: req.wordSize, simulationRounds: req.simulationRounds }),
      });
    }
  } catch (err) {
    parentPort!.postMessage({ type: 'error', message: (err as Error).message });
  }
});
