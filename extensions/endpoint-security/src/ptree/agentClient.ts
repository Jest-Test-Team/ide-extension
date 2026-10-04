import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { SimulationResult } from './engine';

export class AgentError extends Error {
  constructor(
    message: string,
    readonly line?: number,
  ) {
    super(message);
  }
}

interface RpcResponse {
  id: number;
  result?: unknown;
  error?: { message: string; data?: { line?: number } };
}

/** Talks to the simulation agent: a local child process over stdio, or a remote one over HTTP. */
export class AgentClient {
  private child: ChildProcessWithoutNullStreams | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, (r: RpcResponse) => void>();

  constructor(
    private readonly agentScript: string,
    private readonly remoteUrl: () => string | undefined,
  ) {}

  private start(): ChildProcessWithoutNullStreams {
    if (this.child && this.child.exitCode === null) {
      return this.child;
    }
    // process.execPath is Electron inside VS Code; ELECTRON_RUN_AS_NODE makes it behave as node.
    const child = spawn(process.execPath, [this.agentScript], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, stdio: 'pipe' });
    createInterface({ input: child.stdout }).on('line', (line) => {
      const msg = JSON.parse(line) as RpcResponse;
      this.pending.get(msg.id)?.(msg);
      this.pending.delete(msg.id);
    });
    child.on('exit', () => {
      for (const resolve of this.pending.values()) {
        resolve({ id: -1, error: { message: 'Simulation agent exited unexpectedly.' } });
      }
      this.pending.clear();
    });
    this.child = child;
    return child;
  }

  async call<T>(method: string, params?: object): Promise<T> {
    const id = this.nextId++;
    const request = { jsonrpc: '2.0', id, method, params };
    let res: RpcResponse;
    const url = this.remoteUrl()?.trim();
    if (url) {
      const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) });
      res = (await r.json()) as RpcResponse;
    } else {
      const child = this.start();
      res = await new Promise<RpcResponse>((resolve) => {
        this.pending.set(id, resolve);
        child.stdin.write(JSON.stringify(request) + '\n');
      });
    }
    if (res.error) {
      throw new AgentError(res.error.message, res.error.data?.line);
    }
    return res.result as T;
  }

  simulate(scenario: string, rules: string[]): Promise<SimulationResult> {
    return this.call<SimulationResult>('simulate', { scenario, rules });
  }

  dispose(): void {
    this.child?.kill();
  }
}
