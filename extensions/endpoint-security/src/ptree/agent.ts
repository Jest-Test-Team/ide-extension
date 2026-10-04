/**
 * Local simulation agent: JSON-RPC 2.0, one message per line on stdin/stdout. With `--http <port>`
 * it serves the same protocol over HTTP POST on 127.0.0.1 (`--host` to change, e.g. in a sandbox VM). The agent only replays
 * scenario data; it never executes binaries or touches the system.
 */
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { parseRules, parseScenario, ScenarioError, simulate } from './engine';

export const AGENT_VERSION = '1.0.0';

interface Request {
  jsonrpc: '2.0';
  id: number | string;
  method: string;
  params?: { scenario?: string; rules?: string[] };
}

export function handle(req: Request): object {
  const reply = (body: object) => ({ jsonrpc: '2.0', id: req.id, ...body });
  try {
    switch (req.method) {
      case 'ping':
        return reply({ result: { version: AGENT_VERSION, pid: process.pid } });
      case 'simulate': {
        const rules = (req.params?.rules ?? []).flatMap((t) => parseRules(t));
        return reply({ result: simulate(parseScenario(req.params?.scenario ?? '', rules)) });
      }
      default:
        return reply({ error: { code: -32601, message: `Unknown method ${req.method}` } });
    }
  } catch (err) {
    const line = err instanceof ScenarioError ? err.line : undefined;
    return reply({ error: { code: -32000, message: (err as Error).message, data: { line } } });
  }
}

export function serveStdio(): void {
  const rl = createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (!line.trim()) {
      return;
    }
    let req: Request;
    try {
      req = JSON.parse(line) as Request;
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
      return;
    }
    process.stdout.write(JSON.stringify(handle(req)) + '\n');
  });
}

export function serveHttp(port: number, host: string): void {
  createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }
    let body = '';
    req.on('data', (c: Buffer) => {
      body += c.toString();
      if (body.length > 10_000_000) {
        req.destroy();
      }
    });
    req.on('end', () => {
      let out: object;
      try {
        out = handle(JSON.parse(body) as Request);
      } catch {
        out = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out));
    });
  }).listen(port, host, () => process.stderr.write(`ptree agent ${AGENT_VERSION} listening on ${host}:${port}\n`));
}
