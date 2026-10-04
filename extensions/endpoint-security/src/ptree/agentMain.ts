// Entry point of dist/ptreeAgent.js: `node ptreeAgent.js` (stdio) or `--http <port> [--host h]`.
import { serveHttp, serveStdio } from './agent';

const i = process.argv.indexOf('--http');
if (i >= 0) {
  // Loopback by default; pass --host 0.0.0.0 to expose it (e.g. from a sandbox VM).
  const h = process.argv.indexOf('--host');
  serveHttp(Number(process.argv[i + 1] ?? 8765), h >= 0 ? process.argv[h + 1] : '127.0.0.1');
} else {
  serveStdio();
}
