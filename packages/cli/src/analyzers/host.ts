import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { cacheDir } from '../lib/proc';
import {
  ENGINE_BINARIES,
  parseMessage,
  PROTOCOL_VERSION,
  type AnalyzeRequest,
  type AnalyzerInfo,
  type AnalyzerMessage,
  type EngineId,
} from './protocol';

export interface AnalyzerHandle {
  engine: EngineId;
  path: string;
  info: AnalyzerInfo;
}

export interface AnalyzerProblem {
  engine: EngineId;
  reason: string;
}

/** Folders searched for analyzers, in order: $JEST_ANALYZERS_DIR, the user cache, then PATH. */
export function analyzerSearchPath(): string[] {
  return [
    ...(process.env.JEST_ANALYZERS_DIR ? process.env.JEST_ANALYZERS_DIR.split(delimiter) : []),
    join(cacheDir('jest-security'), 'analyzers'),
    ...(process.env.PATH ?? '').split(delimiter),
  ].filter(Boolean);
}

function findBinary(name: string): string | undefined {
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : [''];
  for (const dir of analyzerSearchPath()) {
    for (const ext of exts) {
      const p = join(dir, name + ext);
      if (existsSync(p)) {
        return p;
      }
    }
  }
  return undefined;
}

function runCapture(path: string, args: string[], input: string | undefined, timeoutMs: number, onLine?: (line: string) => void): Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }> {
  return new Promise((resolve, reject) => {
    const windowsScript = process.platform === 'win32' && /\.(cmd|bat)$/i.test(path);
    const child = spawn(path, args, { shell: windowsScript, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let pending = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.on('data', (b: Buffer) => {
      const s = b.toString();
      stdout += s;
      if (onLine) {
        pending += s;
        let i: number;
        while ((i = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, i).trim();
          pending = pending.slice(i + 1);
          if (line) {
            onLine(line);
          }
        }
      }
    });
    child.stderr.on('data', (b: Buffer) => (stderr += b.toString()));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (onLine && pending.trim()) {
        onLine(pending.trim());
      }
      resolve({ code, stdout, stderr, timedOut });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(input ?? '');
  });
}

/**
 * Locates the analyzers and asks each for its info. Missing or broken analyzers are reported in
 * `problems` (never thrown), so a scan always proceeds with whatever is available.
 */
export async function discoverAnalyzers(engines: readonly EngineId[] = ['rs', 'go', 'py', 'jl'], timeoutMs = 15_000): Promise<{ found: AnalyzerHandle[]; problems: AnalyzerProblem[] }> {
  const found: AnalyzerHandle[] = [];
  const problems: AnalyzerProblem[] = [];
  for (const engine of engines) {
    const path = findBinary(ENGINE_BINARIES[engine]);
    if (!path) {
      problems.push({ engine, reason: `${ENGINE_BINARIES[engine]} not installed` });
      continue;
    }
    try {
      const res = await runCapture(path, ['info'], undefined, timeoutMs);
      const info = JSON.parse(res.stdout.trim()) as AnalyzerInfo;
      if (res.code !== 0 || info.protocol !== PROTOCOL_VERSION || !Array.isArray(info.vectors)) {
        problems.push({ engine, reason: `${path}: unsupported analyzer (protocol ${info.protocol ?? '?'}, exit ${res.code})` });
        continue;
      }
      found.push({ engine, path, info });
    } catch (err) {
      problems.push({ engine, reason: `${path}: ${(err as Error).message}` });
    }
  }
  return { found, problems };
}

export interface AnalyzerRun {
  engine: EngineId;
  messages: AnalyzerMessage[];
  ran: string[];
  skipped: { id: string; reason: string }[];
  errors: string[];
  timedOut: boolean;
}

/** Runs one analyzer over the request; malformed lines and failures become `errors`. */
export async function runAnalyzer(handle: AnalyzerHandle, request: AnalyzeRequest, timeoutMs: number, onProgress?: (m: AnalyzerMessage) => void): Promise<AnalyzerRun> {
  const messages: AnalyzerMessage[] = [];
  const errors: string[] = [];
  let done: Extract<AnalyzerMessage, { type: 'done' }> | undefined;
  const res = await runCapture(handle.path, ['analyze'], JSON.stringify(request), timeoutMs, (line) => {
    const m = parseMessage(line);
    if (!m) {
      errors.push(`malformed output: ${line.slice(0, 120)}`);
      return;
    }
    if (m.type === 'done') {
      done = m;
    } else if (m.type === 'error') {
      errors.push(m.ext ? `${m.ext}: ${m.message}` : m.message);
    } else if (m.type === 'progress') {
      onProgress?.(m);
    } else {
      messages.push(m);
    }
  }).catch((err: Error) => {
    errors.push(err.message);
    return { code: -1, stdout: '', stderr: '', timedOut: false };
  });
  if (res.timedOut) {
    errors.push(`timed out after ${Math.round(timeoutMs / 1000)} s`);
  } else if (res.code !== 0 && res.code !== -1) {
    errors.push(`exited with code ${res.code}${res.stderr ? `: ${res.stderr.trim().split('\n').slice(-3).join(' | ')}` : ''}`);
  }
  if (!done && !errors.length) {
    errors.push('ended without a done message');
  }
  return { engine: handle.engine, messages, ran: done?.ran ?? [], skipped: done?.skipped ?? [], errors, timedOut: res.timedOut };
}
