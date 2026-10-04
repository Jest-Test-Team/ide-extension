import { spawn } from 'node:child_process';
import type * as vscode from 'vscode';

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  token?: vscode.CancellationToken;
  timeoutMs?: number;
  /** Streams stdout/stderr lines here as they arrive. */
  output?: vscode.OutputChannel;
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  cancelled: boolean;
  timedOut: boolean;
}

/** Spawns a process without a shell and collects its output; kills it on cancel/timeout. */
export function runProcess(command: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    opts.output?.appendLine(`$ ${[command, ...args].map(quote).join(' ')}`);
    const child = spawn(command, args, { cwd: opts.cwd, env: opts.env ?? process.env, shell: false });
    let stdout = '';
    let stderr = '';
    let cancelled = false;
    let timedOut = false;
    child.stdout.on('data', (b: Buffer) => {
      stdout += b.toString();
      opts.output?.append(b.toString());
    });
    child.stderr.on('data', (b: Buffer) => {
      stderr += b.toString();
      opts.output?.append(b.toString());
    });
    const kill = () => {
      if (child.exitCode === null) {
        child.kill();
      }
    };
    const sub = opts.token?.onCancellationRequested(() => {
      cancelled = true;
      kill();
    });
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          kill();
        }, opts.timeoutMs)
      : undefined;
    child.on('error', (err) => {
      clearTimeout(timer);
      sub?.dispose();
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      sub?.dispose();
      opts.output?.appendLine(`[exit ${code}${cancelled ? ', cancelled' : ''}${timedOut ? ', timed out' : ''}]`);
      resolve({ code, stdout, stderr, cancelled, timedOut });
    });
  });
}

function quote(s: string): string {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}
