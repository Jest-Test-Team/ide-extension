import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import type { Io } from './args';

/** Runs a program without a shell, streaming its output to stderr; resolves with exit code and stdout. */
export function run(
  cmd: string,
  args: string[],
  opts: { cwd: string; io: Io; quiet?: boolean; timeoutMs?: number; env?: Record<string, string> },
): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, shell: false, env: opts.env ? { ...process.env, ...opts.env } : process.env });
    let stdout = '';
    child.stdout.on('data', (b: Buffer) => {
      stdout += b.toString();
      if (!opts.quiet) {
        opts.io.err(b.toString());
      }
    });
    child.stderr.on('data', (b: Buffer) => !opts.quiet && opts.io.err(b.toString()));
    const timer = opts.timeoutMs ? setTimeout(() => child.kill(), opts.timeoutMs) : undefined;
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout });
    });
  });
}

/** Finds an executable on PATH (adds .exe/.cmd on Windows). */
export function which(name: string): string | undefined {
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    for (const ext of exts) {
      const p = join(dir, name + ext);
      if (dir && existsSync(p)) {
        return p;
      }
    }
  }
  return undefined;
}

/** Per-user cache directory for tool environments. */
export function cacheDir(tool: string): string {
  const base =
    process.platform === 'win32'
      ? (process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'))
      : (process.env.XDG_CACHE_HOME ?? join(homedir(), '.cache'));
  return join(base, tool);
}
