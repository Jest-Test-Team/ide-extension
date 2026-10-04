import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import * as vscode from 'vscode';

/**
 * Resolves the Julia binary: our setting, then the julia-vscode extension's setting, then PATH,
 * then the default juliaup location.
 */
export function resolveJulia(): string | undefined {
  const own = vscode.workspace.getConfiguration('juliaProfiler').get<string>('executablePath')?.trim();
  if (own) {
    return own;
  }
  const juliaExt = vscode.workspace.getConfiguration('julia').get<string>('executablePath')?.trim();
  if (juliaExt) {
    return juliaExt;
  }
  const exe = process.platform === 'win32' ? 'julia.exe' : 'julia';
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    if (dir && existsSync(join(dir, exe))) {
      return join(dir, exe);
    }
  }
  const juliaup = join(homedir(), '.juliaup', 'bin', exe);
  return existsSync(juliaup) ? juliaup : undefined;
}
