import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { assetDir } from '../lib/assets';
import { which } from '../lib/proc';
import { createSandbox, readEvents, sandboxEnv, type RunOptions, type RunResult } from './run';

/** The VS Code CLI (not Cursor or another fork that also installs a `code` command). */
export function findVsCode(): string | undefined {
  const candidates = [
    process.env.JEST_AUDIT_CODE,
    process.platform === 'darwin' ? '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code' : undefined,
    process.platform === 'darwin' ? join(homedir(), 'Applications/Visual Studio Code.app/Contents/Resources/app/bin/code') : undefined,
    process.platform === 'win32' ? join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd') : undefined,
    process.platform === 'win32' ? join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Microsoft VS Code', 'bin', 'code.cmd') : undefined,
    '/usr/share/code/bin/code',
    '/snap/bin/code',
    which('code'),
  ];
  for (const c of candidates) {
    if (!c || !existsSync(c)) {
      continue;
    }
    let real = c;
    try {
      real = realpathSync(c);
    } catch {
      // keep c
    }
    if (!/cursor|windsurf|vscodium|codium/i.test(real)) {
      return c;
    }
  }
  return undefined;
}

/**
 * Rewrites the copied extension so its entry point loads the audit agent first. This works whether
 * or not the editor honours NODE_OPTIONS for the extension host.
 */
export function injectAgent(extCopy: string): string {
  const pkgPath = join(extCopy, 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
  if (typeof pkg.main !== 'string') {
    throw new Error('the extension has no `main` entry; nothing runs in the extension host');
  }
  const shim = '__jest_audit_main.js';
  const agent = join(assetDir('runtime'), 'audit-agent.cjs');
  writeFileSync(join(extCopy, shim), `require(${JSON.stringify(agent)});\nmodule.exports = require(${JSON.stringify(`./${pkg.main.replace(/^\.\//, '')}`)});\n`);
  pkg.main = `./${shim}`;
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  return shim;
}

/** Kills every process whose command line mentions the sandbox (the editor instance we started). */
function killSandboxProcesses(root: string): void {
  try {
    if (process.platform === 'win32') {
      execFileSync('powershell', ['-NoProfile', '-Command', `Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*${root.replace(/'/g, "''")}*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`]);
      return;
    }
    const out = execFileSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8' });
    for (const line of out.split('\n')) {
      const m = /^\s*(\d+)\s+(.*)$/.exec(line);
      if (m && m[2].includes(root) && Number(m[1]) !== process.pid) {
        try {
          process.kill(Number(m[1]), 'SIGKILL');
        } catch {
          // gone
        }
      }
    }
  } catch {
    // best effort
  }
}

/**
 * Runs the extension in a real, separate VS Code instance (own user-data and extensions folders,
 * decoy HOME) with the agent injected, then closes that instance. Activation follows the
 * extension's own activation events.
 */
export async function runVsCode(extDir: string, opts: RunOptions, code = findVsCode()): Promise<RunResult> {
  if (!code) {
    throw new Error('VS Code not found; install it or set JEST_AUDIT_CODE to its `code` CLI');
  }
  const sb = createSandbox(extDir);
  injectAgent(sb.ext);
  const user = join(sb.root, 'user-data');
  const exts = join(sb.root, 'extensions');
  mkdirSync(user, { recursive: true });
  mkdirSync(exts, { recursive: true });
  const env = { ...sandboxEnv(sb, opts), NODE_OPTIONS: `--require ${join(assetDir('runtime'), 'audit-agent.cjs')}`, VSCODE_CLI: '1' };
  const args = [
    '--user-data-dir',
    user,
    '--extensions-dir',
    exts,
    '--extensionDevelopmentPath',
    sb.ext,
    '--disable-workspace-trust',
    '--disable-gpu',
    '--skip-welcome',
    '--skip-release-notes',
    '--new-window',
    sb.workspace,
  ];
  const child = spawn(code, args, { env, stdio: 'ignore', shell: process.platform === 'win32', detached: process.platform !== 'win32' });
  child.unref();
  await new Promise((r) => setTimeout(r, (opts.duration + 10) * 1000));
  killSandboxProcesses(sb.root);
  await new Promise((r) => setTimeout(r, 1000));
  return { sandbox: sb, events: readEvents(sb.log), exitCode: 0, timedOut: false, stderr: '', kernelSkipped: 'not available in --mode vscode' };
}
