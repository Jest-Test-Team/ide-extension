import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import * as vscode from 'vscode';

/** A command-line tool bundled in an extension: shim name → script under the extension folder. */
export interface CliSpec {
  name: string;
  /** Path relative to the extension root, e.g. `dist/cli/jest-hw.js`. */
  script: string;
}

const MARKER = 'jest-cli-shim';
const isWin = process.platform === 'win32';

/** Default shim folder: ~/.local/bin (POSIX) or %LOCALAPPDATA%\Programs\jest-cli (Windows). */
export function defaultCliDir(): string {
  return isWin ? join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'Programs', 'jest-cli') : join(homedir(), '.local', 'bin');
}

const shimPath = (dir: string, name: string) => join(dir, isWin ? `${name}.cmd` : name);

/**
 * Shim content. It prefers `node` on PATH and otherwise runs the script with the editor's own
 * runtime (ELECTRON_RUN_AS_NODE), so no separate Node.js install is needed.
 */
export function shimContent(extensionId: string, script: string, runtime: string, windows = isWin): string {
  if (windows) {
    return [
      '@echo off',
      `rem ${MARKER}: ${extensionId}`,
      'where node >nul 2>nul',
      'if %errorlevel%==0 (',
      `  node "${script}" %*`,
      ') else (',
      '  set ELECTRON_RUN_AS_NODE=1',
      `  "${runtime}" "${script}" %*`,
      ')',
      '',
    ].join('\r\n');
  }
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return [
    '#!/bin/sh',
    `# ${MARKER}: ${extensionId}`,
    `script=${q(script)}`,
    'if command -v node >/dev/null 2>&1; then exec node "$script" "$@"; fi',
    `ELECTRON_RUN_AS_NODE=1 exec ${q(runtime)} "$script" "$@"`,
    '',
  ].join('\n');
}

const isOurs = (path: string) => existsSync(path) && readFileSync(path, 'utf8').includes(MARKER);

function writeShim(path: string, content: string): void {
  writeFileSync(path, content);
  if (!isWin) {
    chmodSync(path, 0o755);
  }
}

export function onPath(dir: string): boolean {
  const norm = (p: string) => p.replace(/[\\/]+$/, '').toLowerCase();
  return (process.env.PATH ?? '').split(delimiter).some((p) => norm(p) === norm(dir));
}

/** Installs shims; refuses to overwrite files that are not ours. Returns the written paths. */
export function installCli(context: vscode.ExtensionContext, specs: CliSpec[], dir = defaultCliDir()): string[] {
  mkdirSync(dir, { recursive: true });
  return specs.map((s) => {
    const path = shimPath(dir, s.name);
    if (existsSync(path) && !isOurs(path)) {
      throw new Error(`${path} exists and was not created by this extension; remove it first.`);
    }
    writeShim(path, shimContent(context.extension.id, join(context.extensionPath, s.script), process.execPath));
    return path;
  });
}

export function uninstallCli(specs: CliSpec[], dir = defaultCliDir()): string[] {
  return specs
    .map((s) => shimPath(dir, s.name))
    .filter((p) => isOurs(p))
    .map((p) => {
      unlinkSync(p);
      return p;
    });
}

/** After an extension update the install folder changes; silently repoint our existing shims. */
export function refreshCli(context: vscode.ExtensionContext, specs: CliSpec[], dir = defaultCliDir()): void {
  for (const s of specs) {
    const path = shimPath(dir, s.name);
    if (!isOurs(path) || !readFileSync(path, 'utf8').includes(`${MARKER}: ${context.extension.id}`)) {
      continue;
    }
    const want = shimContent(context.extension.id, join(context.extensionPath, s.script), process.execPath);
    if (readFileSync(path, 'utf8') !== want) {
      writeShim(path, want);
    }
  }
}

/**
 * Registers `<prefix>.installCli` / `<prefix>.uninstallCli`. Both accept `{ dir }` (used by tests)
 * and return the affected paths.
 */
export function registerCliCommands(context: vscode.ExtensionContext, prefix: string, specs: CliSpec[]): void {
  try {
    refreshCli(context, specs);
  } catch {
    // Never block activation on the shim folder.
  }
  const names = specs.map((s) => s.name).join(', ');
  context.subscriptions.push(
    vscode.commands.registerCommand(`${prefix}.installCli`, async (opts?: { dir?: string }) => {
      const dir = opts?.dir ?? defaultCliDir();
      let paths: string[];
      try {
        paths = installCli(context, specs, dir);
      } catch (err) {
        void vscode.window.showErrorMessage((err as Error).message);
        return [];
      }
      if (!opts?.dir) {
        if (onPath(dir)) {
          void vscode.window.showInformationMessage(
            `Installed ${names} in ${dir}. Open a new terminal (or run "rehash" in an open zsh) and run "${specs[0].name} --help".`,
          );
        } else {
          const line = isWin ? `setx PATH "%PATH%;${dir}"` : `export PATH="${dir.replace(homedir(), '$HOME')}:$PATH"`;
          const pick = await vscode.window.showWarningMessage(
            `Installed ${names} in ${dir}, which is not on your PATH. Add it${isWin ? '' : ' to your shell profile (~/.zshrc, ~/.bashrc), then open a new terminal'}: ${line}`,
            'Copy Command',
          );
          if (pick) {
            await vscode.env.clipboard.writeText(line);
          }
        }
      }
      return paths;
    }),
    vscode.commands.registerCommand(`${prefix}.uninstallCli`, (opts?: { dir?: string }) => {
      const removed = uninstallCli(specs, opts?.dir ?? defaultCliDir());
      if (!opts?.dir) {
        void vscode.window.showInformationMessage(removed.length ? `Removed ${removed.join(', ')}` : `No ${names} command installed by this extension.`);
      }
      return removed;
    }),
  );
}
