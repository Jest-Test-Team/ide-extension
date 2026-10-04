import { dirname } from 'node:path';

/** Marker written into every shim the extensions create; files without it are never touched. */
export const SHIM_MARKER = 'jest-cli-shim';

/**
 * Shim content. It prefers `node` on PATH and otherwise runs the script with the editor's own
 * runtime (ELECTRON_RUN_AS_NODE), so no separate Node.js install is needed.
 */
export function shimContent(extensionId: string, script: string, runtime: string, windows = process.platform === 'win32'): string {
  if (windows) {
    return [
      '@echo off',
      `rem ${SHIM_MARKER}: ${extensionId}`,
      `rem script=${script}`,
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
    `# ${SHIM_MARKER}: ${extensionId}`,
    `script=${q(script)}`,
    'if command -v node >/dev/null 2>&1; then exec node "$script" "$@"; fi',
    `ELECTRON_RUN_AS_NODE=1 exec ${q(runtime)} "$script" "$@"`,
    '',
  ].join('\n');
}

/** Extension id and script path recorded in a shim, if it is one of ours. */
export function parseShim(content: string): { extensionId: string; script?: string } | undefined {
  const id = new RegExp(`${SHIM_MARKER}: (\\S+)`).exec(content)?.[1];
  if (!id) {
    return undefined;
  }
  const posix = /^script='((?:[^']|'\\'')*)'$/m.exec(content)?.[1]?.replace(/'\\''/g, "'");
  const win = /^rem script=(.*)$/m.exec(content)?.[1]?.trim();
  return { extensionId: id, script: posix ?? win };
}

/**
 * Whether an activating extension should repoint an existing shim to itself. Only for the same
 * extension, and only when the shim's target is gone (old version removed) or lives in the same
 * extensions folder (an update). A shim made by another editor, or a development copy, is left
 * alone while its target exists.
 */
export function shouldRefreshShim(
  content: string,
  extensionId: string,
  newScript: string,
  extensionsRootOf: (script: string) => string,
  exists: (path: string) => boolean,
): boolean {
  const shim = parseShim(content);
  if (!shim || shim.extensionId !== extensionId) {
    return false;
  }
  if (!shim.script) {
    return true; // older shim format without a recorded path
  }
  if (shim.script === newScript) {
    return false;
  }
  return !exists(shim.script) || extensionsRootOf(shim.script) === extensionsRootOf(newScript);
}

/** `<root>/<publisher.name-version>/dist/cli/x.js` → `<root>`. */
export function extensionsRootOf(script: string, depth = 3): string {
  let d = dirname(script);
  for (let i = 0; i < depth; i++) {
    d = dirname(d);
  }
  return d;
}
