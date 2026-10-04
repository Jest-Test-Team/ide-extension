import { languageIdForPath } from '@ide-ext/core';
import { closeSync, existsSync, openSync, readSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export const DEFAULT_IGNORE = ['node_modules', '.git', '.hg', '.svn', 'build', 'dist', 'out', 'target', 'vendor', '.pio', 'managed_components', '.venv', 'venv', '__pycache__', '.vscode-test', 'coverage'];
const MAX_BYTES = 5 * 1024 * 1024;

export interface SourceFile {
  path: string;
  /** Path relative to the working directory, forward slashes (used in reports). */
  rel: string;
  languageId: string;
}

function looksBinary(path: string): boolean {
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(4096);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).includes(0);
  } finally {
    closeSync(fd);
  }
}

/**
 * Expands files and directories (recursively) into source files. `accept` filters by language id
 * and path; directories in DEFAULT_IGNORE and hidden folders are skipped unless named explicitly.
 */
export function collectFiles(inputs: readonly string[], cwd: string, accept: (languageId: string, path: string) => boolean, ignore = DEFAULT_IGNORE): SourceFile[] {
  const out = new Map<string, SourceFile>();
  const add = (path: string) => {
    const languageId = languageIdForPath(path);
    if (!accept(languageId, path)) {
      return;
    }
    const st = statSync(path);
    if (st.size > MAX_BYTES || looksBinary(path)) {
      return;
    }
    out.set(path, { path, rel: relative(cwd, path).replace(/\\/g, '/') || path, languageId });
  };
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (!ignore.includes(e.name) && !e.name.startsWith('.')) {
          walk(p);
        }
      } else if (e.isFile()) {
        add(p);
      }
    }
  };
  for (const input of inputs.length ? inputs : ['.']) {
    const abs = resolve(cwd, input);
    if (!existsSync(abs)) {
      throw new Error(`no such file or directory: ${input}`);
    }
    if (statSync(abs).isDirectory()) {
      walk(abs);
    } else {
      add(abs);
    }
  }
  return [...out.values()].sort((a, b) => a.rel.localeCompare(b.rel));
}
