import { languageIdForPath } from '@ide-ext/core';
import { closeSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from 'node:fs';
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

export const IGNORE_FILE = '.jestignore';

function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * gitignore-style matcher: blank lines and `#` comments are skipped; a pattern without `/` matches
 * any file or folder name; a pattern with `/` is relative to the working directory; `**` spans
 * folders; a match on a folder ignores everything below it.
 */
export function ignoreMatcher(patterns: readonly string[]): (rel: string) => boolean {
  const rules = patterns
    .map((p) => p.trim())
    .filter((p) => p && !p.startsWith('#'))
    .map((p) => p.replace(/\/+$/, ''))
    .map((p) => (p.includes('/') ? { anchored: true, re: globToRegExp(p.replace(/^\//, '')) } : { anchored: false, re: globToRegExp(p) }));
  return (rel: string) => {
    const parts = rel.split('/');
    return rules.some(({ anchored, re }) =>
      anchored ? parts.some((_, i) => re.test(parts.slice(0, i + 1).join('/'))) : parts.some((seg) => re.test(seg)),
    );
  };
}

/** Patterns from `--ignore` plus the working directory's .jestignore (unless disabled). */
export function ignorePatterns(cwd: string, extra: readonly string[] = [], useFile = true): string[] {
  const file = join(cwd, IGNORE_FILE);
  return [...(useFile && existsSync(file) ? readFileSync(file, 'utf8').split(/\r?\n/) : []), ...extra];
}

/**
 * Expands files and directories (recursively) into source files. `accept` filters by language id
 * and path; directories in DEFAULT_IGNORE and hidden folders are skipped unless named explicitly.
 */
export function collectFiles(
  inputs: readonly string[],
  cwd: string,
  accept: (languageId: string, path: string) => boolean,
  ignore = DEFAULT_IGNORE,
  patterns: readonly string[] = [],
): SourceFile[] {
  const out = new Map<string, SourceFile>();
  const matchers = patterns.map((p) => ignoreMatcher([p]));
  const relOf = (p: string) => relative(cwd, p).replace(/\\/g, '/');
  // Paths named explicitly are scanned even when an ignore pattern covers them: for each input,
  // only the patterns that do not match the input itself apply below it.
  let active = matchers;
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
      const rel = relOf(p);
      if (active.some((m) => m(rel))) {
        continue;
      }
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
    active = matchers.filter((m) => !m(relOf(abs)));
    if (statSync(abs).isDirectory()) {
      walk(abs);
    } else {
      add(abs);
    }
  }
  return [...out.values()].sort((a, b) => a.rel.localeCompare(b.rel));
}
