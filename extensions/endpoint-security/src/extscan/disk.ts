import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative } from 'node:path';
import type { ExtInfo } from './manifest';

interface ProfileEntry {
  identifier?: { id?: string };
  relativeLocation?: string;
  location?: { path?: string } | string;
  metadata?: { source?: string };
}

/**
 * Install sources from the profile's `extensions.json` (written by VS Code next to the installed
 * extensions), keyed by install folder name. Missing or unreadable files yield an empty map.
 */
export function installSources(extensionsDir: string, cache: Map<string, Map<string, string>>): Map<string, string> {
  let map = cache.get(extensionsDir);
  if (map) {
    return map;
  }
  map = new Map();
  try {
    const entries = JSON.parse(readFileSync(join(extensionsDir, 'extensions.json'), 'utf8')) as ProfileEntry[];
    for (const e of entries) {
      const loc = typeof e.location === 'string' ? e.location : e.location?.path;
      const folder = e.relativeLocation ?? (loc ? basename(loc) : undefined);
      if (folder && e.metadata?.source) {
        map.set(folder, e.metadata.source);
      }
    }
  } catch {
    // Not a profile extensions folder (built-in, development host) or an older layout.
  }
  cache.set(extensionsDir, map);
  return map;
}

export function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return !!rel && !rel.startsWith('..') && !isAbsolute(rel);
}

function readExtension(path: string, builtin: boolean, source?: string): ExtInfo | undefined {
  let text: string;
  let pkg: Record<string, unknown>;
  try {
    text = readFileSync(join(path, 'package.json'), 'utf8');
    pkg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  if (typeof pkg.publisher !== 'string' || typeof pkg.name !== 'string') {
    return undefined;
  }
  return {
    id: `${pkg.publisher}.${pkg.name}`,
    version: String(pkg.version ?? '0.0.0'),
    displayName: typeof pkg.displayName === 'string' ? pkg.displayName : undefined,
    path,
    packageJSON: pkg,
    packageJsonText: text,
    builtin,
    source,
  };
}

/**
 * Folders VS Code considers installed: those listed in `extensions.json`, else every folder not
 * marked in `.obsolete` (old versions awaiting cleanup). Undefined = no metadata, take all.
 */
function activeFolders(dir: string): Set<string> | undefined {
  try {
    const entries = JSON.parse(readFileSync(join(dir, 'extensions.json'), 'utf8')) as ProfileEntry[];
    const names = entries
      .map((e) => e.relativeLocation ?? (typeof e.location === 'string' ? e.location : e.location?.path))
      .filter((x): x is string => !!x)
      .map((x) => basename(x));
    if (names.length) {
      return new Set(names);
    }
  } catch {
    // fall through to .obsolete
  }
  try {
    const obsolete = JSON.parse(readFileSync(join(dir, '.obsolete'), 'utf8')) as Record<string, boolean>;
    return new Set(readdirSync(dir).filter((n) => !obsolete[n]));
  } catch {
    return undefined;
  }
}

/**
 * Extensions installed in an extensions folder (e.g. ~/.vscode/extensions), read from disk without
 * VS Code. Each sub-folder with a package.json that has `publisher` and `name` is one extension.
 */
export function readExtensionsDir(dir: string, opts: { builtin?: boolean } = {}): ExtInfo[] {
  if (!existsSync(dir)) {
    return [];
  }
  // A single extension's own folder (it has a package.json with publisher and name).
  const single = readExtension(dir, opts.builtin ?? false, installSources(dirname(dir), new Map()).get(basename(dir)));
  if (single) {
    return [single];
  }
  const cache = new Map<string, Map<string, string>>();
  const active = activeFolders(dir);
  const out: ExtInfo[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.') || (active && !active.has(entry.name))) {
      continue;
    }
    const ext = readExtension(join(dir, entry.name), opts.builtin ?? false, installSources(dir, cache).get(entry.name));
    if (ext) {
      out.push(ext);
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}
