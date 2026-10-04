import { readFileSync } from 'node:fs';
import { basename, dirname, join, relative, isAbsolute } from 'node:path';
import * as vscode from 'vscode';
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
function installSources(extensionsDir: string, cache: Map<string, Map<string, string>>): Map<string, string> {
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

function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return !!rel && !rel.startsWith('..') && !isAbsolute(rel);
}

/** Every installed extension VS Code knows about, as plain data for the scanner. */
export function inventory(): ExtInfo[] {
  const cache = new Map<string, Map<string, string>>();
  return vscode.extensions.all.map((ext) => {
    const pkg = ext.packageJSON as Record<string, unknown>;
    let text: string | undefined;
    try {
      text = readFileSync(join(ext.extensionPath, 'package.json'), 'utf8');
    } catch {
      text = undefined;
    }
    return {
      id: ext.id,
      version: String(pkg.version ?? '0.0.0'),
      displayName: typeof pkg.displayName === 'string' ? pkg.displayName : undefined,
      path: ext.extensionPath,
      packageJSON: pkg,
      packageJsonText: text,
      builtin: isInside(ext.extensionPath, vscode.env.appRoot),
      source: installSources(dirname(ext.extensionPath), cache).get(basename(ext.extensionPath)),
    };
  });
}
