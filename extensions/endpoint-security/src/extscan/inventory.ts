import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import * as vscode from 'vscode';
import { installSources, isInside } from './disk';
import type { ExtInfo } from './manifest';

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
