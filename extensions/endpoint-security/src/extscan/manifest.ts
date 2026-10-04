import { LineIndex, type Range } from '@ide-ext/core';
import type { RemovedEntry } from './knownBad';
import { removalVerdict } from './knownBad';
import { signal, SIGNALS, type Located, type Signal } from './signals';
import { findTyposquat } from './typosquat';

/** What the scanner knows about one installed extension (no VS Code types, so it is testable). */
export interface ExtInfo {
  /** `publisher.name`, as reported by VS Code. */
  id: string;
  version: string;
  displayName?: string;
  /** Install folder. */
  path: string;
  packageJSON: Record<string, unknown>;
  /** Raw `package.json` text, for locating keys; optional. */
  packageJsonText?: string;
  builtin: boolean;
  /** Install source from VS Code's extension metadata (`gallery`, `vsix`, `resource`), when known. */
  source?: string;
}

export interface ManifestOptions {
  trustedPublishers: ReadonlySet<string>;
  popular: readonly string[];
  knownBad: ReadonlyMap<string, RemovedEntry>;
}

const ZERO: Range = { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };

/** Locates `"key"` (and optionally a value after it) in package.json for SARIF / jump-to. */
function locate(ext: ExtInfo, id: string, message: string, key?: string, value?: string): Located[] {
  const file = `${ext.path.replace(/[\\/]$/, '')}/package.json`;
  let range = ZERO;
  if (ext.packageJsonText && key) {
    const text = ext.packageJsonText;
    const keyAt = text.indexOf(`"${key}"`);
    if (keyAt >= 0) {
      const valueAt = value ? text.indexOf(value, keyAt) : -1;
      const start = valueAt >= 0 ? valueAt : keyAt;
      const lines = new LineIndex(text);
      range = lines.rangeOf(start, start + (valueAt >= 0 ? value!.length : key.length + 2));
    }
  }
  const info = SIGNALS[id];
  return [{ file, finding: { ruleId: id, severity: info.severity, message, range, refs: info.refs ?? [] } }];
}

function make(ext: ExtInfo, id: string, message: string, key?: string, value?: string, overrides: Partial<Signal> = {}): Signal {
  return signal(id, message, locate(ext, id, message, key, value), overrides);
}

export function manifestSignals(ext: ExtInfo, opts: ManifestOptions): Signal[] {
  const pkg = ext.packageJSON;
  const out: Signal[] = [];
  const id = ext.id.toLowerCase();
  const publisher = id.split('.')[0];

  const events = Array.isArray(pkg.activationEvents) ? (pkg.activationEvents as unknown[]).map(String) : [];
  if (events.includes('*')) {
    out.push(make(ext, 'ext/activates-on-startup', 'Activates on every startup (`"*"`).', 'activationEvents', '"*"'));
  } else if (events.includes('onStartupFinished')) {
    out.push(make(ext, 'ext/activates-after-startup', 'Activates after every startup (`onStartupFinished`).', 'activationEvents', '"onStartupFinished"'));
  }

  const untrusted = (pkg.capabilities as { untrustedWorkspaces?: { supported?: unknown } } | undefined)?.untrustedWorkspaces?.supported;
  if (untrusted === true) {
    out.push(make(ext, 'ext/untrusted-workspace', 'Declares `untrustedWorkspaces.supported: true` — runs in Restricted Mode.', 'untrustedWorkspaces'));
  }

  const deps = Array.isArray(pkg.extensionDependencies) ? (pkg.extensionDependencies as unknown[]) : [];
  if (deps.length > 3) {
    out.push(make(ext, 'ext/many-dependencies', `Depends on ${deps.length} other extensions.`, 'extensionDependencies'));
  }

  if (!opts.trustedPublishers.has(publisher)) {
    out.push(make(ext, 'ext/unknown-publisher', `Publisher \`${publisher}\` is not in the built-in trusted list.`, 'publisher'));
  }

  const squat = findTyposquat(id, opts.popular);
  if (squat) {
    const how = squat.reason === 'homoglyph' ? 'look-alike characters' : `${squat.distance} edit${squat.distance === 1 ? '' : 's'} away`;
    out.push(make(ext, 'ext/typosquat', `\`${id}\` resembles the popular extension \`${squat.target}\` (${how}).`, 'name'));
  }

  if (ext.source === 'vsix' || ext.source === 'resource') {
    out.push(make(ext, 'ext/sideloaded', `Installed from a ${ext.source === 'vsix' ? 'VSIX file' : 'local resource'}, not from the Marketplace.`));
  }

  const removed = opts.knownBad.get(id);
  if (removed) {
    const v = removalVerdict(removed.type);
    out.push(
      make(ext, 'ext/known-bad', `Removed from the VS Marketplace on ${removed.date} (${removed.type}).`, 'name', undefined, {
        weight: v.weight,
        force: v.force,
      }),
    );
  }
  return out;
}
