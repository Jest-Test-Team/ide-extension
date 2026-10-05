import { existsSync, readdirSync } from 'node:fs';
import { LineIndex } from '@ide-ext/core';
import type { ExtInfo, ManifestOptions } from './manifest';
import { signal, SIGNALS, type Located, type Signal } from './signals';

/**
 * Deep manifest checks (Phase 2 of docs/plans/deep-extension-inspection.md). Pure functions over
 * package.json, plus a listing of the install folder for the licence check. Nothing is executed.
 */

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Finds the first occurrence of `needle` in package.json (after `afterKey` if given) for jump-to. */
function at(ext: ExtInfo, id: string, message: string, needle?: string, afterKey?: string): Located[] {
  const file = `${ext.path.replace(/[\\/]$/, '')}/package.json`;
  const text = ext.packageJsonText ?? '';
  let start = -1;
  if (needle && text) {
    const from = afterKey ? Math.max(0, text.indexOf(`"${afterKey}"`)) : 0;
    start = text.indexOf(needle, from);
  }
  const lines = new LineIndex(text);
  const range = start >= 0 ? lines.rangeOf(start, start + needle!.length) : { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
  const info = SIGNALS[id];
  return [{ file, finding: { ruleId: id, severity: info.severity, message, range, refs: info.refs ?? [] } }];
}

function make(ext: ExtInfo, id: string, message: string, needle?: string, afterKey?: string): Signal {
  return signal(id, message, at(ext, id, message, needle, afterKey));
}

/** Shortcuts people use constantly; binding them without a `when` clause intercepts them everywhere. */
const SENSITIVE_KEYS = /^(ctrl|cmd)\+(c|v|x|s|a|z)$|^enter$|^(ctrl|cmd)\+shift\+(p|v)$/;
const SECURITY_SETTINGS = /^(security\.|extensions\.(autoUpdate|autoCheckUpdates|verifySignature)|workbench\.trust|git\.(allowNoVerifyCommit|ignoreLegacyWarning)$|http\.systemCertificates)/;
const PROXY_SETTINGS = /^http\.(proxy|proxyStrictSSL|proxyAuthorization|proxySupport|noProxy)$/;
const TERMINAL_ENV = /^terminal\.integrated\.env\./;
const BRANDS = /\b(microsoft|github|google|amazon|aws|azure|jetbrains|docker|redhat|red hat|openai|anthropic)\b/i;
const BRAND_PUBLISHERS = /^(microsoft|ms-[\w-]+|vscode|github|google|googlecloudtools|amazonwebservices|aws-\w+|jetbrains|docker|ms-azuretools|redhat|openai|anthropic)$/i;
/** Schema hosts every popular extension uses; a schema from elsewhere is worth a look. */
const KNOWN_SCHEMA_HOSTS = /^https?:\/\/([\w-]+\.)*(schemastore\.org|json-schema\.org|raw\.githubusercontent\.com|microsoft\.com|azure\.com|vscode-cdn\.net)\//i;
const NORMAL_ENTRY_DIRS = /^(\.\/)?(out|dist|lib|build|bundle|src|client|extension|server|web|bin|packages?)\//;

export function deepManifestSignals(ext: ExtInfo, opts: ManifestOptions): Signal[] {
  const pkg = ext.packageJSON;
  const contributes = obj(pkg.contributes);
  const out: Signal[] = [];
  const events = arr(pkg.activationEvents).map(String);

  if (events.includes('onUri')) {
    out.push(make(ext, 'ext/uri-handler', 'Handles `vscode://` links (`onUri`): web pages can trigger it with chosen parameters.', '"onUri"'));
  }
  const broad = events.find((e) => /^workspaceContains:(\*\*\/\*|\*|\*\*|\*\*\/\*\.\*)$/.test(e));
  if (broad) {
    out.push(make(ext, 'ext/broad-workspace-contains', `Activation event \`${broad}\` matches practically every folder.`, `"${broad}"`));
  }
  const profiles = arr(obj(contributes.terminal).profiles);
  if (profiles.length) {
    out.push(make(ext, 'ext/terminal-profile', `Contributes ${profiles.length} terminal profile(s) that launch a program.`, '"profiles"'));
  }
  if (arr(contributes.taskDefinitions).length) {
    out.push(make(ext, 'ext/task-provider', 'Defines task types that run commands in a terminal.', '"taskDefinitions"'));
  }
  const debuggers = arr(contributes.debuggers).map(obj);
  const exec = debuggers.find((d) => ['program', 'runtime'].some((k) => d[k] !== undefined) || ['windows', 'osx', 'linux'].some((os) => obj(d[os]).program !== undefined));
  if (exec) {
    out.push(make(ext, 'ext/debug-adapter-executable', `Debugger \`${String(exec.type ?? '?')}\` starts an executable debug adapter.`, '"debuggers"'));
  }
  const auth = arr(contributes.authentication).map(obj);
  if (auth.length) {
    out.push(make(ext, 'ext/auth-provider', `Registers authentication provider(s): ${auth.map((a) => String(a.label ?? a.id)).join(', ')}.`, '"authentication"'));
  }
  const keys = arr(contributes.keybindings)
    .map(obj)
    .filter((k) => !k.when && [k.key, k.mac, k.win, k.linux].some((x) => typeof x === 'string' && SENSITIVE_KEYS.test(x.toLowerCase().replace(/\s+/g, ''))));
  if (keys.length) {
    const k = String(keys[0].key ?? keys[0].mac);
    out.push(make(ext, 'ext/keybinding-override', `Binds \`${k}\`${keys.length > 1 ? ` and ${keys.length - 1} more common shortcut(s)` : ''} without a \`when\` clause.`, `"${k}"`));
  }
  const defaults = Object.keys(obj(contributes.configurationDefaults));
  const sec = defaults.filter((k) => SECURITY_SETTINGS.test(k));
  if (sec.length) {
    out.push(make(ext, 'ext/security-setting-defaults', `Changes security settings for every user: ${sec.join(', ')}.`, `"${sec[0]}"`));
  }
  const proxy = defaults.filter((k) => PROXY_SETTINGS.test(k));
  if (proxy.length) {
    out.push(make(ext, 'ext/proxy-defaults', `Sets proxy defaults: ${proxy.join(', ')}.`, `"${proxy[0]}"`));
  }
  const env = defaults.filter((k) => TERMINAL_ENV.test(k));
  if (env.length) {
    out.push(make(ext, 'ext/terminal-env-defaults', `Injects terminal environment variables: ${env.join(', ')}.`, `"${env[0]}"`));
  }
  const related = [...arr(pkg.extensionDependencies), ...arr(pkg.extensionPack)].map((x) => String(x).toLowerCase());
  const unknown = related.filter((id) => !opts.trustedPublishers.has(id.split('.')[0]) && id.split('.')[0] !== ext.id.toLowerCase().split('.')[0]);
  if (unknown.length) {
    out.push(make(ext, 'ext/unknown-dependency', `Pulls in extensions from unknown publishers: ${unknown.slice(0, 5).join(', ')}${unknown.length > 5 ? ', …' : ''}.`, `"${unknown[0]}"`));
  }
  if (!pkg.repository) {
    out.push(make(ext, 'ext/missing-repository', 'No `repository` field: the code cannot be compared with its source.'));
  }
  if (!pkg.license && !hasLicenseFile(ext.path)) {
    out.push(make(ext, 'ext/missing-license', 'No license declared and no LICENSE file shipped.'));
  }
  const publisher = ext.id.toLowerCase().split('.')[0];
  const name = String(pkg.name ?? '').toLowerCase();
  const sameName = opts.popular.find((p) => p.split('.')[1] === name && p.split('.')[0] !== publisher);
  const display = typeof pkg.displayName === 'string' ? pkg.displayName : '';
  const brand = BRANDS.exec(display);
  if (!opts.trustedPublishers.has(publisher) && (sameName || (brand && !BRAND_PUBLISHERS.test(publisher)))) {
    out.push(
      make(
        ext,
        'ext/brand-impersonation',
        sameName ? `Uses the name \`${name}\` of the popular extension \`${sameName}\` under a different publisher.` : `Display name "${display}" names ${brand![0]}, but the publisher is \`${publisher}\`.`,
        sameName ? '"name"' : '"displayName"',
      ),
    );
  }
  const scripts = Object.keys(obj(pkg.scripts)).filter((s) => /^(pre|post)?install$/.test(s));
  // VS Code never runs these; a trusted publisher's leftover build hook is noise.
  if (scripts.length && !opts.trustedPublishers.has(publisher)) {
    out.push(make(ext, 'ext/manifest-install-scripts', `Lifecycle script(s) ${scripts.join(', ')} in the packaged manifest.`, `"${scripts[0]}"`));
  }
  const schemas = arr(contributes.jsonValidation)
    .map(obj)
    .map((j) => String(j.url ?? ''))
    .filter((u) => /^https?:\/\//.test(u) && !KNOWN_SCHEMA_HOSTS.test(u));
  if (schemas.length) {
    out.push(make(ext, 'ext/remote-schema', `Fetches JSON schemas from ${schemas.slice(0, 3).join(', ')}.`, `"${schemas[0]}"`));
  }
  const media = arr(contributes.walkthroughs)
    .flatMap((w) => arr(obj(w).steps))
    .flatMap((s) => Object.values(obj(obj(s).media)))
    .flatMap((m) => (typeof m === 'string' ? [m] : Object.values(obj(m)).map(String)))
    .filter((u) => /^https?:\/\//.test(u));
  if (media.length) {
    out.push(make(ext, 'ext/remote-walkthrough-media', `Walkthrough loads remote media (${media[0]}).`, `"${media[0]}"`));
  }
  for (const key of ['main', 'browser']) {
    const entry = typeof pkg[key] === 'string' ? (pkg[key] as string) : '';
    const why = unusualEntry(entry);
    if (why) {
      out.push(make(ext, 'ext/unusual-entry', `\`${key}\` entry \`${entry}\` ${why}.`, `"${entry}"`, key));
    }
  }
  return out;
}

export function unusualEntry(entry: string): string | undefined {
  if (!entry) {
    return undefined;
  }
  const parts = entry.replace(/^\.\//, '').split(/[\\/]/);
  if (parts.some((p) => p.startsWith('.') && p !== '.' && p !== '..')) {
    return 'is inside a hidden folder';
  }
  if (parts.includes('node_modules')) {
    return 'points into node_modules';
  }
  if (parts.length > 5) {
    return 'is unusually deeply nested';
  }
  const base = parts[parts.length - 1].replace(/\.[cm]?js$/, '');
  if (/^[a-f0-9]{16,}$/i.test(base) || (/^[a-z0-9]{12,}$/i.test(base) && /\d/.test(base) && /[a-z]/i.test(base) && !/(extension|index|main|bundle|client|server)/i.test(base))) {
    return 'has a random-looking file name';
  }
  if (parts.length > 1 && !NORMAL_ENTRY_DIRS.test(parts.join('/') + '/') && !NORMAL_ENTRY_DIRS.test(parts.slice(0, -1).join('/') + '/')) {
    return 'is outside the usual output folders';
  }
  return undefined;
}

function hasLicenseFile(dir: string): boolean {
  try {
    return existsSync(dir) && readdirSync(dir).some((f) => /^(licen[sc]e|copying)(\.|$)/i.test(f));
  } catch {
    return false;
  }
}

/**
 * Vectors that need both manifest and code evidence; called after the code scan with all signals
 * collected so far.
 */
export function combinedSignals(ext: ExtInfo, signals: readonly Signal[]): Signal[] {
  const out: Signal[] = [];
  const kind = ext.packageJSON.extensionKind;
  const kinds = Array.isArray(kind) ? kind.map(String) : typeof kind === 'string' ? [kind] : [];
  const runsProcesses = signals.some((s) => s.id === 'ext/process-exec' || s.id === 'ext/shell-exec');
  if (kinds[0] === 'workspace' && runsProcesses) {
    out.push(make(ext, 'ext/remote-workspace-exec', 'Runs on the remote / container / WSL host (`extensionKind: workspace`) and executes programs there.', '"extensionKind"'));
  }
  return out;
}

export const DEEP_MANIFEST_VECTORS = [
  'ext/uri-handler',
  'ext/broad-workspace-contains',
  'ext/remote-workspace-exec',
  'ext/terminal-profile',
  'ext/task-provider',
  'ext/debug-adapter-executable',
  'ext/auth-provider',
  'ext/keybinding-override',
  'ext/security-setting-defaults',
  'ext/proxy-defaults',
  'ext/terminal-env-defaults',
  'ext/unknown-dependency',
  'ext/missing-repository',
  'ext/missing-license',
  'ext/brand-impersonation',
  'ext/manifest-install-scripts',
  'ext/remote-schema',
  'ext/remote-walkthrough-media',
  'ext/unusual-entry',
] as const;

