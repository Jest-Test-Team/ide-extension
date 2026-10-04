import { parseRulePack, type Finding, type Rule, type RuleEngine, type TreeSitterHost } from '@ide-ext/core';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { EXTSCAN_CUSTOM_RULES } from './codeRules';
import { signal, signalIdOf, SIGNALS, type Located, type Signal } from './signals';

export const CODE_RULES_FILE = 'extension-risk.yaml';

/** Code rules: the bundled YAML pack plus the custom rules. Throws on an invalid built-in pack. */
export function loadCodeRules(dataDir: string): { rules: Rule[]; version: string } {
  const text = readFileSync(join(dataDir, CODE_RULES_FILE), 'utf8');
  const res = parseRulePack(text, CODE_RULES_FILE);
  if (res.errors.length || !res.pack) {
    throw new Error(`Invalid ${CODE_RULES_FILE}:\n${res.errors.join('\n')}`);
  }
  // Results are cached per extension version; a rules change must invalidate that cache.
  const version = createHash('sha256')
    .update(text)
    .update(EXTSCAN_CUSTOM_RULES.map((r) => r.id + r.check.toString()).join('\n'))
    .digest('hex')
    .slice(0, 12);
  return { rules: [...res.pack.rules, ...EXTSCAN_CUSTOM_RULES], version };
}

export interface CodeScanOptions {
  includeNodeModules: boolean;
  maxFileSizeMB: number;
  maxFiles: number;
  /** Locations kept per signal (counts stay exact). */
  maxLocations?: number;
}

export interface CodeScanResult {
  signals: Signal[];
  filesScanned: number;
  bytesScanned: number;
}

const JS = new Set(['.js', '.cjs', '.mjs']);
const NATIVE = new Set(['.node', '.dll', '.dylib', '.so', '.exe']);
const SKIP_DIRS = new Set(['.git', '.svn', '.hg']);
const MAX_MESSAGE = 240;

interface Walk {
  js: string[];
  native: string[];
}

async function walk(dir: string, includeNodeModules: boolean, out: Walk = { js: [], native: [] }): Promise<Walk> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    // Symlinks are not followed: they could point anywhere on disk.
    if (e.isSymbolicLink()) {
      continue;
    }
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && (includeNodeModules || e.name !== 'node_modules')) {
        await walk(p, includeNodeModules, out);
      }
    } else if (e.isFile()) {
      const ext = extname(e.name).toLowerCase();
      if (JS.has(ext)) {
        out.js.push(p);
      } else if (NATIVE.has(ext) || /\.so(\.\d+)+$/.test(e.name)) {
        out.native.push(p);
      }
    }
  }
  return out;
}

/** Entry points first, then the extension's own code, then dependencies — the budget favours what runs. */
function prioritise(files: string[], dir: string, pkg: Record<string, unknown>): string[] {
  const entries = [pkg.main, pkg.browser]
    .filter((e): e is string => typeof e === 'string')
    .flatMap((e) => {
      const p = resolve(dir, e);
      return [p, `${p}.js`, join(p, 'index.js')];
    });
  const rank = (f: string) => {
    const i = entries.indexOf(f);
    if (i >= 0) {
      return i;
    }
    return relative(dir, f).split(sep).includes('node_modules') ? 2000 : 1000;
  };
  return [...files].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/**
 * Scans one extension's folder: runs the code rules on its JavaScript and lists native binaries.
 * Reads files only — nothing is executed or loaded.
 */
export async function scanExtensionCode(
  engine: RuleEngine,
  host: TreeSitterHost,
  dir: string,
  pkg: Record<string, unknown>,
  opts: CodeScanOptions,
  isCancelled: () => boolean = () => false,
): Promise<CodeScanResult> {
  const maxLocations = opts.maxLocations ?? 20;
  const found = await walk(dir, opts.includeNodeModules);
  const files = prioritise(found.js, dir, pkg);
  const byRule = new Map<string, { locations: Located[]; count: number }>();
  const skipped: string[] = [];
  let filesScanned = 0;
  let bytesScanned = 0;

  for (const file of files) {
    if (isCancelled()) {
      break;
    }
    if (filesScanned >= opts.maxFiles) {
      skipped.push(`${files.length - files.indexOf(file)} file(s) beyond the ${opts.maxFiles}-file budget`);
      break;
    }
    let text: string;
    try {
      const st = await stat(file);
      if (st.size > opts.maxFileSizeMB * 1024 * 1024) {
        skipped.push(`${relative(dir, file)} (${(st.size / 1024 / 1024).toFixed(1)} MB)`);
        continue;
      }
      text = await readFile(file, 'utf8');
    } catch {
      skipped.push(`${relative(dir, file)} (unreadable)`);
      continue;
    }
    const uri = pathToFileURL(file).toString();
    let findings: Finding[];
    try {
      findings = await engine.run({ uri, path: file, languageId: 'javascript', text });
    } finally {
      // RuleEngine caches the tree per URI; drop it, or thousands of files stay in wasm memory.
      host.forget(uri);
    }
    filesScanned++;
    bytesScanned += text.length;
    for (const f of findings) {
      if (!SIGNALS[signalIdOf(f.ruleId)]) {
        continue; // e.g. a "rule failed" hint
      }
      if (f.message.length > MAX_MESSAGE) {
        // Captures in minified code can span a whole line.
        f.message = `${f.message.slice(0, MAX_MESSAGE - 1)}…`;
      }
      const entry = byRule.get(f.ruleId) ?? { locations: [], count: 0 };
      entry.count++;
      if (entry.locations.length < maxLocations) {
        entry.locations.push({ file, finding: f });
      }
      byRule.set(f.ruleId, entry);
    }
  }

  const signals: Signal[] = [];
  const bySignal = new Map<string, { locations: Located[]; count: number; files: Set<string> }>();
  for (const [ruleId, { locations, count }] of byRule) {
    const id = signalIdOf(ruleId);
    const s = bySignal.get(id) ?? { locations: [], count: 0, files: new Set() };
    s.locations.push(...locations.slice(0, maxLocations - s.locations.length));
    s.count += count;
    locations.forEach((l) => s.files.add(l.file));
    bySignal.set(id, s);
  }
  for (const [id, s] of bySignal) {
    const first = s.locations[0];
    const where = `${s.count} hit${s.count === 1 ? '' : 's'} in ${s.files.size}${s.files.size >= maxLocations ? '+' : ''} file${s.files.size === 1 ? '' : 's'}`;
    signals.push(signal(id, `${first.finding.message} (${where})`, s.locations, { count: s.count }));
  }

  if (found.native.length) {
    const names = found.native.map((f) => relative(dir, f));
    const zero = { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
    const info = SIGNALS['ext/native-binary'];
    const locations = found.native.slice(0, maxLocations).map(
      (file): Located => ({ file, finding: { ruleId: 'ext/native-binary', severity: info.severity, message: `Native binary ${relative(dir, file)}`, range: zero, refs: info.refs ?? [] } }),
    );
    const list = names.slice(0, 3).join(', ') + (names.length > 3 ? `, … (${names.length})` : '');
    signals.push(signal('ext/native-binary', `Ships native binaries that cannot be inspected: ${list}.`, locations, { count: names.length }));
  }
  if (skipped.length) {
    signals.push(signal('ext/scan-incomplete', `Not scanned: ${skipped.slice(0, 3).join('; ')}${skipped.length > 3 ? `; … (${skipped.length})` : ''}.`, [], { count: skipped.length }));
  }
  return { signals, filesScanned, bytesScanned };
}
