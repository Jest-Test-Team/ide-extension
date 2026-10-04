import type { ExtResult } from '../../../extensions/endpoint-security/src/extscan/scanner';
import type { Io } from './lib/args';

/** Signal groups used to summarise what installed extensions can do. */
export const CATEGORIES: { title: string; signals: string[] }[] = [
  { title: 'Known-malicious or impersonation', signals: ['ext/known-bad', 'ext/typosquat'] },
  { title: 'Data access (credentials, clipboard, keystrokes)', signals: ['ext/credential-path', 'ext/input-capture'] },
  { title: 'Network endpoints (hard-coded IPs, exfiltration services)', signals: ['ext/hardcoded-ip', 'ext/exfil-endpoint'] },
  { title: 'Code execution (processes, eval, native binaries, obfuscation)', signals: ['ext/process-exec', 'ext/dynamic-code', 'ext/native-binary', 'ext/obfuscated'] },
  { title: 'Activation and trust (startup, untrusted workspaces, dependencies)', signals: ['ext/activates-on-startup', 'ext/activates-after-startup', 'ext/untrusted-workspace', 'ext/many-dependencies'] },
  { title: 'Origin (unknown / unverified publisher, side-loaded, not on Marketplace)', signals: ['ext/unknown-publisher', 'ext/unverified-publisher', 'ext/sideloaded', 'ext/not-on-marketplace', 'ext/low-installs', 'ext/stale'] },
];

/** `vscode`, `cursor`, … from a path like ~/.cursor/extensions/x. */
export const editorOf = (p: string) => /[\\/]\.([\w-]+)[\\/]extensions[\\/]/.exec(p)?.[1] ?? 'custom';

export interface ExtensionAnalysis {
  total: number;
  levels: { high: number; medium: number; low: number };
  byEditor: Record<string, number>;
  bySource: Record<string, number>;
  categories: { title: string; extensions: { id: string; editor: string; signals: string[] }[] }[];
  /** Same extension id installed in more than one editor, with the versions seen. */
  multiEditor: { id: string; installs: { editor: string; version: string }[] }[];
  recommendations: string[];
}

export function analyzeExtensions(results: readonly ExtResult[]): ExtensionAnalysis {
  const levels = { high: 0, medium: 0, low: 0 };
  const byEditor: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const installs = new Map<string, { editor: string; version: string }[]>();
  for (const r of results) {
    levels[r.risk.level]++;
    const editor = editorOf(r.ext.path);
    byEditor[editor] = (byEditor[editor] ?? 0) + 1;
    const source = r.ext.source === 'gallery' ? 'Marketplace' : r.ext.source === 'vsix' ? 'VSIX (side-loaded)' : (r.ext.source ?? 'unknown');
    bySource[source] = (bySource[source] ?? 0) + 1;
    const key = r.ext.id.toLowerCase();
    installs.set(key, [...(installs.get(key) ?? []), { editor, version: r.ext.version }]);
  }
  const categories = CATEGORIES.map((c) => ({
    title: c.title,
    extensions: results
      .map((r) => ({ id: r.ext.id, editor: editorOf(r.ext.path), signals: r.risk.signals.filter((s) => c.signals.includes(s.id)).map((s) => s.id) }))
      .filter((x) => x.signals.length),
  }));
  const multiEditor = [...installs]
    .filter(([, v]) => v.length > 1)
    .map(([key, v]) => ({ id: results.find((r) => r.ext.id.toLowerCase() === key)!.ext.id, installs: v }));

  const rec: string[] = [];
  const has = (id: string) => results.filter((r) => r.risk.signals.some((s) => s.id === id));
  for (const r of has('ext/known-bad')) {
    rec.push(`UNINSTALL ${r.ext.id}: it is on Microsoft's list of extensions removed from the Marketplace.`);
  }
  for (const r of has('ext/typosquat')) {
    rec.push(`Verify ${r.ext.id}: its id imitates a popular extension (possible typosquat).`);
  }
  for (const r of results.filter((x) => x.risk.level === 'high' && !x.risk.signals.some((s) => s.id === 'ext/known-bad'))) {
    rec.push(`Review ${r.ext.id}@${r.ext.version} (high risk, score ${r.risk.score}): check the listed code locations; uninstall it if you do not need it.`);
  }
  const sideUnknown = results.filter((r) => r.risk.signals.some((s) => s.id === 'ext/sideloaded') && r.risk.signals.some((s) => s.id === 'ext/unknown-publisher'));
  if (sideUnknown.length) {
    rec.push(`Confirm where these side-loaded extensions from unknown publishers came from: ${[...new Set(sideUnknown.map((r) => r.ext.id))].join(', ')}.`);
  }
  const mismatched = multiEditor.filter((m) => new Set(m.installs.map((x) => x.version)).size > 1);
  if (mismatched.length) {
    rec.push(`Update outdated copies in other editors: ${mismatched.map((m) => `${m.id} (${m.installs.map((x) => `${x.editor} ${x.version}`).join(', ')})`).join('; ')}.`);
  }
  if (!rec.length) {
    rec.push('No action needed: no known-bad, typosquat or high-risk extensions. Allowlist extensions you trust with --allowlist to keep future reports focused.');
  }
  return { total: results.length, levels, byEditor, bySource, categories, multiEditor, recommendations: rec };
}

export function analysisText(io: Io, a: ExtensionAnalysis): string {
  const bold = (s: string) => (io.color ? `\x1b[1m${s}\x1b[0m` : s);
  const fmt = (o: Record<string, number>) => Object.entries(o).map(([k, v]) => `${k} ${v}`).join(', ');
  const lines = [
    bold('Inventory'),
    `  ${a.total} extension(s) — by editor: ${fmt(a.byEditor)}; by install source: ${fmt(a.bySource)}`,
    ...(a.multiEditor.length
      ? [`  Installed in several editors: ${a.multiEditor.map((m) => `${m.id} (${m.installs.map((x) => `${x.editor} ${x.version}`).join(', ')})`).join('; ')}`]
      : []),
    '',
    bold('What installed extensions can do (by category)'),
  ];
  for (const c of a.categories) {
    lines.push(`  ${c.title}: ${c.extensions.length ? c.extensions.length : 'none'}`);
    for (const e of c.extensions) {
      lines.push(`    - ${e.id} [${e.editor}]: ${e.signals.join(', ')}`);
    }
  }
  lines.push('', bold('Recommendations'), ...a.recommendations.map((r) => `  • ${r}`));
  return lines.join('\n') + '\n';
}
