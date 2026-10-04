import { toMarkdownReport, toSarif, type CustomRule, type Finding, type Rule } from '@ide-ext/core';
import { dirname, relative } from 'node:path';
import type { ExtResult } from './scanner';
import { signalRules, SIGNALS } from './signals';

const RISK_RULE: CustomRule = {
  kind: 'custom',
  id: 'ext/risk',
  title: 'Installed extension risk level',
  severity: 'info',
  message: 'Installed extension risk level',
  description: 'Overall heuristic risk of an installed extension: low, medium or high, derived from the other ext/* signals. Heuristic: it flags risk, it does not prove an extension safe or malicious.',
  languages: [],
  tags: ['extension-scan'],
  check: () => [],
};

const ZERO = { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
const LEVEL_SEVERITY = { high: 'error', medium: 'warning', low: 'info' } as const;

/** Path of a file relative to the extensions folder, e.g. `foo.bar-1.0.0/out/extension.js`. */
function relPath(r: ExtResult, file: string): string {
  return relative(dirname(r.ext.path), file).replace(/\\/g, '/');
}

function reasons(r: ExtResult, max = 3): string {
  const scored = r.risk.signals.filter((s) => s.weight > 0);
  const list = scored.slice(0, max).map((s) => SIGNALS[s.id]?.title ?? s.id);
  return list.join('; ') + (scored.length > max ? `; +${scored.length - max} more` : '') || '—';
}

/** Findings keyed by path relative to the extensions folder, plus one `ext/risk` result per extension. */
export function reportFindings(results: readonly ExtResult[]): Map<string, Finding[]> {
  const out = new Map<string, Finding[]>();
  const add = (path: string, f: Finding) => out.set(path, [...(out.get(path) ?? []), f]);
  for (const r of results) {
    const manifest = relPath(r, `${r.ext.path}/package.json`);
    add(manifest, {
      ruleId: RISK_RULE.id,
      severity: LEVEL_SEVERITY[r.risk.level],
      message: `${r.ext.id}@${r.ext.version}: ${r.risk.level} risk (score ${r.risk.score}${r.risk.allowlisted ? ', allowlisted' : ''}). ${reasons(r, 10)}.`,
      range: ZERO,
      refs: [],
    });
    for (const s of r.risk.signals) {
      if (!s.locations.length) {
        const info = SIGNALS[s.id];
        add(manifest, { ruleId: s.id, severity: info?.severity ?? 'info', message: `${r.ext.id}: ${s.message}`, range: ZERO, refs: info?.refs ?? [] });
      }
      for (const loc of s.locations) {
        add(relPath(r, loc.file), { ...loc.finding, message: `${r.ext.id}: ${loc.finding.message}` });
      }
    }
  }
  return out;
}

export function reportRules(codeRules: readonly Rule[]): Rule[] {
  return [RISK_RULE, ...signalRules(), ...codeRules];
}

export function toExtensionSarif(results: readonly ExtResult[], codeRules: readonly Rule[], toolVersion: string): object {
  return toSarif({
    toolName: 'Endpoint Security & Compliance Toolkit — Extension Scan',
    toolVersion,
    informationUri: 'https://github.com/Jest-Test-Team/ide-extension',
    rules: reportRules(codeRules),
    findings: reportFindings(results),
  });
}

export function toExtensionMarkdown(results: readonly ExtResult[], codeRules: readonly Rule[]): string {
  const esc = (s: string) => s.replace(/\|/g, '\\|');
  const counts = { high: 0, medium: 0, low: 0 };
  results.forEach((r) => counts[r.risk.level]++);
  const out = [
    '# Installed extension risk report',
    '',
    `Generated ${new Date().toISOString()} — ${results.length} extension(s): ${counts.high} high, ${counts.medium} medium, ${counts.low} low.`,
    '',
    '> Heuristic scan: it flags risk signals with their reasons; it cannot prove an extension safe. Many legitimate extensions run processes or read credentials for their own features.',
    '',
    '| Extension | Version | Risk | Score | Main reasons |',
    '|---|---|---|---|---|',
    ...results.map(
      (r) =>
        `| ${esc(r.ext.displayName ?? r.ext.id)} (\`${r.ext.id}\`) | ${r.ext.version} | ${r.risk.level}${r.risk.allowlisted ? ' (allowlisted)' : ''}${r.risk.capped ? ' (capped)' : ''} | ${r.risk.score} | ${esc(reasons(r))} |`,
    ),
    '',
  ];
  const findings = reportFindings(results);
  // The per-extension summary rows already cover ext/risk.
  for (const [path, fs] of findings) {
    const rest = fs.filter((f) => f.ruleId !== RISK_RULE.id);
    if (rest.length) {
      findings.set(path, rest);
    } else {
      findings.delete(path);
    }
  }
  return `${out.join('\n')}\n${toMarkdownReport('Findings', reportRules(codeRules), findings).replace(/^# Findings/, '## Findings')}`;
}
