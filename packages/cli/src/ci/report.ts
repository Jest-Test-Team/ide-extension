import { toSarif, type CustomRule, type Finding, type Range, type Rule, type Severity } from '@ide-ext/core';
import { relative } from 'node:path';
import { reportRules } from '../../../../extensions/endpoint-security/src/extscan/report';
import { SIGNALS, type RiskLevel } from '../../../../extensions/endpoint-security/src/extscan/signals';
import type { GuardItem, GuardReport } from './guard';

/** Marker that lets the GitHub Action find and update its own PR comment. */
export const COMMENT_MARKER = '<!-- jest-security-extension-guard -->';

const rule = (id: string, title: string, severity: Severity, description: string): CustomRule => ({
  kind: 'custom',
  id,
  title,
  severity,
  message: title,
  description,
  languages: [],
  tags: ['extension-guard'],
  check: () => [],
});

export const GUARD_RULES: Rule[] = [
  rule('policy/blocked', 'Extension blocked by policy', 'error', 'The extension or its publisher is on the policy file\'s "blocked" list.'),
  rule('policy/publisher-not-allowed', 'Publisher not allowed by policy', 'error', 'The policy file restricts extensions to an "allowed-publishers" list.'),
  rule('policy/unverified-publisher', 'Publisher not verified', 'error', 'The policy file requires a Marketplace-verified publisher domain.'),
  rule('ci/unscanned', 'Extension could not be scanned', 'warning', 'The package could not be resolved or downloaded (registry outage, hash mismatch, size limit); it was judged by its id only.'),
];

const LEVEL_SEVERITY: Record<RiskLevel, Severity> = { high: 'error', medium: 'warning', low: 'info' };
const ICON: Record<RiskLevel, string> = { high: '🔴', medium: '🟠', low: '🟢' };

const anchorOf = (item: GuardItem) => item.change.entries[0];
const rangeOf = (line: number): Range => ({ start: { line: line - 1, character: 0 }, end: { line: line - 1, character: 0 } });
const versionOf = (item: GuardItem) => item.result?.ext.version ?? item.change.version ?? 'latest';

export function itemLink(item: GuardItem, registry: GuardReport['registry']): string {
  const [pub, name] = item.change.id.split('.');
  return registry === 'open-vsx' ? `https://open-vsx.org/extension/${pub}/${name}` : `https://marketplace.visualstudio.com/items?itemName=${item.change.id}`;
}

/** The heaviest scored reasons, as short titles. */
export function reasons(item: GuardItem, max = 3): string {
  const scored = (item.result?.risk.signals ?? []).filter((s) => s.weight > 0);
  const list = [...item.violations.map((v) => v.message.replace(/`/g, '')), ...scored.slice(0, max).map((s) => SIGNALS[s.id]?.title ?? s.id)];
  const more = scored.length > max ? `; +${scored.length - max} more` : '';
  return list.length ? list.join('; ') + more : '—';
}

/** Location of a signal inside the package, relative to the extension folder. */
function where(item: GuardItem, file: string, line: number): string {
  return item.fetched ? `${relative(item.fetched.dir, file).replace(/\\/g, '/')}:${line + 1}` : '';
}

/**
 * SARIF for code scanning. Findings inside a downloaded package cannot be annotated in the
 * repository, so every result points at the manifest line that adds the extension.
 */
export function guardFindings(report: GuardReport): Map<string, Finding[]> {
  const out = new Map<string, Finding[]>();
  const add = (file: string, f: Finding) => out.set(file, [...(out.get(file) ?? []), f]);
  for (const item of report.items) {
    const anchor = anchorOf(item);
    const range = rangeOf(anchor.line);
    const id = `${item.change.id}@${versionOf(item)}`;
    const risk = item.result?.risk;
    if (risk) {
      add(anchor.file, {
        ruleId: 'ext/risk',
        severity: LEVEL_SEVERITY[risk.level],
        message: `${id} (${item.change.status}): ${risk.level} risk, score ${risk.score}${risk.allowlisted ? ', allowlisted' : ''}. ${reasons(item, 10)}.`,
        range,
        refs: [],
      });
      // Individual reasons for anything that is not plainly low risk.
      if (risk.level !== 'low' || item.failing) {
        for (const s of risk.signals.filter((x) => x.weight > 0)) {
          const loc = s.locations[0];
          const at = loc ? where(item, loc.file, loc.finding.range.start.line) : '';
          add(anchor.file, {
            ruleId: s.id,
            severity: SIGNALS[s.id]?.severity ?? 'info',
            message: `${id}: ${s.message}${at ? ` (in ${at})` : ''}`,
            range,
            refs: SIGNALS[s.id]?.refs ?? [],
          });
        }
      }
    }
    for (const v of item.violations) {
      add(anchor.file, { ruleId: v.rule, severity: 'error', message: `${id}: ${v.message}`, range, refs: [] });
    }
    if (item.status === 'unscanned') {
      add(anchor.file, { ruleId: 'ci/unscanned', severity: 'warning', message: `${id}: not scanned — ${item.reason ?? 'unknown error'}`, range, refs: [] });
    }
  }
  return out;
}

export function guardSarif(report: GuardReport, toolVersion: string): object {
  return toSarif({
    toolName: 'jest-security extension guard',
    toolVersion,
    informationUri: 'https://github.com/Jest-Test-Team/ide-extension',
    rules: [...reportRules(report.codeRules), ...GUARD_RULES],
    findings: guardFindings(report),
  });
}

function verdict(report: GuardReport): string {
  const failing = report.items.filter((i) => i.failing).length;
  const unscanned = report.items.filter((i) => i.status === 'unscanned').length;
  if (failing) {
    return `❌ **${failing} extension(s) blocked** (risk ≥ ${report.failOn} or policy violation).`;
  }
  if (unscanned) {
    return `⚠️ **${unscanned} extension(s) could not be scanned** — see below.`;
  }
  return report.items.length ? '✅ No new extension reaches the fail level.' : '✅ No extensions added or changed.';
}

/** Markdown for the job summary and the PR comment. */
export function guardMarkdown(report: GuardReport): string {
  const esc = (s: string) => s.replace(/\|/g, '\\|');
  const counts = { added: 0, changed: 0, removed: 0, unchanged: 0 };
  report.changes.forEach((c) => counts[c.status]++);
  const out = [
    COMMENT_MARKER,
    '## 🛡️ Extension guard',
    '',
    verdict(report),
    '',
    report.base
      ? `Compared with \`${report.base.slice(0, 12)}\`: ${counts.added} added, ${counts.changed} changed, ${counts.removed} removed, ${counts.unchanged} unchanged.`
      : `${report.items.length} listed extension(s) scanned (no base revision).`,
    '',
  ];
  if (report.items.length) {
    out.push('| | Extension | Version | Change | Risk | Main reasons |', '|---|---|---|---|---|---|');
    for (const item of report.items) {
      const risk = item.result?.risk;
      const icon = item.violations.length ? '⛔' : item.status === 'unscanned' ? '⚠️' : risk ? ICON[risk.level] : '❔';
      const level = risk ? `${risk.level} (${risk.score})${risk.allowlisted ? ' · allowlisted' : ''}` : '—';
      const note = item.status === 'id-only' ? ' · *not downloadable*' : item.status === 'unscanned' ? ' · *not scanned*' : '';
      const a = anchorOf(item);
      out.push(
        `| ${icon} | [\`${item.change.id}\`](${itemLink(item, report.registry)}) | ${esc(versionOf(item))} | ${report.base ? item.change.status : 'listed'} · \`${a.file}:${a.line}\` | ${level}${note} | ${esc(reasons(item))} |`,
      );
    }
    out.push('');
  }
  for (const item of report.items.filter((i) => i.failing || i.status !== 'scanned' || (i.result && i.result.risk.level !== 'low'))) {
    const risk = item.result?.risk;
    out.push(`<details><summary><b>${item.change.id}</b> — ${risk ? `${risk.level} risk, score ${risk.score}` : 'not scored'}</summary>`, '');
    item.violations.forEach((v) => out.push(`- ⛔ ${v.message}`));
    if (item.reason) {
      out.push(`- ${item.status === 'id-only' ? 'ℹ️' : '⚠️'} ${item.reason}`);
    }
    for (const b of risk?.boosts ?? []) {
      out.push(`- 🔗 +${b.weight} ${b.label}`);
    }
    for (const s of (risk?.signals ?? []).filter((x) => x.weight !== 0)) {
      const loc = s.locations[0];
      const at = loc ? where(item, loc.file, loc.finding.range.start.line) : '';
      out.push(`- ${s.weight > 0 ? `+${s.weight}` : s.weight} **${SIGNALS[s.id]?.title ?? s.id}** — ${s.message.replace(/\n/g, ' ')}${at ? ` (\`${at}\`)` : ''}`);
    }
    if (item.fetched) {
      out.push(`- 📦 ${item.fetched.pkg.registry} ${item.fetched.pkg.targetPlatform}, SHA-256 \`${item.fetched.sha256.slice(0, 16)}…\`${item.fetched.verified ? ' (matches the registry)' : ''}`);
    }
    out.push('', '</details>', '');
  }
  const removed = report.changes.filter((c) => c.status === 'removed');
  if (removed.length) {
    out.push(`Removed: ${removed.map((c) => `\`${c.id}\``).join(', ')}`, '');
  }
  out.push(
    `<sub>jest-security scan-manifest · registry ${report.registry} · platform ${report.targetPlatform} · fail-on ${report.failOn} · ${report.files.length} manifest file(s). Heuristic: risk signals with reasons, not a verdict.</sub>`,
    '',
  );
  return out.join('\n');
}

/** Plain-text report for the terminal. */
export function guardText(report: GuardReport): string {
  const lines = [`== Extension lists ==`, ...report.files.map((f) => `  ${f}`), ''];
  if (report.base) {
    lines.push(`== Changes since ${report.base} ==`);
    for (const c of report.changes.filter((x) => x.status !== 'unchanged')) {
      lines.push(`  ${c.status.padEnd(8)} ${c.id}${c.version ? `@${c.version}` : ''}${c.baseVersion && c.status === 'changed' ? ` (was ${c.baseVersion})` : ''}`);
    }
    lines.push('');
  }
  lines.push('== Scanned ==');
  if (!report.items.length) {
    lines.push('  nothing to scan');
  }
  for (const item of report.items) {
    const risk = item.result?.risk;
    const mark = item.failing ? 'FAIL' : item.status === 'unscanned' ? 'WARN' : 'ok  ';
    lines.push(`  ${mark} ${(risk?.level ?? '-').toUpperCase().padEnd(6)} ${String(risk?.score ?? '-').padStart(3)}  ${item.change.id}@${versionOf(item)}  [${item.status}]`);
    lines.push(`         ${reasons(item, 5)}`);
    if (item.reason) {
      lines.push(`         ${item.reason}`);
    }
  }
  lines.push('', `Result: ${report.exitCode === 0 ? 'pass' : report.exitCode === 1 ? 'blocked' : 'incomplete (some extensions could not be scanned)'}`, '');
  return lines.join('\n');
}

const escData = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s: string) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

/** GitHub workflow commands: inline annotations on the manifest lines, no permissions needed. */
export function githubAnnotations(report: GuardReport): string {
  const out: string[] = [];
  for (const item of report.items) {
    const a = anchorOf(item);
    const risk = item.result?.risk;
    const kind = item.failing ? 'error' : item.status === 'unscanned' || risk?.level === 'medium' ? 'warning' : undefined;
    if (!kind) {
      continue;
    }
    const title = `${item.change.id}: ${item.violations.length ? 'policy violation' : item.status === 'unscanned' ? 'not scanned' : `${risk?.level} risk (${risk?.score})`}`;
    out.push(`::${kind} file=${escProp(a.file)},line=${a.line},title=${escProp(title)}::${escData(reasons(item, 5) + (item.reason ? ` — ${item.reason}` : ''))}`);
  }
  return out.length ? out.join('\n') + '\n' : '';
}

/** JSON for scripting. */
export function guardJson(report: GuardReport): object {
  return {
    base: report.base,
    files: report.files,
    failOn: report.failOn,
    exitCode: report.exitCode,
    changes: report.changes.map((c) => ({ id: c.id, status: c.status, version: c.version, baseVersion: c.baseVersion, at: c.entries.map((e) => `${e.file}:${e.line}`) })),
    items: report.items.map((i) => ({
      id: i.change.id,
      change: i.change.status,
      status: i.status,
      version: versionOf(i),
      level: i.result?.risk.level,
      score: i.result?.risk.score,
      failing: i.failing,
      violations: i.violations,
      reason: i.reason,
      signals: i.result?.risk.signals.map((s) => ({ id: s.id, weight: s.weight, message: s.message })),
      package: i.fetched ? { url: i.fetched.pkg.url, sha256: i.fetched.sha256, verified: i.fetched.verified, targetPlatform: i.fetched.pkg.targetPlatform } : undefined,
    })),
  };
}
