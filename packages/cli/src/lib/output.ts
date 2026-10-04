import { toMarkdownReport, toSarif, type Finding, type Rule, type Severity } from '@ide-ext/core';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { UsageError, VERSION, type FlagSpec, type Io } from './args';

export type Format = 'text' | 'json' | 'sarif' | 'md';
export const FORMATS: Format[] = ['text', 'json', 'sarif', 'md'];

export const REPORT_FLAGS: Record<string, FlagSpec> = {
  format: { type: 'string', alias: 'f', value: '<text|json|sarif|md>', description: 'Output format', default: 'text' },
  out: { type: 'string', alias: 'o', value: '<file>', description: 'Write the report to a file instead of stdout' },
};

export const LINT_FLAGS: Record<string, FlagSpec> = {
  ...REPORT_FLAGS,
  'fail-on': { type: 'string', value: '<error|warning|info|hint|none>', description: 'Exit with code 1 when a finding has at least this severity', default: 'error' },
  disable: { type: 'string', multiple: true, value: '<rule-id>', description: 'Turn a rule off' },
  'rule-pack': { type: 'string', multiple: true, value: '<file.yaml>', description: 'Add a YAML/JSON rule pack' },
  quiet: { type: 'boolean', alias: 'q', description: 'Report errors only' },
};

const RANK: Record<Severity, number> = { error: 3, warning: 2, info: 1, hint: 0 };

export function formatOf(v: unknown): Format {
  if (!FORMATS.includes(v as Format)) {
    throw new UsageError(`--format must be one of ${FORMATS.join(', ')}`);
  }
  return v as Format;
}

export function failThreshold(v: unknown): number {
  if (v === 'none') {
    return Infinity;
  }
  if (!(String(v) in RANK)) {
    throw new UsageError('--fail-on must be error, warning, info, hint or none');
  }
  return RANK[v as Severity];
}

const paint = (io: Io, code: number, s: string) => (io.color ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR: Record<Severity, number> = { error: 31, warning: 33, info: 36, hint: 90 };

/** eslint-style text report. */
export function textReport(io: Io, findings: ReadonlyMap<string, readonly Finding[]>): string {
  const lines: string[] = [];
  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0, hint: 0 };
  for (const [file, list] of findings) {
    if (!list.length) {
      continue;
    }
    lines.push(paint(io, 4, file));
    const sorted = [...list].sort((a, b) => a.range.start.line - b.range.start.line || a.range.start.character - b.range.start.character);
    const posW = Math.max(...sorted.map((f) => `${f.range.start.line + 1}:${f.range.start.character + 1}`.length));
    for (const f of sorted) {
      counts[f.severity]++;
      const pos = `${f.range.start.line + 1}:${f.range.start.character + 1}`.padEnd(posW);
      lines.push(`  ${paint(io, 90, pos)}  ${paint(io, SEV_COLOR[f.severity], f.severity.padEnd(7))}  ${f.message}  ${paint(io, 90, f.ruleId)}`);
    }
    lines.push('');
  }
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  lines.push(
    total
      ? paint(io, counts.error ? 31 : 33, `✖ ${total} problem(s) (${counts.error} error(s), ${counts.warning} warning(s), ${counts.info + counts.hint} info)`)
      : paint(io, 32, '✔ No problems found'),
  );
  return lines.join('\n') + '\n';
}

export function renderFindings(format: Format, io: Io, opts: { toolName: string; title: string; rules: readonly Rule[]; findings: ReadonlyMap<string, Finding[]> }): string {
  switch (format) {
    case 'json':
      return JSON.stringify(
        [...opts.findings].map(([file, findings]) => ({ file, findings })),
        null,
        2,
      ) + '\n';
    case 'sarif':
      return JSON.stringify(
        toSarif({ toolName: opts.toolName, toolVersion: VERSION, informationUri: 'https://github.com/Jest-Test-Team/ide-extension', rules: opts.rules, findings: opts.findings }),
        null,
        2,
      ) + '\n';
    case 'md':
      return toMarkdownReport(opts.title, opts.rules, opts.findings) + '\n';
    default:
      return textReport(io, opts.findings);
  }
}

/** Writes to --out (creating folders) or stdout. */
export function emit(io: Io, text: string, out: unknown): void {
  if (typeof out === 'string' && out) {
    const target = resolve(io.cwd, out);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
    io.err(`wrote ${out}\n`);
  } else {
    io.out(text);
  }
}

export function exitFor(findings: ReadonlyMap<string, readonly Finding[]>, threshold: number): number {
  for (const list of findings.values()) {
    if (list.some((f) => RANK[f.severity] >= threshold)) {
      return 1;
    }
  }
  return 0;
}
