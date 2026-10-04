import type { Finding, Rule, Severity } from './rules/schema';

const LEVEL: Record<Severity, string> = { error: 'error', warning: 'warning', info: 'note', hint: 'note' };

export interface SarifInput {
  toolName: string;
  toolVersion: string;
  informationUri?: string;
  rules: readonly Rule[];
  /** Findings keyed by repository-relative path (forward slashes). */
  findings: ReadonlyMap<string, readonly Finding[]>;
}

/** Produces a SARIF 2.1.0 log, the format consumed by GitHub code scanning. */
export function toSarif(input: SarifInput): object {
  const ruleIds = new Set<string>();
  input.findings.forEach((fs) => fs.forEach((f) => ruleIds.add(f.ruleId)));
  const rules = input.rules
    .filter((r) => ruleIds.has(r.id))
    .map((r) => ({
      id: r.id,
      name: r.title,
      shortDescription: { text: r.title },
      fullDescription: { text: r.description ?? r.title },
      helpUri: r.refs?.find((ref) => ref.url)?.url,
      help: { text: (r.refs ?? []).map((ref) => `${ref.label}${ref.url ? ` <${ref.url}>` : ''}`).join('\n') || r.title },
      defaultConfiguration: { level: LEVEL[r.severity] },
      properties: { tags: r.tags ?? [] },
    }));
  const results: object[] = [];
  for (const [path, fs] of input.findings) {
    for (const f of fs) {
      results.push({
        ruleId: f.ruleId,
        level: LEVEL[f.severity],
        message: { text: f.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: path },
              region: {
                startLine: f.range.start.line + 1,
                startColumn: f.range.start.character + 1,
                endLine: f.range.end.line + 1,
                endColumn: f.range.end.character + 1,
              },
            },
          },
        ],
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: input.toolName, version: input.toolVersion, informationUri: input.informationUri, rules } },
        results,
      },
    ],
  };
}

/** Markdown summary grouped by rule, for human-readable reports. */
export function toMarkdownReport(title: string, rules: readonly Rule[], findings: ReadonlyMap<string, readonly Finding[]>): string {
  const byRule = new Map<string, { path: string; f: Finding }[]>();
  for (const [path, fs] of findings) {
    for (const f of fs) {
      const list = byRule.get(f.ruleId) ?? [];
      list.push({ path, f });
      byRule.set(f.ruleId, list);
    }
  }
  const total = [...byRule.values()].reduce((n, l) => n + l.length, 0);
  const out = [`# ${title}`, '', `Generated ${new Date().toISOString()} — ${total} finding(s) across ${findings.size} file(s).`, ''];
  if (total === 0) {
    out.push('No findings.');
  }
  for (const [id, list] of byRule) {
    const rule = rules.find((r) => r.id === id);
    out.push(`## ${rule?.title ?? id} (\`${id}\`, ${list[0].f.severity})`, '');
    if (rule?.description) {
      out.push(rule.description, '');
    }
    if (rule?.refs?.length) {
      out.push('References:', ...rule.refs.map((r) => `- ${r.url ? `[${r.label}](${r.url})` : r.label}`), '');
    }
    out.push('| Location | Message |', '|---|---|');
    for (const { path, f } of list) {
      out.push(`| \`${path}:${f.range.start.line + 1}\` | ${f.message.replace(/\|/g, '\\|')} |`);
    }
    out.push('');
  }
  return out.join('\n');
}
