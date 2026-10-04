import * as vscode from 'vscode';
import type { Finding, Rule, RuleRef, Severity } from '../rules/schema';
import type { Range } from '../text';

const SEVERITY: Record<Severity, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

export function toRange(r: Range): vscode.Range {
  return new vscode.Range(r.start.line, r.start.character, r.end.line, r.end.character);
}

export function fromRange(r: vscode.Range): Range {
  return {
    start: { line: r.start.line, character: r.start.character },
    end: { line: r.end.line, character: r.end.character },
  };
}

/** Diagnostics carry the finding so code actions and hovers can recover rule metadata. */
export interface FindingDiagnostic extends vscode.Diagnostic {
  finding: Finding;
}

export function toDiagnostic(f: Finding, source: string): FindingDiagnostic {
  const d = new vscode.Diagnostic(toRange(f.range), f.message, SEVERITY[f.severity]) as FindingDiagnostic;
  d.source = source;
  const url = f.refs.find((r) => r.url)?.url;
  d.code = url ? { value: f.ruleId, target: vscode.Uri.parse(url) } : f.ruleId;
  d.finding = f;
  return d;
}

export function refsMarkdown(refs: readonly RuleRef[]): string {
  return refs.map((r) => (r.url ? `- [${r.label}](${r.url})` : `- ${r.label}`)).join('\n');
}

export function ruleMarkdown(rule: Rule): vscode.MarkdownString {
  const md = new vscode.MarkdownString(undefined, true);
  md.appendMarkdown(`**${rule.title}** \`${rule.id}\`\n\n`);
  if (rule.description) {
    md.appendMarkdown(`${rule.description}\n\n`);
  }
  if (rule.refs?.length) {
    md.appendMarkdown(`**Sources**\n\n${refsMarkdown(rule.refs)}\n`);
  }
  return md;
}
