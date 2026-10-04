import type { Node } from 'web-tree-sitter';
import { grammarForLanguage, type GrammarId, type TreeSitterHost } from '../parsing/treeSitter';
import { LineIndex, renderTemplate, type Range } from '../text';
import type { AbsentRule, CustomRule, Finding, PatternRule, QueryRule, Rule, RuleContext } from './schema';
import { VALIDATORS } from './validators';

export interface SourceDocument {
  uri: string;
  /** File system path (or the URI path) used by `pathPattern`. */
  path: string;
  languageId: string;
  text: string;
  version?: number;
}

/**
 * Comment directives honoured by every rule:
 *   `ide-ext-ignore-next-line <rule-id>[, <rule-id>]` and `ide-ext-ignore <rule-id>` (same line).
 * `*` disables all rules for that line.
 */
const SUPPRESS_RE = /ide-ext-ignore(-next-line)?\s+([\w*.,\t -]+)/g;

function isNode(x: Node | Range): x is Node {
  return typeof (x as Node).startIndex === 'number';
}

export class RuleEngine {
  private rules: Rule[] = [];

  constructor(
    private readonly host: TreeSitterHost,
    rules: Rule[] = [],
  ) {
    this.setRules(rules);
  }

  setRules(rules: Rule[]): void {
    this.rules = rules.filter((r) => r.enabled !== false);
  }

  getRules(): readonly Rule[] {
    return this.rules;
  }

  getRule(id: string): Rule | undefined {
    return this.rules.find((r) => r.id === id);
  }

  appliesTo(languageId: string): boolean {
    return this.rules.some((r) => r.languages.includes('*') || r.languages.includes(languageId));
  }

  async run(doc: SourceDocument): Promise<Finding[]> {
    const rules = this.rules.filter(
      (r) =>
        (r.languages.includes('*') || r.languages.includes(doc.languageId)) &&
        (!r.pathPattern || new RegExp(r.pathPattern).test(doc.path.replace(/\\/g, '/'))) &&
        (!r.unless || !new RegExp(r.unless, 'm').test(doc.text)),
    );
    if (rules.length === 0) {
      return [];
    }
    const lines = new LineIndex(doc.text);
    const grammar = grammarForLanguage(doc.languageId);
    const tree = grammar ? await this.host.parse(grammar, doc.text, doc.uri, doc.version ?? 0) : undefined;

    const findings: Finding[] = [];
    for (const rule of rules) {
      try {
        const ctx = this.context(rule, doc, lines, grammar, tree);
        switch (rule.kind) {
          case 'pattern':
            findings.push(...runPattern(rule, ctx));
            break;
          case 'absent':
            findings.push(...runAbsent(rule, ctx));
            break;
          case 'custom':
            findings.push(...(await rule.check(ctx)));
            break;
          default:
            if (grammar && tree) {
              findings.push(...(await this.runQuery(rule, ctx, grammar)));
            }
        }
      } catch (err) {
        // A broken rule must not take the others down; surface it as a finding on line 0.
        findings.push({
          ruleId: rule.id,
          severity: 'hint',
          message: `Rule ${rule.id} failed: ${(err as Error).message}`,
          range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
          refs: [],
        });
      }
    }
    return applySuppressions(findings, lines);
  }

  private context(
    rule: Rule,
    doc: SourceDocument,
    lines: LineIndex,
    grammar: GrammarId | undefined,
    tree: RuleContext['tree'],
  ): RuleContext {
    return {
      uri: doc.uri,
      path: doc.path,
      languageId: doc.languageId,
      text: doc.text,
      lines,
      grammar,
      tree,
      matches: async (source) => {
        if (!grammar || !tree) {
          return [];
        }
        return (await this.host.query(grammar, source)).matches(tree.rootNode);
      },
      report: (at, message, vars = {}) => {
        const range = isNode(at) ? lines.rangeOf(at.startIndex, at.endIndex) : at;
        const text = isNode(at) ? at.text : '';
        const allVars = { match: text, ...vars };
        return {
          ruleId: rule.id,
          severity: rule.severity,
          message: renderTemplate(message ?? rule.message, allVars),
          range,
          refs: rule.refs ?? [],
          fix: rule.fix
            ? { title: rule.fix.title, edits: [{ range, newText: renderTemplate(rule.fix.replacement, allVars) }] }
            : undefined,
        };
      },
    };
  }

  private async runQuery(rule: QueryRule, ctx: RuleContext, grammar: GrammarId): Promise<Finding[]> {
    const source = typeof rule.query === 'string' ? rule.query : rule.query[grammar];
    if (!source) {
      return [];
    }
    const where = Object.entries(rule.where ?? {}).map(([name, c]) => ({
      name,
      matches: c.matches ? new RegExp(c.matches) : undefined,
      notMatches: c.notMatches ? new RegExp(c.notMatches) : undefined,
    }));
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const m of await ctx.matches(source)) {
      const vars: Record<string, string> = {};
      for (const c of m.captures) {
        vars[c.name] ??= c.node.text;
      }
      const ok = where.every(({ name, matches, notMatches }) => {
        const v = vars[name];
        return v !== undefined && (!matches || matches.test(v)) && (!notMatches || !notMatches.test(v));
      });
      if (!ok) {
        continue;
      }
      const target =
        m.captures.find((c) => c.name === (rule.capture ?? 'match')) ??
        (rule.capture ? undefined : m.captures[0]);
      if (!target) {
        continue;
      }
      const key = `${target.node.startIndex}:${target.node.endIndex}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(ctx.report(target.node, undefined, vars));
      }
    }
    return out;
  }
}

function runPattern(rule: PatternRule, ctx: RuleContext): Finding[] {
  const flags = new Set((rule.flags ?? '').split(''));
  flags.add('g');
  const re = new RegExp(rule.pattern, [...flags].join(''));
  const validate = rule.validate ? VALIDATORS[rule.validate] : undefined;
  if (rule.validate && !validate) {
    throw new Error(`unknown validator "${rule.validate}"`);
  }
  const out: Finding[] = [];
  for (const m of ctx.text.matchAll(re)) {
    const value = m.groups?.value ?? m[0];
    if (validate && !validate(value)) {
      continue;
    }
    const start = m.index ?? 0;
    const range = ctx.lines.rangeOf(start, start + m[0].length);
    out.push(ctx.report(range, undefined, { match: m[0], ...(m.groups as Record<string, string>) }));
  }
  return out;
}

function runAbsent(rule: AbsentRule, ctx: RuleContext): Finding[] {
  if (new RegExp(rule.pattern, rule.flags ?? 'm').test(ctx.text)) {
    return [];
  }
  let range: Range = { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
  if (rule.anchor) {
    const m = new RegExp(rule.anchor, rule.flags ?? 'm').exec(ctx.text);
    if (m) {
      range = ctx.lines.rangeOf(m.index, m.index + m[0].length);
    }
  }
  return [ctx.report(range)];
}

function applySuppressions(findings: Finding[], lines: LineIndex): Finding[] {
  if (!/ide-ext-ignore/.test(lines.text)) {
    return findings;
  }
  const suppressed = new Map<number, Set<string>>();
  for (const m of lines.text.matchAll(SUPPRESS_RE)) {
    const line = lines.positionAt(m.index ?? 0).line + (m[1] ? 1 : 0);
    const ids = m[2]
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const set = suppressed.get(line) ?? new Set<string>();
    ids.forEach((id) => set.add(id));
    suppressed.set(line, set);
  }
  return findings.filter((f) => {
    const set = suppressed.get(f.range.start.line);
    return !set || !(set.has('*') || set.has(f.ruleId));
  });
}

export type { AbsentRule, CustomRule, PatternRule, QueryRule };
