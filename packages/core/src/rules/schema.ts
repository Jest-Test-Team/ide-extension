import type { GrammarId } from '../parsing/treeSitter';
import type { LineIndex, Range } from '../text';
import type { Node, QueryMatch, Tree } from 'web-tree-sitter';

export type Severity = 'error' | 'warning' | 'info' | 'hint';

/** A citation backing a rule: the standard / document and, ideally, a stable URL. */
export interface RuleRef {
  label: string;
  url?: string;
}

export interface RuleFix {
  title: string;
  /** Replacement text for the reported range; `{{capture}}` placeholders are expanded. */
  replacement: string;
}

interface RuleBase {
  id: string;
  title: string;
  severity: Severity;
  /** Diagnostic message; `{{capture}}` placeholders are expanded from query captures / regex groups. */
  message: string;
  /** VS Code language ids the rule applies to, or `*` for every document the host scans. */
  languages: string[];
  description?: string;
  refs?: RuleRef[];
  tags?: string[];
  fix?: RuleFix;
  enabled?: boolean;
  /** Suppresses the rule for the whole document when this regex matches anywhere in the text. */
  unless?: string;
  /** Runs the rule only when this regex matches somewhere in the document (e.g. `^esphome:`). */
  when?: string;
  /** Only run when the document path matches this regex (e.g. `(^|/)sdkconfig(\\.\\w+)?$`). */
  pathPattern?: string;
}

/** Structural rule expressed as a tree-sitter query. */
export interface QueryRule extends RuleBase {
  kind?: 'query';
  /**
   * One query for every grammar, or a query per grammar id. A query may hold several top-level
   * patterns. Note: web-tree-sitter does not apply text predicates (`#eq?`, `#match?`) inside
   * `[...]` alternations, so write alternatives as separate top-level patterns instead. Predicates
   * are JavaScript regular expressions (no inline `(?i)`); use `where` with `flags` for that.
   */
  query: string | Partial<Record<GrammarId, string>>;
  /** Capture whose node is reported. Defaults to `match`, else the first capture. */
  capture?: string;
  /** Extra regex constraints on capture text, applied after the query's own predicates. */
  where?: Record<string, { matches?: string; notMatches?: string; flags?: string }>;
}

/** Line-oriented text rule, for files without a grammar (sdkconfig, YAML) or simple literals. */
export interface PatternRule extends RuleBase {
  kind: 'pattern';
  pattern: string;
  flags?: string;
  /** Name of a built-in validator applied to the `value` group (or whole match), e.g. `luhn`. */
  validate?: string;
}

/** Reports when `pattern` is missing from a document; positioned at `anchor` if that matches. */
export interface AbsentRule extends RuleBase {
  kind: 'absent';
  pattern: string;
  anchor?: string;
  flags?: string;
}

export interface RuleContext {
  uri: string;
  path: string;
  languageId: string;
  text: string;
  lines: LineIndex;
  grammar?: GrammarId;
  tree?: Tree;
  /** Runs a query against the document tree (empty when the language has no grammar). */
  matches(query: string): Promise<QueryMatch[]>;
  /** Builds a finding for this rule at a node or range. */
  report(at: Node | Range, message?: string, vars?: Record<string, string>): Finding;
}

/** Rule implemented in code for analyses that a single query cannot express. */
export interface CustomRule extends RuleBase {
  kind: 'custom';
  check(ctx: RuleContext): Finding[] | Promise<Finding[]>;
}

export type Rule = QueryRule | PatternRule | AbsentRule | CustomRule;

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  range: Range;
  refs: RuleRef[];
  fix?: { title: string; edits: TextEdit[] };
  /** Free-form data a host can attach (for example a related location). */
  data?: Record<string, unknown>;
}

export interface TextEdit {
  range: Range;
  newText: string;
}

export interface RulePack {
  id: string;
  title: string;
  version?: string;
  refs?: RuleRef[];
  rules: Rule[];
}
