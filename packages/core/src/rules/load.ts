import { parse as parseYaml } from 'yaml';
import type { Rule, RulePack, Severity } from './schema';

const SEVERITIES: Severity[] = ['error', 'warning', 'info', 'hint'];
const KINDS = ['query', 'pattern', 'absent'];

export interface LoadResult {
  pack?: RulePack;
  errors: string[];
}

/**
 * Parses a declarative rule pack (YAML or JSON). Custom rules cannot be declared in files; they are
 * registered in code. Invalid rules are dropped and reported in `errors`, valid ones are kept.
 */
export function parseRulePack(text: string, source = 'rule pack'): LoadResult {
  let raw: unknown;
  try {
    raw = source.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  } catch (err) {
    return { errors: [`${source}: ${(err as Error).message}`] };
  }
  if (!raw || typeof raw !== 'object') {
    return { errors: [`${source}: expected an object with "id" and "rules"`] };
  }
  const obj = raw as Record<string, unknown>;
  const errors: string[] = [];
  if (typeof obj.id !== 'string') {
    errors.push(`${source}: missing pack "id"`);
  }
  if (!Array.isArray(obj.rules)) {
    errors.push(`${source}: "rules" must be a list`);
    return { errors };
  }
  const rules: Rule[] = [];
  const seen = new Set<string>();
  obj.rules.forEach((r: unknown, i: number) => {
    const problems = validateRule(r);
    const id = (r as { id?: unknown })?.id;
    const label = `${source}: rules[${i}]${typeof id === 'string' ? ` (${id})` : ''}`;
    if (typeof id === 'string' && seen.has(id)) {
      problems.push(`duplicate id`);
    }
    if (problems.length) {
      errors.push(`${label}: ${problems.join('; ')}`);
      return;
    }
    seen.add(id as string);
    rules.push(r as Rule);
  });
  return {
    pack: {
      id: String(obj.id ?? source),
      title: String(obj.title ?? obj.id ?? source),
      version: obj.version === undefined ? undefined : String(obj.version),
      refs: Array.isArray(obj.refs) ? (obj.refs as RulePack['refs']) : undefined,
      rules,
    },
    errors,
  };
}

function validateRule(r: unknown): string[] {
  if (!r || typeof r !== 'object') {
    return ['must be an object'];
  }
  const rule = r as Record<string, unknown>;
  const problems: string[] = [];
  for (const key of ['id', 'title', 'message']) {
    if (typeof rule[key] !== 'string' || !rule[key]) {
      problems.push(`"${key}" is required`);
    }
  }
  if (!SEVERITIES.includes(rule.severity as Severity)) {
    problems.push(`"severity" must be one of ${SEVERITIES.join(', ')}`);
  }
  if (!Array.isArray(rule.languages) || rule.languages.some((l) => typeof l !== 'string')) {
    problems.push(`"languages" must be a list of language ids`);
  }
  const kind = (rule.kind as string | undefined) ?? 'query';
  if (!KINDS.includes(kind)) {
    problems.push(`"kind" must be one of ${KINDS.join(', ')}`);
  } else if (kind === 'query') {
    const q = rule.query;
    if (!(typeof q === 'string' || (q && typeof q === 'object'))) {
      problems.push(`"query" is required for query rules`);
    }
  } else if (typeof rule.pattern !== 'string') {
    problems.push(`"pattern" is required for ${kind} rules`);
  }
  for (const key of ['pattern', 'anchor', 'unless', 'when', 'pathPattern']) {
    if (typeof rule[key] === 'string') {
      try {
        new RegExp(rule[key] as string);
      } catch (err) {
        problems.push(`"${key}" is not a valid regex: ${(err as Error).message}`);
      }
    }
  }
  return problems;
}
