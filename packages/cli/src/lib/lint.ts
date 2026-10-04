import { parseRulePack, RuleEngine, TreeSitterHost, type Finding, type Rule } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Command, Flags, Io } from './args';
import { assetDir } from './assets';
import { collectFiles } from './files';
import { emit, exitFor, failThreshold, formatOf, LINT_FLAGS, renderFindings } from './output';

let host: TreeSitterHost | undefined;
export function treeSitter(): TreeSitterHost {
  host ??= new TreeSitterHost(assetDir('grammars'));
  return host;
}

/** Rules after --disable and --rule-pack. */
export function effectiveRules(base: readonly Rule[], flags: Flags, io: Io): Rule[] {
  const extra: Rule[] = [];
  for (const file of (flags['rule-pack'] as string[] | undefined) ?? []) {
    const res = parseRulePack(readFileSync(resolve(io.cwd, file), 'utf8'), file);
    res.errors.forEach((e) => io.err(`warning: ${e}\n`));
    extra.push(...(res.pack?.rules ?? []));
  }
  const disabled = new Set((flags.disable as string[] | undefined) ?? []);
  return [...base, ...extra].filter((r) => !disabled.has(r.id));
}

/** Lints files; keys of the result are paths relative to io.cwd. */
export async function lintFiles(rules: readonly Rule[], inputs: readonly string[], io: Io, quiet = false): Promise<Map<string, Finding[]>> {
  const engine = new RuleEngine(treeSitter(), [...rules]);
  const wildcard = rules.some((r) => r.languages.includes('*'));
  const files = collectFiles(inputs, io.cwd, (lang) => wildcard || engine.appliesTo(lang));
  const out = new Map<string, Finding[]>();
  for (const f of files) {
    let findings = await engine.run({ uri: `file://${f.path}`, path: f.path, languageId: f.languageId, text: readFileSync(f.path, 'utf8') });
    if (quiet) {
      findings = findings.filter((x) => x.severity === 'error');
    }
    if (findings.length) {
      out.set(f.rel, findings);
    }
  }
  return out;
}

/** A standard `lint` command for a rule set. */
export function lintCommand(opts: { name?: string; summary: string; toolName: string; title: string; rules: (flags: Flags) => Rule[]; examples?: string[]; extraFlags?: Command['flags'] }): Command {
  return {
    name: opts.name ?? 'lint',
    summary: opts.summary,
    args: '[paths…]',
    flags: { ...(opts.extraFlags ?? {}), ...LINT_FLAGS },
    examples: opts.examples,
    async run({ positionals, flags }, io) {
      const format = formatOf(flags.format);
      const threshold = failThreshold(flags['fail-on']);
      const rules = effectiveRules(opts.rules(flags), flags, io);
      const findings = await lintFiles(rules, positionals, io, !!flags.quiet);
      emit(io, renderFindings(format, io, { toolName: opts.toolName, title: opts.title, rules, findings }), flags.out);
      return exitFor(findings, threshold);
    },
  };
}
