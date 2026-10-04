import { parseRulePack, type Rule, type RulePack } from '@ide-ext/core';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Loads the bundled declarative packs (data/rules → dist/rules). Throws on invalid built-in rules. */
export function loadBuiltInPacks(dir: string): RulePack[] {
  return readdirSync(dir)
    .filter((f) => /\.(ya?ml|json)$/.test(f))
    .sort()
    .map((f) => {
      const res = parseRulePack(readFileSync(join(dir, f), 'utf8'), f);
      if (res.errors.length || !res.pack) {
        throw new Error(`Invalid built-in rule pack ${f}:\n${res.errors.join('\n')}`);
      }
      return res.pack;
    });
}

export const rulesOf = (packs: RulePack[]): Rule[] => packs.flatMap((p) => p.rules);
