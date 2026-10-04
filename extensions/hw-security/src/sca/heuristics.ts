import type { CustomRule, Finding, RuleContext } from '@ide-ext/core';
import { calls, descendants, functionDefs } from '../cast';

const CRYPTO_FN = /(aes|des|sm4|chacha|encrypt|decrypt|cipher|crypt|sign|verify|ecdsa|ecdh|rsa|hmac|mac|kdf|keyexp|key_?sched|sbox|subbytes|mixcol|modexp|scalar_?mul|ladder)/i;
const SECRET_ID = /^(key|k|sk|secret|priv\w*|round_?key\w*|rk|subkey|nonce_?secret|scalar|exponent|d|state|st)$|(_key|key_|secret)/i;
const TAG = /@sca\s*\(/;

const ref = {
  label: 'NewAE ChipWhisperer documentation',
  url: 'https://chipwhisperer.readthedocs.io/',
};
const ct = { label: 'BearSSL — Constant-time crypto', url: 'https://www.bearssl.org/constanttime.html' };

/**
 * Suggests @sca tags for secret-dependent table lookups and branches inside crypto-looking
 * functions that carry no tag yet — the usual first-order leakage points targeted by power/EM
 * analysis (e.g. AES S-box lookups indexed by key ⊕ plaintext, square-and-multiply branches).
 */
export const scaCandidate: CustomRule = {
  kind: 'custom',
  id: 'sca/untagged-leak-candidate',
  title: 'Possible side-channel leak (untagged)',
  description:
    'Table lookups indexed by key material and branches on secret values have data-dependent timing and power consumption. Tag them with `@sca(id, "…")` so ChipWhisperer analysis scripts can reference them with `@sca-ref(id)`, or make the code constant-time.',
  severity: 'hint',
  languages: ['c', 'cpp'],
  message: '',
  refs: [ref, ct],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const out: Finding[] = [];
    for (const fn of functionDefs(ctx.tree.rootNode)) {
      if (!CRYPTO_FN.test(fn.name) || TAG.test(fn.node.text)) {
        continue;
      }
      // Comments immediately above the function count as tagging it.
      const above = ctx.lines.lineText(Math.max(0, ctx.lines.positionAt(fn.node.startIndex).line - 1));
      if (TAG.test(above)) {
        continue;
      }
      const secretIn = (n: { text: string; descendantsOfType: (t: string) => ({ text: string } | null)[] }) =>
        n.descendantsOfType('identifier').some((i) => i && SECRET_ID.test(i.text));
      for (const sub of descendants(fn.body, 'subscript_expression')) {
        const index = sub.childForFieldName('index') ?? sub.namedChildren.at(-1);
        if (index && secretIn(index)) {
          out.push(ctx.report(sub, `Table lookup \`${sub.text}\` in \`${fn.name}\` is indexed by secret-derived data (cache/power leakage). Tag it with @sca or use a constant-time implementation.`));
          break;
        }
      }
      for (const ifs of descendants(fn.body, 'if_statement')) {
        const cond = ifs.childForFieldName('condition');
        if (cond && secretIn(cond)) {
          out.push(ctx.report(cond, `Branch on secret-dependent value in \`${fn.name}\` (timing/power leakage). Tag it with @sca or make it branch-free.`));
          break;
        }
      }
      // Early-exit comparisons of secrets (memcmp on MACs/keys).
      for (const c of calls(fn.body)) {
        if (/^(memcmp|strcmp|strncmp)$/.test(c.name) && c.args.some((a) => SECRET_ID.test(a.text) || /mac|tag|digest|hash/i.test(a.text))) {
          out.push(ctx.report(c.node, `\`${c.name}\` returns early on the first mismatch; compare secrets with a constant-time function.`));
          break;
        }
      }
    }
    return out;
  },
};
