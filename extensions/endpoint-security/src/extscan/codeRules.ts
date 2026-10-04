import type { CustomRule, Finding, RuleContext } from '@ide-ext/core';

const OBF_REF = { label: 'MITRE ATT&CK T1027 — Obfuscated Files or Information', url: 'https://attack.mitre.org/techniques/T1027/' };

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s.length) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of s) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Identifiers javascript-obfuscator emits (`_0x3f2a1c`). Minifiers never produce these. */
const OBFUSCATOR_IDENT = /\b_0x[0-9a-f]{4,6}\b/g;
const OBFUSCATOR_MIN_HITS = 20;

/**
 * javascript-obfuscator output. Reported once per file, at the first identifier, with the count.
 */
export const obfuscatorMarkers: CustomRule = {
  kind: 'custom',
  id: 'ext/obfuscated.obfuscator',
  title: 'javascript-obfuscator output',
  severity: 'warning',
  languages: ['javascript'],
  message: 'javascript-obfuscator style identifiers ({{count}} × `_0x…`, e.g. `{{match}}`).',
  refs: [OBF_REF],
  when: '_0x[0-9a-f]{4}',
  check(ctx: RuleContext): Finding[] {
    const hits = [...ctx.text.matchAll(OBFUSCATOR_IDENT)];
    const distinct = new Set(hits.map((m) => m[0]));
    if (hits.length < OBFUSCATOR_MIN_HITS || distinct.size < 5) {
      return [];
    }
    const first = hits[0];
    const start = first.index ?? 0;
    return [ctx.report(ctx.lines.rangeOf(start, start + first[0].length), undefined, { match: first[0], count: String(hits.length) })];
  },
};

/** A long base64 / hex string literal. */
const BLOB = /(['"`])([A-Za-z0-9+/=_-]{400,}|(?:\\x[0-9a-fA-F]{2}){150,})\1/g;
/** Evaluation sinks that turn a decoded blob into code. */
const SINK = /\beval\s*\(|\bFunction\s*\(|\brunIn(?:New|This)?Context\s*\(|\bcompileFunction\s*\(/;
const SINK_WINDOW = 400;
export const BLOB_ENTROPY = 5.2;

/**
 * A high-entropy blob literal with a code-evaluation sink nearby: a packed payload. Bundled wasm
 * or images also embed base64, so the blob alone is not reported.
 */
export const packedPayload: CustomRule = {
  kind: 'custom',
  id: 'ext/obfuscated.packed-payload',
  title: 'Encoded payload evaluated at run time',
  severity: 'warning',
  languages: ['javascript'],
  message: 'A {{length}}-character encoded literal (entropy {{entropy}} bits/char) is next to code evaluation (`{{sink}}`).',
  refs: [OBF_REF],
  check(ctx: RuleContext): Finding[] {
    const out: Finding[] = [];
    for (const m of ctx.text.matchAll(BLOB)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      const body = m[2].startsWith('\\x') ? m[2].replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))) : m[2];
      const entropy = shannonEntropy(body);
      // Hex-escaped strings decode to arbitrary bytes; judge them by their decoded entropy too.
      if (entropy < (m[2].startsWith('\\x') ? 4.5 : BLOB_ENTROPY)) {
        continue;
      }
      const around = ctx.text.slice(Math.max(0, start - SINK_WINDOW), Math.min(ctx.text.length, end + SINK_WINDOW));
      const sink = SINK.exec(around);
      if (!sink) {
        continue;
      }
      out.push(
        ctx.report(ctx.lines.rangeOf(start, Math.min(end, start + 80)), undefined, {
          length: String(m[2].length),
          entropy: entropy.toFixed(2),
          sink: sink[0].replace(/\s*\($/, ''),
        }),
      );
    }
    return out;
  },
};

export const EXTSCAN_CUSTOM_RULES: CustomRule[] = [obfuscatorMarkers, packedPayload];
