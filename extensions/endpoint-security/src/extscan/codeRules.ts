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

/**
 * High-entropy encoded literals with no evaluation sink nearby (packed-payload covers those).
 * Reported once per file with the count; bundled fonts or wasm also trip this, hence a low weight.
 */
export const encodedBlob: CustomRule = {
  kind: 'custom',
  id: 'ext/encoded-blob.literal',
  title: 'Long encoded literal',
  severity: 'info',
  languages: ['javascript'],
  message: '{{count}} encoded literal(s), the first {{length}} characters long (entropy {{entropy}} bits/char).',
  refs: [OBF_REF],
  check(ctx: RuleContext): Finding[] {
    let first: { start: number; end: number; length: number; entropy: number } | undefined;
    let count = 0;
    for (const m of ctx.text.matchAll(BLOB)) {
      if (m[2].startsWith('\\x')) {
        continue;
      }
      const entropy = shannonEntropy(m[2]);
      if (entropy < BLOB_ENTROPY) {
        continue;
      }
      const start = m.index ?? 0;
      const around = ctx.text.slice(Math.max(0, start - SINK_WINDOW), Math.min(ctx.text.length, start + m[0].length + SINK_WINDOW));
      if (SINK.test(around)) {
        continue; // reported by packed-payload
      }
      count++;
      first ??= { start, end: start + Math.min(m[0].length, 80), length: m[2].length, entropy };
    }
    if (!first) {
      return [];
    }
    return [ctx.report(ctx.lines.rangeOf(first.start, first.end), undefined, { count: String(count), length: String(first.length), entropy: first.entropy.toFixed(2) })];
  },
};

/** Literals without whitespace, long enough for entropy to mean something. */
const LONG_LITERAL = /(['"`])([^'"`\s\\]{128,})\1/g;
/** Embedded images, fonts and wasm: legitimately random-looking. */
const KNOWN_BLOB_PREFIXES = ['iVBOR', 'R0lGOD', '/9j/', 'AGFzbQ', 'd09GR', 'T1RUTw', 'AAEAAA', 'PHN2Zy', 'data:', 'sha256-', 'sha384-', 'sha512-'];
export const HIGH_ENTROPY = 5.8;

/** Literals with Shannon entropy above 5.8 bits/char: compressed, encrypted or encoded payloads. */
export const highEntropyString: CustomRule = {
  kind: 'custom',
  id: 'ext/high-entropy-string.literal',
  title: 'High-entropy literal',
  severity: 'info',
  languages: ['javascript'],
  message: '{{count}} literal(s) above {{threshold}} bits/char, the first {{length}} characters at {{entropy}}.',
  refs: [OBF_REF],
  check(ctx: RuleContext): Finding[] {
    let first: { start: number; length: number; entropy: number } | undefined;
    let count = 0;
    for (const m of ctx.text.matchAll(LONG_LITERAL)) {
      if (KNOWN_BLOB_PREFIXES.some((p) => m[2].startsWith(p))) {
        continue;
      }
      const entropy = shannonEntropy(m[2]);
      if (entropy <= HIGH_ENTROPY) {
        continue;
      }
      count++;
      first ??= { start: m.index ?? 0, length: m[2].length, entropy };
    }
    if (!first) {
      return [];
    }
    return [
      ctx.report(ctx.lines.rangeOf(first.start, first.start + Math.min(first.length, 80)), undefined, {
        count: String(count),
        threshold: String(HIGH_ENTROPY),
        length: String(first.length),
        entropy: first.entropy.toFixed(2),
      }),
    ];
  },
};

const ESC = '(?:\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4})';
/** A literal opening with 40+ consecutive escapes. */
const ESCAPE_RUN = new RegExp(`['"\`]${ESC}{40,}`, 'g');
/** A short literal made only of escapes (javascript-obfuscator string arrays). */
const ESCAPED_LITERAL = new RegExp(`(['"])${ESC}{4,}\\1`, 'g');
const ESCAPED_LITERALS_MIN = 150;
/** JSFuck: code written with only []()!+ */
const JSFUCK = /[[\]()!+]{500,}/;

/** Dense hex / unicode escapes or JSFuck: text hidden from readers and naive scanners. */
export const escapeDensity: CustomRule = {
  kind: 'custom',
  id: 'ext/hex-or-unicode-escape-density.literal',
  title: 'Dense hex / unicode escapes',
  severity: 'warning',
  languages: ['javascript'],
  message: '{{what}}',
  refs: [OBF_REF],
  when: '\\\\[xu][0-9a-fA-F]|[[\\]()!+]{500}',
  check(ctx: RuleContext): Finding[] {
    const run = ESCAPE_RUN.exec(ctx.text);
    ESCAPE_RUN.lastIndex = 0;
    if (run) {
      const n = run[0].match(/\\[xu]/g)?.length ?? 0;
      return [ctx.report(ctx.lines.rangeOf(run.index, run.index + Math.min(run[0].length, 80)), undefined, { what: `A string literal opens with ${n}+ consecutive hex / unicode escapes.` })];
    }
    const literals = [...ctx.text.matchAll(ESCAPED_LITERAL)];
    if (literals.length >= ESCAPED_LITERALS_MIN) {
      const at = literals[0].index ?? 0;
      return [ctx.report(ctx.lines.rangeOf(at, at + Math.min(literals[0][0].length, 80)), undefined, { what: `${literals.length} string literals consist only of hex / unicode escapes.` })];
    }
    const fuck = JSFUCK.exec(ctx.text);
    if (fuck) {
      return [ctx.report(ctx.lines.rangeOf(fuck.index, fuck.index + 80), undefined, { what: `${fuck[0].length} characters written only with []()!+ (JSFuck).` })];
    }
    return [];
  },
};

export const EXTSCAN_CUSTOM_RULES: CustomRule[] = [obfuscatorMarkers, packedPayload, encodedBlob, highEntropyString, escapeDensity];
