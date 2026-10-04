import { describe, expect, it } from 'vitest';
import { luhn, parseRulePack, scanTags, TagIndex, toSarif, LineIndex } from '../src';

describe('parseRulePack', () => {
  it('keeps valid rules and reports invalid ones', () => {
    const { pack, errors } = parseRulePack(
      `id: demo
title: Demo
rules:
  - id: ok
    title: ok
    severity: warning
    languages: [c]
    message: m
    query: "(identifier) @match"
  - id: bad
    title: bad
    severity: fatal
    languages: [c]
    message: m
  - id: re
    kind: pattern
    title: r
    severity: info
    languages: ["*"]
    message: m
    pattern: "(["
`,
      'demo.yaml',
    );
    expect(pack?.rules.map((r) => r.id)).toEqual(['ok']);
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain('severity');
    expect(errors[1]).toContain('not a valid regex');
  });
});

describe('luhn', () => {
  it('validates card numbers', () => {
    expect(luhn('4111 1111 1111 1111')).toBe(true);
    expect(luhn('4111111111111112')).toBe(false);
    expect(luhn('1234')).toBe(false);
  });
});

describe('tags', () => {
  it('scans definitions and references', () => {
    const text = '// @sca(aes-sbox, "S-box lookup")\nx = 1 # @sca-ref(aes-sbox)\n';
    const tags = scanTags('u', text, ['sca', 'sca-ref']);
    expect(tags.map((t) => [t.tag, t.id, t.description, t.line])).toEqual([
      ['sca', 'aes-sbox', 'S-box lookup', 0],
      ['sca-ref', 'aes-sbox', undefined, 1],
    ]);
    expect(tags[0].range.start.character).toBe(8);
    const index = new TagIndex(['sca', 'sca-ref']);
    index.update('u', text);
    expect(index.find('aes-sbox', 'sca')).toHaveLength(1);
    expect(index.at('u', 1, 18)?.tag).toBe('sca-ref');
  });
});

describe('LineIndex', () => {
  it('round-trips offsets', () => {
    const li = new LineIndex('ab\r\ncd\nef');
    expect(li.positionAt(4)).toEqual({ line: 1, character: 0 });
    expect(li.offsetAt({ line: 2, character: 1 })).toBe(8);
    expect(li.lineText(0)).toBe('ab');
  });
});

describe('toSarif', () => {
  it('emits 1-based regions', () => {
    const log = toSarif({
      toolName: 't',
      toolVersion: '1',
      rules: [{ id: 'r', title: 'R', severity: 'error', languages: ['c'], message: 'm', query: '' }],
      findings: new Map([['a.c', [{ ruleId: 'r', severity: 'error', message: 'm', refs: [], range: { start: { line: 0, character: 0 }, end: { line: 0, character: 3 } } }]]]),
    }) as { runs: { results: { locations: { physicalLocation: { region: { startLine: number } } }[] }[] }[] };
    expect(log.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);
  });
});
