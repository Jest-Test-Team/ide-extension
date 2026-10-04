import { describe, expect, it } from 'vitest';
import { RuleEngine, type Rule } from '../src';
import { testHost } from './grammars';

const doc = (languageId: string, text: string, path = `/w/file.${languageId}`) => ({
  uri: `file://${path}`,
  path,
  languageId,
  text,
});

describe('RuleEngine', () => {
  it('reports query matches with capture templating and a fix', async () => {
    const rules: Rule[] = [
      {
        id: 'no-strcpy',
        title: 'strcpy',
        severity: 'warning',
        languages: ['c'],
        message: 'avoid {{fn}}',
        query: '(call_expression function: (identifier) @fn (#eq? @fn "strcpy")) @match',
        capture: 'fn',
        fix: { title: 'use strlcpy', replacement: 'strlcpy' },
        refs: [{ label: 'CWE-120', url: 'https://cwe.mitre.org/data/definitions/120.html' }],
      },
    ];
    const engine = new RuleEngine(testHost(), rules);
    const out = await engine.run(doc('c', '// 註解\nvoid f(){ strcpy(a, b); }'));
    expect(out).toHaveLength(1);
    expect(out[0].message).toBe('avoid strcpy');
    expect(out[0].range).toEqual({ start: { line: 1, character: 10 }, end: { line: 1, character: 16 } });
    expect(out[0].fix?.edits[0].newText).toBe('strlcpy');
    expect(out[0].refs[0].label).toBe('CWE-120');
  });

  it('supports per-grammar queries and where constraints', async () => {
    const engine = new RuleEngine(testHost(), [
      {
        id: 'md5',
        title: 'md5',
        severity: 'error',
        languages: ['go', 'typescript'],
        message: 'weak hash {{name}}',
        query: {
          go: '(call_expression function: (selector_expression field: (field_identifier) @name)) @match',
          typescript: '(call_expression function: (member_expression property: (property_identifier) @name)) @match',
        },
        where: { name: { matches: '^(New|Sum)$|^createHash$' } },
      },
    ]);
    expect(await engine.run(doc('go', 'package m\nfunc f(){ md5.Sum(b); x.Other() }'))).toHaveLength(1);
    expect(await engine.run(doc('typescript', 'crypto.createHash("md5"); a.b();'))).toHaveLength(1);
  });

  it('runs pattern rules with validators', async () => {
    const engine = new RuleEngine(testHost(), [
      {
        kind: 'pattern',
        id: 'pan',
        title: 'pan',
        severity: 'error',
        languages: ['*'],
        message: 'PAN literal {{value}}',
        pattern: '\\b(?<value>\\d{13,19})\\b',
        validate: 'luhn',
      },
    ]);
    const out = await engine.run(doc('go', 'a := "4111111111111111"; b := "4111111111111112"'));
    expect(out.map((f) => f.message)).toEqual(['PAN literal 4111111111111111']);
  });

  it('runs absent rules anchored and filtered by path', async () => {
    const rule: Rule = {
      kind: 'absent',
      id: 'secure-boot',
      title: 'secure boot',
      severity: 'warning',
      languages: ['*'],
      pathPattern: '(^|/)sdkconfig$',
      message: 'secure boot disabled',
      pattern: '^CONFIG_SECURE_BOOT=y$',
      anchor: '^# CONFIG_SECURE_BOOT is not set$',
    };
    const engine = new RuleEngine(testHost(), [rule]);
    const bad = await engine.run(doc('plaintext', 'A=1\n# CONFIG_SECURE_BOOT is not set\n', '/w/sdkconfig'));
    expect(bad).toHaveLength(1);
    expect(bad[0].range.start.line).toBe(1);
    expect(await engine.run(doc('plaintext', 'CONFIG_SECURE_BOOT=y\n', '/w/sdkconfig'))).toHaveLength(0);
    expect(await engine.run(doc('plaintext', 'A=1\n', '/w/other.txt'))).toHaveLength(0);
  });

  it('honours unless and suppression comments', async () => {
    const base = {
      id: 'new-client',
      title: 'client',
      severity: 'warning' as const,
      languages: ['c'],
      message: 'leak',
      query: '(call_expression function: (identifier) @f (#eq? @f "es_new_client")) @match',
      unless: 'es_delete_client',
    };
    const engine = new RuleEngine(testHost(), [base]);
    expect(await engine.run(doc('c', 'void f(){ es_new_client(&c, h); }'))).toHaveLength(1);
    expect(await engine.run(doc('c', 'void f(){ es_new_client(&c, h); es_delete_client(c); }'))).toHaveLength(0);
    const suppressed = 'void f(){\n// ide-ext-ignore-next-line new-client\nes_new_client(&c, h);\n}';
    expect(await engine.run(doc('c', suppressed))).toHaveLength(0);
  });

  it('runs rules only when their `when` regex matches', async () => {
    const engine = new RuleEngine(testHost(), [
      { kind: 'pattern', id: 'pw', title: 'pw', severity: 'warning', languages: ['yaml'], message: 'm', pattern: 'password: \\w+', when: '^esphome:' },
    ]);
    expect(await engine.run(doc('yaml', 'esphome:\n  name: x\nwifi:\n  password: abc\n'))).toHaveLength(1);
    expect(await engine.run(doc('yaml', 'db:\n  password: abc\n'))).toHaveLength(0);
  });

  it('suppresses namespaced rule ids (with a slash)', async () => {
    const rule = { kind: 'pattern' as const, id: 'esp32/bad', title: 'x', severity: 'warning' as const, languages: ['*'], message: 'm', pattern: 'BAD' };
    const engine = new RuleEngine(testHost(), [rule]);
    expect(await engine.run(doc('c', '// ide-ext-ignore-next-line esp32/bad\nBAD\nBAD\n', '/w/s.c'))).toHaveLength(1);
    expect(await engine.run(doc('c', 'BAD // ide-ext-ignore esp32/bad\n', '/w/t.c'))).toHaveLength(0);
    expect(await engine.run(doc('c', '// ide-ext-ignore-file esp32/bad\nBAD\nBAD\n', '/w/u.c'))).toHaveLength(0);
  });

  it('supports file-level suppression and excluded paths', async () => {
    const rule = { kind: 'pattern' as const, id: 'x', title: 'x', severity: 'warning' as const, languages: ['*'], message: 'm', pattern: 'BAD' };
    const engine = new RuleEngine(testHost(), [rule, { ...rule, id: 'y' }, { ...rule, id: 'z', excludePathPattern: '\\.test\\.ts$' }]);
    const text = '// ide-ext-ignore-file x\nBAD\n';
    expect((await engine.run(doc('typescript', text, '/w/a.ts'))).map((f) => f.ruleId)).toEqual(['y', 'z']);
    expect((await engine.run(doc('typescript', text, '/w/a.test.ts'))).map((f) => f.ruleId)).toEqual(['y']);
    expect(await engine.run(doc('typescript', '// ide-ext-ignore-file *\nBAD', '/w/b.ts'))).toEqual([]);
  });

  it('isolates a failing custom rule', async () => {
    const engine = new RuleEngine(testHost(), [
      { kind: 'custom', id: 'boom', title: 'b', severity: 'error', languages: ['c'], message: '', check: () => { throw new Error('x'); } },
    ]);
    const out = await engine.run(doc('c', 'int a;'));
    expect(out[0].severity).toBe('hint');
    expect(out[0].message).toContain('boom');
  });
});
