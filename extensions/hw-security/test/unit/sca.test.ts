import { RuleEngine, scanTags } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { scaCandidate } from '../../src/sca/heuristics';

const fx = (p: string) => readFileSync(join(__dirname, '../fixtures/sca', p), 'utf8');

describe('side-channel candidates', () => {
  it('flags untagged secret-dependent branches and early-exit compares, not tagged code', async () => {
    const engine = new RuleEngine(testHost(), [scaCandidate]);
    const out = await engine.run({ uri: 'file:///aes.c', path: '/aes.c', languageId: 'c', text: fx('firmware/aes.c') });
    const lines = out.map((f) => [f.range.start.line + 1, f.message.split(' ')[0]]);
    expect(lines).toEqual([
      [19, 'Branch'],
      [27, '`memcmp`'],
    ]);
  });

  it('indexes definitions and references across languages', () => {
    const defs = scanTags('c', fx('firmware/aes.c'), ['sca', 'sca-ref']);
    const refs = scanTags('py', fx('analysis/cpa_attack.py'), ['sca', 'sca-ref']);
    expect(defs.map((t) => [t.tag, t.id, t.line + 1])).toEqual([['sca', 'aes-sbox', 9]]);
    expect(defs[0].description).toContain('S-box');
    expect(refs.map((t) => [t.tag, t.id])).toEqual([
      ['sca-ref', 'aes-sbox'],
      ['sca-ref', 'modexp-branch'],
    ]);
  });
});
