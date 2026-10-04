import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { nonIidAssessment, prepareDataset, relEpsilonEqual, tupleStats } from '../../src/entropy/sp80090b';
import { VECTORS } from './vectors';

type Ref = { wordSize: number; literal: Record<string, number>; bitstring: Record<string, number>; hOriginal?: number; hBitstring?: number; hAssessed: number };
const REF = JSON.parse(readFileSync(join(__dirname, '../fixtures/entropy/nist-reference.json'), 'utf8')) as Record<string, Ref>;

// NIST uses long double in a few places (t-tuple/LRS powers, the prediction-estimate root
// finding); everything else is plain double. Agreement to 1e-9 relative is expected.
const close = (a: number | undefined, b: number | undefined) => {
  expect(a).toBeDefined();
  expect(Math.abs(a! - b!)).toBeLessThanOrEqual(1e-9 * Math.max(1, Math.abs(b!)));
};

describe('SP 800-90B non-IID estimators match NIST ea_non_iid', () => {
  for (const v of VECTORS) {
    it(v.name, () => {
      const ref = REF[v.name];
      const res = nonIidAssessment(v.data(), { wordSize: v.wordSize });
      for (const [id, value] of Object.entries(ref.literal)) {
        close(res.literal[id as keyof typeof res.literal], value);
      }
      for (const [id, value] of Object.entries(ref.bitstring)) {
        close(res.bitstring[id as keyof typeof res.bitstring], value);
      }
      expect(Object.keys(res.literal).sort()).toEqual(Object.keys(ref.literal).sort());
      expect(Object.keys(res.bitstring).sort()).toEqual(Object.keys(ref.bitstring).sort());
      close(res.hAssessed, ref.hAssessed);
    }, 60_000);
  }
});

describe('tuple statistics', () => {
  const brute = (s: Uint8Array, w: number) => {
    const counts = new Map<string, number>();
    for (let i = 0; i + w <= s.length; i++) {
      const k = Array.from(s.subarray(i, i + w)).join(',');
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    let q = 0;
    let pairs = 0;
    for (const c of counts.values()) {
      q = Math.max(q, c);
      pairs += (c * (c - 1)) / 2;
    }
    return { q, pairs };
  };

  it('match brute force on random and repetitive strings', () => {
    let seed = 7;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const cases = [
      Uint8Array.from({ length: 300 }, () => (rnd() < 0.5 ? 0 : 1)),
      Uint8Array.from({ length: 200 }, () => Math.floor(rnd() * 4)),
      Uint8Array.from({ length: 120 }, (_, i) => i % 7),
      new Uint8Array(64),
    ];
    for (const s of cases) {
      const { v, Q, S } = tupleStats(s);
      for (let w = 1; w <= v; w++) {
        const b = brute(s, w);
        expect(Q[w]).toBe(b.q);
        expect(S[w]).toBe(b.pairs);
      }
      expect(brute(s, v + 1).pairs).toBe(0);
    }
  });
});

describe('dataset preparation', () => {
  it('infers word size, maps down symbols and builds the bitstring', () => {
    const ds = prepareDataset(Uint8Array.from([3, 17, 200, 3]));
    expect(ds.wordSize).toBe(8);
    expect(ds.alphSize).toBe(3);
    expect(Array.from(ds.symbols)).toEqual([0, 1, 2, 0]);
    expect(Array.from(ds.bits.subarray(0, 8))).toEqual([0, 0, 0, 0, 0, 0, 1, 1]);
  });

  it('rejects single-symbol data', () => {
    expect(() => nonIidAssessment(new Uint8Array(100).fill(1))).toThrow(/1 symbol/);
  });

  it('compares floats like NIST', () => {
    expect(relEpsilonEqual(1, 1 + 2.220446049250313e-16)).toBe(true);
    expect(relEpsilonEqual(1, 1.0001)).toBe(false);
  });
});
