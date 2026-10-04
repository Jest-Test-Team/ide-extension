import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parsePufCsv, parseSamples } from '../../src/entropy/parse';
import { blockFailureProbability, pufMetrics, requiredCorrection } from '../../src/entropy/puf';
import { restartTest } from '../../src/entropy/restart';
import { RESTART_VECTOR } from './vectors';

describe('restart test (SP 800-90B 3.1.4)', () => {
  it('matches NIST ea_restart row/column entropies and passes validation', () => {
    const ref = JSON.parse(readFileSync(join(__dirname, '../fixtures/entropy/nist-restart-reference.json'), 'utf8')) as {
      overall: { h_r: number; h_c: number };
    };
    const res = restartTest(RESTART_VECTOR.data(), RESTART_VECTOR.hI, { wordSize: RESTART_VECTOR.wordSize, simulationRounds: 20_000 });
    expect(Math.abs(res.hRow - ref.overall.h_r)).toBeLessThan(1e-9);
    expect(Math.abs(res.hCol - ref.overall.h_c)).toBeLessThan(1e-9);
    expect(res.sanityPassed).toBe(true);
    expect(res.passed).toBe(true);
  }, 120_000);

  it('fails the sanity check when restarts repeat', () => {
    const rows = 100;
    const cols = 100;
    const data = new Uint8Array(rows * cols);
    for (let j = 0; j < cols; j++) {
      const v = (j * 7 + (j >> 2)) & 1;
      for (let i = 0; i < rows; i++) {
        data[i * cols + j] = v; // every restart produces the same sequence
      }
    }
    // X_max = rows (a column is constant), far above the cutoff for H_I = 0.9.
    const res = restartTest(data, 0.9, { rows, cols, wordSize: 1, simulationRounds: 5_000 });
    expect(res.xMax).toBe(rows);
    expect(res.sanityPassed).toBe(false);
    expect(res.passed).toBe(false);
  });

  it('validates its input shape', () => {
    expect(() => restartTest(new Uint8Array(10), 1)).toThrow(/1000000/);
  });
});

describe('PUF metrics', () => {
  const csv = `device,read,response
A,0,11110000
A,1,11110001
B,0,00001111
B,1,00001111
C,0,10101010
`;

  it('computes uniformity, uniqueness, reliability and aliasing', () => {
    const r = pufMetrics(parsePufCsv(csv));
    expect(r.devices).toBe(3);
    expect(r.bits).toBe(8);
    // Inter-device HD of references: A-B 8/8, A-C 4/8, B-C 4/8.
    expect(r.uniqueness).toBeCloseTo((1 + 0.5 + 0.5) / 3, 12);
    // Intra-device: A flips 1 of 8 bits, B none.
    expect(r.bitErrorRate).toBeCloseTo((1 / 8 + 0) / 2, 12);
    expect(r.reliability).toBeCloseTo(1 - 1 / 16, 12);
    expect(r.uniformity.mean).toBeCloseTo((4 + 5 + 4 + 4 + 4) / 8 / 5, 12);
    expect(r.unstableBitFraction).toBeCloseTo((1 / 8 + 0 + 0) / 3, 12);
    expect(r.warnings.some((w) => w.includes('3 device'))).toBe(true);
  });

  it('parses hex responses and implicit read numbers', () => {
    const r = parsePufCsv('device,response\nx,0xF0\nx,f1\n');
    expect(r.map((x) => x.read)).toEqual([0, 1]);
    expect(Array.from(r[1].bits)).toEqual([1, 1, 1, 1, 0, 0, 0, 1]);
  });

  it('models ECC block failure for a bit error rate', () => {
    expect(blockFailureProbability(10, 10, 0.3)).toBe(0);
    expect(blockFailureProbability(1, 0, 0.1)).toBeCloseTo(0.1, 12);
    // P(>1 error in 3 bits at p=0.5) = 4/8
    expect(blockFailureProbability(3, 1, 0.5)).toBeCloseTo(0.5, 12);
    const t = requiredCorrection(255, 0.05, 1e-6)!;
    expect(blockFailureProbability(255, t, 0.05)).toBeLessThanOrEqual(1e-6);
    expect(blockFailureProbability(255, t - 1, 0.05)).toBeGreaterThan(1e-6);
  });
});

describe('sample parsing', () => {
  it('reads binary files byte-wise and text files as integers', () => {
    expect(Array.from(parseSamples('a.bin', Uint8Array.from([1, 2, 255])))).toEqual([1, 2, 255]);
    expect(Array.from(parseSamples('a.txt', new TextEncoder().encode('1, 2\n0x0f 255')))).toEqual([1, 2, 15, 255]);
    expect(() => parseSamples('a.csv', new TextEncoder().encode('1,256'))).toThrow(/0\.\.255/);
  });
});
