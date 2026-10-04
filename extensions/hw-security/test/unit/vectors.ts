// Deterministic datasets for validating the SP 800-90B port against NIST's ea_non_iid.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const N = 100_000;

function gen(seed: number, n: number, next: (rnd: () => number, i: number, prev: number) => number): Uint8Array {
  const rnd = mulberry32(seed);
  const out = new Uint8Array(n);
  let prev = 0;
  for (let i = 0; i < n; i++) {
    prev = out[i] = next(rnd, i, prev);
  }
  return out;
}

export interface Vector {
  name: string;
  wordSize: number;
  data: () => Uint8Array;
}

const fixture = (f: string) => () => new Uint8Array(readFileSync(join(__dirname, '../fixtures/entropy', f)));

export const VECTORS: Vector[] = [
  { name: 'bits-uniform', wordSize: 1, data: () => gen(1, N, (r) => (r() < 0.5 ? 1 : 0)) },
  { name: 'bits-biased', wordSize: 1, data: () => gen(2, N, (r) => (r() < 0.7 ? 1 : 0)) },
  { name: 'bits-markov', wordSize: 1, data: () => gen(3, N, (r, i, p) => (i === 0 ? 0 : r() < 0.8 ? p : 1 - p)) },
  { name: 'bytes-uniform', wordSize: 8, data: () => gen(4, N, (r) => Math.floor(r() * 256)) },
  {
    name: 'nibbles-skewed',
    wordSize: 4,
    data: () => gen(5, N, (r) => Math.min(15, Math.floor(-Math.log(1 - r()) * 2.5))),
  },
  { name: 'bytes-random-walk', wordSize: 8, data: () => gen(6, N, (r, _i, p) => (p + Math.floor(r() * 5) - 2) & 0xff) },
  { name: 'small-alphabet', wordSize: 8, data: () => gen(7, N, (r) => [3, 17, 200][Math.floor(r() * 3)]) },
  {
    name: 'nibbles-periodic-noisy',
    wordSize: 4,
    data: () => gen(8, N, (r, i) => (r() < 0.05 ? Math.floor(r() * 16) : (i * 7 + (i % 5)) % 16)),
  },
  { name: 'nist-rand1_short', wordSize: 1, data: fixture('rand1_short.bin') },
  { name: 'nist-rand8_short', wordSize: 8, data: fixture('rand8_short.bin') },
];

/** 1000 restarts × 1000 samples of a 2-bit source whose most likely symbol has p ≈ 0.4. */
export const RESTART_VECTOR = {
  name: 'restart-2bit',
  wordSize: 2,
  hI: 1.2,
  data: () => gen(9, 1_000_000, (r) => {
    const x = r();
    return x < 0.4 ? 0 : x < 0.6 ? 1 : x < 0.8 ? 2 : 3;
  }),
};
