/**
 * SP 800-90B section 3.1.4 restart tests: a sanity check on the most-common-value counts of the
 * restart matrix (rows = restarts, columns = sample index), then the non-IID estimators on the
 * row-wise and column-wise datasets. Ported from NIST's restart_main.cpp.
 */
import {
  collision,
  compression,
  lag,
  lz78y,
  markov,
  mostCommonValue,
  multiMcw,
  multiMmc,
  prepareDataset,
  tTupleAndLrs,
} from './sp80090b';

export interface RestartResult {
  rows: number;
  cols: number;
  hI: number;
  xMax: number;
  xCutoff: number;
  sanityPassed: boolean;
  hRow: number;
  hCol: number;
  passed: boolean;
  simulationRounds: number;
}

/** xoshiro128** — deterministic so reports are reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0 || 1;
  let b = 0x9e3779b9;
  let c = 0x243f6a88;
  let d = 0xb7e15162;
  return () => {
    const t = b << 9;
    let r = Math.imul(b, 5);
    r = Math.imul((r << 7) | (r >>> 25), 9);
    c ^= a;
    d ^= b;
    b ^= c;
    a ^= d;
    c ^= t;
    d = (d << 11) | (d >>> 21);
    return (r >>> 0) / 4294967296;
  };
}

/** Monte-Carlo upper bound on the max symbol count in `n` samples (simulateBound; NIST uses n = 1000). */
export function simulateBound(alpha: number, k: number, hI: number, rounds: number, n = 1000, seed = 1): number {
  const p = Math.pow(2, -hI);
  const kEff = Math.ceil(1 / p);
  if (kEff > k) {
    throw new Error(`H_I = ${hI} implies ${kEff} symbols but the data has only ${k}`);
  }
  const rnd = rng(seed);
  const results = new Uint16Array(rounds);
  const counts = new Uint16Array(257);
  for (let i = 0; i < rounds; i++) {
    counts.fill(0);
    for (let j = 0; j < n; j++) {
      counts[Math.floor(rnd() / p)]++;
    }
    let max = 0;
    for (let j = 0; j < kEff; j++) {
      max = Math.max(max, counts[j]);
    }
    results[i] = max;
  }
  results.sort();
  return results[Math.floor((1 - alpha) * rounds) - 1];
}

function literalMin(data: Uint8Array, k: number, wordSize: number): number {
  const ests: number[] = [mostCommonValue(data, k)];
  if (k === 2) {
    ests.push(collision(data), markov(data));
    const c = compression(data);
    if (c >= 0) {
      ests.push(c);
    }
  }
  const t = tTupleAndLrs(data);
  if (t.tTuple >= 0) {
    ests.push(t.tTuple);
  }
  if (t.lrs >= 0) {
    ests.push(t.lrs);
  }
  for (const r of [multiMcw(data, k), lag(data, k), multiMmc(data, k), lz78y(data, k)]) {
    if (r) {
      ests.push(r.entropy);
    }
  }
  return Math.min(wordSize, ...ests);
}

/**
 * @param raw restart data in row-major order: rows × cols samples (SP 800-90B uses 1000 × 1000)
 * @param hI the initial entropy estimate (bits per sample) being validated
 */
export function restartTest(raw: Uint8Array, hI: number, opts: { rows?: number; cols?: number; wordSize?: number; simulationRounds?: number } = {}): RestartResult {
  const rows = opts.rows ?? 1000;
  const cols = opts.cols ?? 1000;
  if (rows !== cols) {
    throw new Error('The restart matrix must be square (SP 800-90B uses 1000 × 1000).');
  }
  if (raw.length !== rows * cols) {
    throw new Error(`Restart data must contain ${rows} × ${cols} = ${rows * cols} samples (got ${raw.length}).`);
  }
  const ds = prepareDataset(raw, opts.wordSize ?? 0);
  if (hI < 0 || hI > ds.wordSize) {
    throw new Error(`H_I must be between 0 and ${ds.wordSize}.`);
  }
  const rdata = ds.symbols;
  const cdata = new Uint8Array(rdata.length);
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      cdata[j * rows + i] = rdata[i * cols + j];
    }
  }
  const maxCount = (data: Uint8Array, outer: number, inner: number) => {
    let best = 0;
    const counts = new Int32Array(256);
    for (let o = 0; o < outer; o++) {
      counts.fill(0);
      for (let x = 0; x < inner; x++) {
        best = Math.max(best, ++counts[data[o * inner + x]]);
      }
    }
    return best;
  };
  const xMax = Math.max(maxCount(rdata, rows, cols), maxCount(cdata, cols, rows));
  const alpha = 1 - Math.exp(Math.log(0.99) / (rows + cols));
  const rounds = opts.simulationRounds ?? 200_000;
  const xCutoff = simulateBound(alpha, ds.alphSize, hI, rounds, cols);
  const sanityPassed = xMax <= xCutoff;
  const hRow = literalMin(rdata, ds.alphSize, ds.wordSize);
  const hCol = literalMin(cdata, ds.alphSize, ds.wordSize);
  return {
    rows,
    cols,
    hI,
    xMax,
    xCutoff,
    sanityPassed,
    hRow,
    hCol,
    passed: sanityPassed && Math.min(hRow, hCol) >= hI / 2,
    simulationRounds: rounds,
  };
}
