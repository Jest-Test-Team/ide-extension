/**
 * PUF quality metrics (Maiti, Gunreddy & Schaumont, "A Systematic Method to Evaluate and Compare
 * the Performance of Physical Unclonable Functions", 2013) for SRAM or quantum-tunnelling PUFs.
 */

export interface PufReading {
  device: string;
  /** Measurement index; read 0 (or the first seen) is the enrolment reference. */
  read: number;
  bits: Uint8Array;
}

export interface PufReport {
  devices: number;
  readsPerDevice: number;
  bits: number;
  /** Mean fraction of 1s per response (ideal 50 %). */
  uniformity: { mean: number; min: number; max: number };
  /** Mean inter-device fractional Hamming distance of reference responses (ideal 50 %). */
  uniqueness: number;
  /** 1 − mean intra-device fractional HD vs. the reference (ideal 100 %). */
  reliability: number;
  /** Mean intra-device bit error rate (= 1 − reliability). */
  bitErrorRate: number;
  /** Per-bit-position fraction of devices whose reference bit is 1 (ideal 50 %). */
  bitAliasing: { mean: number; worst: { index: number; value: number }[] };
  /** Average per-bit min-entropy across devices: mean over bits of −log2(max(p, 1 − p)). */
  minEntropyPerBit: number;
  interHd: number[];
  intraHd: number[];
  /** Positions whose value flipped at least once across reads, per device (unstable cells). */
  unstableBitFraction: number;
  warnings: string[];
}

const popcount = (bits: Uint8Array) => bits.reduce((n, b) => n + b, 0);

function hd(a: Uint8Array, b: Uint8Array): number {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    d += a[i] ^ b[i];
  }
  return d / a.length;
}

export function pufMetrics(readings: PufReading[]): PufReport {
  if (!readings.length) {
    throw new Error('No PUF responses found.');
  }
  const n = readings[0].bits.length;
  if (readings.some((r) => r.bits.length !== n)) {
    throw new Error('All PUF responses must have the same length.');
  }
  const warnings: string[] = [];
  const byDevice = new Map<string, PufReading[]>();
  for (const r of readings) {
    byDevice.set(r.device, [...(byDevice.get(r.device) ?? []), r]);
  }
  for (const list of byDevice.values()) {
    list.sort((a, b) => a.read - b.read);
  }
  const refs = [...byDevice.values()].map((l) => l[0].bits);
  const uni = readings.map((r) => popcount(r.bits) / n);

  const interHd: number[] = [];
  for (let i = 0; i < refs.length; i++) {
    for (let j = i + 1; j < refs.length; j++) {
      interHd.push(hd(refs[i], refs[j]));
    }
  }
  const intraHd: number[] = [];
  let unstable = 0;
  for (const list of byDevice.values()) {
    const flipped = new Uint8Array(n);
    for (const r of list.slice(1)) {
      intraHd.push(hd(list[0].bits, r.bits));
      for (let b = 0; b < n; b++) {
        flipped[b] |= list[0].bits[b] ^ r.bits[b];
      }
    }
    unstable += popcount(flipped) / n;
  }
  const aliasing = Array.from({ length: n }, (_, b) => refs.reduce((s, r) => s + r[b], 0) / refs.length);
  const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN);
  const minEntropy = mean(aliasing.map((p) => -Math.log2(Math.max(p, 1 - p))));
  if (refs.length < 2) {
    warnings.push('Uniqueness and bit-aliasing need responses from at least two devices.');
  }
  if (!intraHd.length) {
    warnings.push('Reliability needs at least two reads of the same device.');
  }
  if (refs.length < 10) {
    warnings.push(`Only ${refs.length} device(s): bit-aliasing and min-entropy have high variance.`);
  }
  const ber = mean(intraHd);
  return {
    devices: refs.length,
    readsPerDevice: Math.round(readings.length / refs.length),
    bits: n,
    uniformity: { mean: mean(uni), min: Math.min(...uni), max: Math.max(...uni) },
    uniqueness: mean(interHd),
    reliability: 1 - ber,
    bitErrorRate: ber,
    bitAliasing: {
      mean: mean(aliasing),
      worst: aliasing
        .map((value, index) => ({ index, value }))
        .sort((a, b) => Math.abs(b.value - 0.5) - Math.abs(a.value - 0.5))
        .slice(0, 10),
    },
    minEntropyPerBit: minEntropy,
    interHd,
    intraHd,
    unstableBitFraction: unstable / byDevice.size,
    warnings,
  };
}

/** log of the binomial coefficient, via lgamma-free summation (n ≤ a few thousand). */
function logChoose(n: number, k: number): number {
  let s = 0;
  for (let i = 1; i <= k; i++) {
    s += Math.log(n - k + i) - Math.log(i);
  }
  return s;
}

/**
 * Probability that an n-bit block with independent bit errors (rate p) has more than t errors —
 * i.e. the key-reconstruction failure rate of a t-error-correcting code (e.g. BCH) per block.
 */
export function blockFailureProbability(n: number, t: number, p: number): number {
  if (p <= 0) {
    return 0;
  }
  if (p >= 1) {
    return t < n ? 1 : 0;
  }
  let ok = 0;
  for (let i = 0; i <= Math.min(t, n); i++) {
    ok += Math.exp(logChoose(n, i) + i * Math.log(p) + (n - i) * Math.log1p(-p));
  }
  return Math.max(0, 1 - ok);
}

/** Smallest t such that the block failure rate is at most `target`. */
export function requiredCorrection(n: number, p: number, target: number): number | undefined {
  for (let t = 0; t <= n; t++) {
    if (blockFailureProbability(n, t, p) <= target) {
      return t;
    }
  }
  return undefined;
}
