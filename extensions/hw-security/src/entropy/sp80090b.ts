/**
 * NIST SP 800-90B (January 2018) non-IID min-entropy estimators, section 6.3.
 *
 * This is a TypeScript port that follows NIST's reference implementation
 * (https://github.com/usnistgov/SP800-90B_EntropyAssessment, cpp/) step for step — including its
 * tie-breaking rules, update order and numeric search — so results match `ea_non_iid` (to within
 * double vs. long double rounding in a few places). Function names reference the spec sections.
 */

export const ZALPHA = 2.5758293035489008;
const MIN_SIZE = 1_000_000;
const ITERMAX = 1076;
const DBL_EPSILON = 2.220446049250313e-16;
const DBL_MIN = 2.2250738585072014e-308;

export interface Dataset {
  /** Samples mapped down to 0..alphSize-1 (as NIST does when fewer than 2^wordSize symbols occur). */
  symbols: Uint8Array;
  /** Bitstring of the (unmapped) samples, MSB first, truncated to 1,000,000 bits unless allBits. */
  bits: Uint8Array;
  wordSize: number;
  alphSize: number;
  len: number;
}

/** Mirrors read_file(): mask to wordSize, infer wordSize from the data when not given, map down. */
export function prepareDataset(raw: Uint8Array, wordSize = 0, allBits = false): Dataset {
  let maxRaw = 0;
  for (const v of raw) {
    maxRaw = Math.max(maxRaw, v);
  }
  if (wordSize === 0) {
    wordSize = 1;
    while (wordSize < 8 && 1 << wordSize <= maxRaw) {
      wordSize++;
    }
  }
  if (wordSize < 1 || wordSize > 8) {
    throw new Error('bits per symbol must be between 1 and 8');
  }
  const mask = (1 << wordSize) - 1;
  const masked = new Uint8Array(raw.length);
  const seen = new Uint8Array(1 << wordSize);
  let maxSymbol = 0;
  for (let i = 0; i < raw.length; i++) {
    masked[i] = raw[i] & mask;
    seen[masked[i]] = 1;
    maxSymbol = Math.max(maxSymbol, masked[i]);
  }
  const mapDown = new Uint8Array(1 << wordSize);
  let alphSize = 0;
  for (let i = 0; i < seen.length; i++) {
    if (seen[i]) {
      mapDown[i] = alphSize++;
    }
  }
  let blen = raw.length * wordSize;
  if (!allBits && blen > MIN_SIZE) {
    blen = MIN_SIZE;
  }
  const bits = new Uint8Array(blen);
  for (let b = 0; b < blen; b++) {
    const i = Math.floor(b / wordSize);
    const j = b - i * wordSize;
    bits[b] = (masked[i] >> (wordSize - 1 - j)) & 1;
  }
  const symbols = alphSize < maxSymbol + 1 ? masked.map((s) => mapDown[s]) : masked;
  return { symbols, bits, wordSize, alphSize, len: raw.length };
}

// --- numeric helpers ---------------------------------------------------------------------------

const f64 = new Float64Array(1);
const u64 = new BigUint64Array(f64.buffer);
function bitsOf(x: number): bigint {
  f64[0] = x;
  return u64[0];
}

/** NIST's relEpsilonEqual(A, B, DBL_MIN, DBL_EPSILON, 4). */
export function relEpsilonEqual(a: number, b: number, maxAbs = DBL_MIN, maxRel = DBL_EPSILON, maxULP = 4): boolean {
  if (Number.isNaN(a) || Number.isNaN(b)) {
    return false;
  }
  if (a === b) {
    return true;
  }
  if (!Number.isFinite(a) || !Number.isFinite(b)) {
    return false;
  }
  let absA = Math.abs(a);
  let absB = Math.abs(b);
  if (absA > absB) {
    [a, b] = [b, a];
    [absA, absB] = [absB, absA];
  }
  const diff = Math.abs(b - a);
  if (absA < DBL_MIN || diff < DBL_MIN || !Number.isFinite(diff) || absB * maxRel < DBL_MIN) {
    return diff <= maxAbs;
  } else if (diff <= absB * maxRel) {
    return true;
  }
  if (Math.sign(a) !== Math.sign(b)) {
    return false;
  }
  return bitsOf(absB) - bitsOf(absA) <= BigInt(maxULP);
}

const inClosed = (x: number, a: number, b: number) => (a > b ? x >= b && x <= a : x >= a && x <= b);
const inOpen = (x: number, a: number, b: number) => (a > b ? x > b && x < a : x > a && x < b);

/**
 * The bisection used throughout the reference implementation: finds p in [ldomain, hdomain] with
 * f(p) = target, where f is monotonically decreasing. `onFail` is returned when the target is
 * outside the bracket.
 */
function bisect(f: (p: number) => number, target: number, ldomain: number, hdomain: number, onFail: number): number {
  let lbound = ldomain;
  let hbound = hdomain;
  let lvalue = Infinity;
  let hvalue = -Infinity;
  let p = (lbound + hbound) / 2;
  let pVal = f(p);
  for (let j = 0; j < ITERMAX; j++) {
    if (relEpsilonEqual(pVal, target)) {
      break;
    }
    if (target < pVal) {
      lbound = p;
      lvalue = pVal;
    } else {
      hbound = p;
      hvalue = pVal;
    }
    if (lbound >= hbound) {
      p = Math.min(Math.max(lbound, hbound), hdomain);
      break;
    }
    if (!(inClosed(lbound, ldomain, hdomain) && inClosed(hbound, ldomain, hdomain))) {
      p = onFail;
      break;
    }
    if (!inClosed(target, lvalue, hvalue)) {
      p = onFail;
      break;
    }
    const lastP = p;
    p = (lbound + hbound) / 2;
    if (!inOpen(p, lbound, hbound)) {
      p = hbound;
      break;
    }
    if (lastP === p) {
      p = hbound;
      break;
    }
    pVal = f(p);
    if (!inClosed(pVal, lvalue, hvalue)) {
      p = hbound;
      break;
    }
  }
  return p;
}

function kahan(): { add(x: number): void; value(): number } {
  let sum = 0;
  let comp = 0;
  return {
    add(x: number) {
      const y = x - comp;
      const t = sum + y;
      comp = t - sum - y;
      sum = t;
    },
    value: () => sum,
  };
}

// --- 6.3.1 Most Common Value -------------------------------------------------------------------

export function mostCommonValue(data: Uint8Array, k: number): number {
  const counts = new Float64Array(Math.max(k, 256));
  let mode = 0;
  for (const s of data) {
    mode = Math.max(mode, ++counts[s]);
  }
  const pmax = mode / data.length;
  const ubound = Math.min(1, pmax + ZALPHA * Math.sqrt((pmax * (1 - pmax)) / (data.length - 1)));
  return -Math.log2(ubound);
}

// --- 6.3.2 Collision (binary) ------------------------------------------------------------------

export function collision(bits: Uint8Array): number {
  const len = bits.length;
  let i = 0;
  let v = 0;
  let s = 0;
  while (i < len - 1) {
    let t: number;
    if (bits[i] === bits[i + 1]) {
      t = 2;
    } else if (i < len - 2) {
      t = 3;
    } else {
      break;
    }
    v++;
    s += t * t;
    i += t;
  }
  let x = i / v;
  const sigma = Math.sqrt((s - i * x) / (v - 1));
  x -= (ZALPHA * sigma) / Math.sqrt(v);
  if (x < 2) {
    x = 2;
  }
  if (x < 2.5) {
    return -Math.log2(0.5 + Math.sqrt(1.25 - 0.5 * x));
  }
  return 1;
}

// --- 6.3.3 Markov (binary) ---------------------------------------------------------------------

export function markov(bits: Uint8Array): number {
  const len = bits.length;
  let c0 = 0;
  let c00 = 0;
  let c10 = 0;
  for (let i = 0; i < len - 1; i++) {
    if (bits[i] === 0) {
      c0++;
      if (bits[i + 1] === 0) {
        c00++;
      }
    } else if (bits[i + 1] === 0) {
      c10++;
    }
  }
  const c1 = len - 1 - c0;
  const p00 = c0 > 0 ? c00 / c0 : 0;
  const p01 = c0 > 0 ? 1 - p00 : 0;
  const p10 = c1 > 0 ? c10 / c1 : 0;
  const p11 = c1 > 0 ? 1 - p10 : 0;
  if (bits[len - 1] === 0) {
    c0++;
  }
  const p0 = c0 / len;
  const p1 = 1 - p0;
  let h = 128;
  const consider = (cond: boolean, value: () => number) => {
    if (cond) {
      h = Math.min(h, value());
    }
  };
  const lg = Math.log2;
  consider(p00 > 0, () => -lg(p0) - 127 * lg(p00));
  consider(p01 > 0 && p10 > 0, () => -lg(p0) - 64 * lg(p01) - 63 * lg(p10));
  consider(p01 > 0 && p11 > 0, () => -lg(p0) - lg(p01) - 126 * lg(p11));
  consider(p10 > 0 && p00 > 0, () => -lg(p1) - lg(p10) - 126 * lg(p00));
  consider(p10 > 0 && p01 > 0, () => -lg(p1) - 64 * lg(p10) - 63 * lg(p01));
  consider(p11 > 0, () => -lg(p1) - 127 * lg(p11));
  return Math.min(h / 128, 1);
}

// --- 6.3.4 Compression (binary, 6-bit blocks) --------------------------------------------------

function compressionG(z: number, d: number, numBlocks: number): number {
  const ai = kahan();
  const firstSum = kahan();
  const v = numBlocks - d;
  const bterm = 1 - z;
  let bi = bterm;
  for (let i = 2; i <= d; i++) {
    ai.add(Math.log2(i) * bi);
    bi *= bterm;
  }
  const ad1 = ai.value();
  let underflow = false;
  for (let i = d + 1; i <= numBlocks - 1; i++) {
    const a = Math.log2(i) * bi;
    ai.add(a);
    const scaled = (numBlocks - i) * a;
    if (scaled > 0) {
      firstSum.add(scaled);
    } else {
      underflow = true;
      break;
    }
    bi *= bterm;
  }
  firstSum.add((numBlocks - d) * ad1);
  if (!underflow) {
    ai.add(Math.log2(numBlocks) * bi);
  }
  return (1 / v) * z * (z * firstSum.value() + (ai.value() - ad1));
}

export function compression(bits: Uint8Array): number {
  const b = 6;
  const alph = 1 << b;
  const d = 1000;
  const numBlocks = Math.floor(bits.length / b);
  if (numBlocks <= d) {
    return -1;
  }
  const dict = new Float64Array(alph);
  const block = (i: number) => {
    let x = 0;
    for (let j = 0; j < b; j++) {
      x |= (bits[i * b + j] & 1) << (b - j - 1);
    }
    return x;
  };
  for (let i = 0; i < d; i++) {
    dict[block(i)] = i + 1;
  }
  const v = numBlocks - d;
  const X = kahan();
  const S = kahan();
  for (let i = d; i < numBlocks; i++) {
    const blk = block(i);
    const l = Math.log2(i + 1 - dict[blk]);
    X.add(l);
    S.add(l * l);
    dict[blk] = i + 1;
  }
  let x = X.value() / v;
  const sigma = 0.5907 * Math.sqrt(S.value() / (v - 1) - x * x);
  x -= (ZALPHA * sigma) / Math.sqrt(v);
  const comExp = (p: number) => {
    const q = (1 - p) / (alph - 1);
    return compressionG(p, d, numBlocks) + (alph - 1) * compressionG(q, d, numBlocks);
  };
  let p = -1;
  if (comExp(1 / alph) > x) {
    p = bisect(comExp, x, 1 / alph, 1, 1 / alph);
  }
  return p > 1 / alph ? -Math.log2(p) / b : 1;
}

// --- 6.3.5 / 6.3.6 t-Tuple and LRS (suffix array) ----------------------------------------------

/** Suffix array by prefix doubling with radix sort, O(n log n). */
export function suffixArray(s: Uint8Array): Int32Array {
  const n = s.length;
  const sa = new Int32Array(n);
  let rank = new Int32Array(n);
  let tmp = new Int32Array(n);
  const order = new Int32Array(n);
  // Initial order by first symbol (counting sort).
  const cnt = new Int32Array(Math.max(257, n + 1));
  for (let i = 0; i < n; i++) {
    cnt[s[i]]++;
  }
  for (let i = 1; i < 256; i++) {
    cnt[i] += cnt[i - 1];
  }
  for (let i = n - 1; i >= 0; i--) {
    sa[--cnt[s[i]]] = i;
  }
  let classes = 1;
  rank[sa[0]] = 0;
  for (let i = 1; i < n; i++) {
    if (s[sa[i]] !== s[sa[i - 1]]) {
      classes++;
    }
    rank[sa[i]] = classes - 1;
  }
  for (let h = 1; h < n && classes < n; h <<= 1) {
    // Sort by (rank[i], rank[i+h]) where suffixes shorter than h+... get -1 for the second key.
    let p = 0;
    for (let i = n - h; i < n; i++) {
      order[p++] = i; // second key is "empty", sorts first
    }
    for (let i = 0; i < n; i++) {
      if (sa[i] >= h) {
        order[p++] = sa[i] - h;
      }
    }
    cnt.fill(0, 0, classes + 1);
    for (let i = 0; i < n; i++) {
      cnt[rank[i]]++;
    }
    for (let i = 1; i < classes; i++) {
      cnt[i] += cnt[i - 1];
    }
    for (let i = n - 1; i >= 0; i--) {
      sa[--cnt[rank[order[i]]]] = order[i];
    }
    tmp[sa[0]] = 0;
    classes = 1;
    for (let i = 1; i < n; i++) {
      const a = sa[i - 1];
      const b = sa[i];
      const ra2 = a + h < n ? rank[a + h] : -1;
      const rb2 = b + h < n ? rank[b + h] : -1;
      if (rank[a] !== rank[b] || ra2 !== rb2) {
        classes++;
      }
      tmp[b] = classes - 1;
    }
    [rank, tmp] = [tmp, rank];
  }
  return sa;
}

/** Kasai LCP: lcp[i] = LCP(suffix sa[i-1], suffix sa[i]) for i >= 1; lcp[0] = 0. */
export function lcpArray(s: Uint8Array, sa: Int32Array): Int32Array {
  const n = s.length;
  const rank = new Int32Array(n);
  for (let i = 0; i < n; i++) {
    rank[sa[i]] = i;
  }
  const lcp = new Int32Array(n);
  let h = 0;
  for (let i = 0; i < n; i++) {
    if (rank[i] > 0) {
      const j = sa[rank[i] - 1];
      while (i + h < n && j + h < n && s[i + h] === s[j + h]) {
        h++;
      }
      lcp[rank[i]] = h;
      if (h > 0) {
        h--;
      }
    } else {
      h = 0;
    }
  }
  return lcp;
}

/**
 * For every tuple length W: Q[W] = count of the most common W-tuple, S[W] = Σ C(count, 2) over
 * distinct W-tuples (overlapping tuples). Computed from lcp-intervals in O(n + v).
 */
export function tupleStats(s: Uint8Array): { v: number; Q: Float64Array; S: Float64Array } {
  const n = s.length;
  const lcp = lcpArray(s, suffixArray(s));
  let v = 0;
  for (let i = 1; i < n; i++) {
    v = Math.max(v, lcp[i]);
  }
  const best = new Float64Array(v + 2);
  const diff = new Float64Array(v + 3);
  // Bottom-up lcp-interval traversal (Abouelhoda, Kurtz & Ohlebusch).
  const stLcp: number[] = [0];
  const stLb: number[] = [0];
  for (let i = 1; i <= n; i++) {
    const cur = i < n ? lcp[i] : 0;
    let lb = i - 1;
    while (cur < stLcp[stLcp.length - 1]) {
      const l = stLcp.pop()!;
      const ilb = stLb.pop()!;
      const size = i - ilb; // rb = i-1
      const parent = Math.max(cur, stLcp[stLcp.length - 1]);
      best[l] = Math.max(best[l], size);
      const pairs = (size * (size - 1)) / 2;
      diff[parent + 1] += pairs;
      diff[l + 1] -= pairs;
      lb = ilb;
    }
    if (cur > stLcp[stLcp.length - 1]) {
      stLcp.push(cur);
      stLb.push(lb);
    }
  }
  const Q = new Float64Array(v + 2).fill(1);
  let run = 1;
  for (let w = v; w >= 1; w--) {
    run = Math.max(run, best[w]);
    Q[w] = run;
  }
  const S = new Float64Array(v + 2);
  let acc = 0;
  for (let w = 1; w <= v; w++) {
    acc += diff[w];
    S[w] = acc;
  }
  return { v, Q, S };
}

export function tTupleAndLrs(data: Uint8Array): { tTuple: number; lrs: number; t: number; u: number; v: number } {
  const n = data.length;
  const { v, Q, S } = tupleStats(data);
  if (v === 0) {
    return { tTuple: -1, lrs: -1, t: 0, u: 1, v };
  }
  let u = 1;
  while (u <= v && Q[u] >= 35) {
    u++;
  }
  let pmax = -1;
  for (let i = 1; i < u; i++) {
    pmax = Math.max(pmax, Math.pow(Q[i] / (n - i + 1), 1 / i));
  }
  const bound = (p: number) => Math.min(1, p + ZALPHA * Math.sqrt((p * (1 - p)) / (n - 1)));
  const tTuple = pmax > 0 ? -Math.log2(bound(pmax)) : -1;
  let lrs = -1;
  if (v >= u) {
    pmax = 0;
    for (let w = u; w <= v; w++) {
      const choices = ((n - w) * (n - w + 1)) / 2;
      pmax = Math.max(pmax, Math.pow(S[w] / choices, 1 / w));
    }
    lrs = -Math.log2(bound(pmax));
  }
  return { tTuple, lrs, t: u - 1, u, v };
}

// --- 6.3.7 - 6.3.10 prediction estimators ------------------------------------------------------

function predictionFunction(p: number, r: number, N: number): number {
  const q = 1 - p;
  let x = 1;
  let xlast = 0;
  for (let i = 0; i <= 65 && x - xlast > DBL_EPSILON * x; i++) {
    xlast = x;
    x = 1 + q * Math.pow(p, r) * Math.pow(x, r + 1);
  }
  return Math.log(1 - p * x) - Math.log((r + 1 - r * x) * q) - (N + 1) * Math.log(x);
}

export interface PredictionResult {
  entropy: number;
  N: number;
  C: number;
  r: number;
  pGlobal: number;
  pLocal?: number;
}

/** predictionEstimate(): combines P'_global and P_local (spec 6.3.7 steps 5-7). */
export function predictionEstimate(C: number, N: number, maxRun: number, k: number): PredictionResult {
  let curMax = 1 / k;
  const pGlobal = C / N;
  const pGlobalPrime =
    pGlobal > 0 ? Math.min(1, pGlobal + ZALPHA * Math.sqrt((pGlobal * (1 - pGlobal)) / (N - 1))) : 1 - Math.pow(0.01, 1 / N);
  curMax = Math.max(curMax, pGlobalPrime);
  let pLocal: number | undefined;
  const logAlpha = Math.log(0.99);
  if (curMax < 1 && predictionFunction(curMax, maxRun + 1, N) > logAlpha) {
    pLocal = bisect((p) => predictionFunction(p, maxRun + 1, N), logAlpha, curMax, 1, 1);
    curMax = Math.max(curMax, pLocal);
  }
  return { entropy: -Math.log2(curMax), N, C, r: maxRun + 1, pGlobal: pGlobalPrime, pLocal };
}

export function multiMcw(data: Uint8Array, k: number): PredictionResult | undefined {
  const W = [63, 255, 1023, 4095];
  const len = data.length;
  if (len < W[3] + 1) {
    return undefined;
  }
  const N = len - W[0];
  let winner = 0;
  let C = 0;
  let run = 0;
  let maxRun = 0;
  const scoreboard = [0, 0, 0, 0];
  const maxCnts = [0, 0, 0, 0];
  const cnts = W.map(() => new Int32Array(k));
  const poses = W.map(() => new Float64Array(k));
  const frequent = [0, 0, 0, 0];
  for (let i = 0; i < W[3]; i++) {
    for (let j = 0; j < 4; j++) {
      if (i < W[j]) {
        if (maxCnts[j] <= ++cnts[j][data[i]]) {
          maxCnts[j] = cnts[j][data[i]];
          frequent[j] = data[i];
        }
        poses[j][data[i]] = i;
      }
    }
  }
  for (let i = W[0]; i < len; i++) {
    if (frequent[winner] === data[i]) {
      C++;
      if (++run > maxRun) {
        maxRun = run;
      }
    } else {
      run = 0;
    }
    for (let j = 0; j < 4; j++) {
      if (i >= W[j] && frequent[j] === data[i]) {
        if (++scoreboard[j] >= scoreboard[winner]) {
          winner = j;
        }
      }
    }
    for (let j = 0; j < 4; j++) {
      if (i >= W[j]) {
        const old = data[i - W[j]];
        cnts[j][old]--;
        cnts[j][data[i]]++;
        poses[j][data[i]] = i;
        if (old !== frequent[j] && maxCnts[j] <= cnts[j][data[i]]) {
          maxCnts[j] = cnts[j][data[i]];
          frequent[j] = data[i];
        } else if (old === frequent[j]) {
          maxCnts[j]--;
          let maxPos = i - W[j];
          for (let s = 0; s < k; s++) {
            if (maxCnts[j] < cnts[j][s] || (maxCnts[j] === cnts[j][s] && maxPos <= poses[j][s])) {
              maxCnts[j] = cnts[j][s];
              frequent[j] = s;
              maxPos = poses[j][s];
            }
          }
        }
      }
    }
  }
  return predictionEstimate(C, N, maxRun, k);
}

export function lag(data: Uint8Array, k: number): PredictionResult {
  const D = 128;
  const L = data.length;
  const scoreboard = new Float64Array(D);
  let winner = 0;
  let run = 0;
  let maxRun = 0;
  let C = 0;
  let high = 0;
  // Per-symbol ring buffers of recent positions (see lag_test.h).
  const buf = Array.from({ length: k }, () => new Float64Array(D));
  const start = new Uint8Array(k);
  const end = new Uint8Array(k);
  buf[data[0]][0] = 0;
  end[data[0]] = 1;
  for (let i = 1; i < L; i++) {
    const sym = data[i];
    if (sym === data[i - winner - 1]) {
      C++;
      if (++run > maxRun) {
        maxRun = run;
      }
    } else {
      run = 0;
    }
    if (start[sym] !== end[sym]) {
      let idx = end[sym];
      const cutoff = i >= D ? i - D : 0;
      do {
        idx = (idx - 1) & 0xff;
        const pos = buf[sym][idx & (D - 1)];
        if (pos >= cutoff) {
          const off = i - pos - 1;
          const score = ++scoreboard[off];
          if (score >= high) {
            winner = off;
            high = score;
          }
        } else {
          start[sym] = (idx + 1) & 0xff;
          break;
        }
      } while (idx !== start[sym]);
    }
    if (((end[sym] - start[sym]) & 0xff) === D) {
      start[sym] = (start[sym] + 1) & 0xff;
    }
    buf[sym][end[sym] & (D - 1)] = i;
    end[sym] = (end[sym] + 1) & 0xff;
  }
  return predictionEstimate(C, L - 1, maxRun, k);
}

/** NIST's PostfixDictionary: counts per following symbol, prediction = max count, ties → larger symbol. */
class Postfix {
  private readonly counts = new Map<number, number>();
  best = 0;
  prediction = 0;

  increment(sym: number, makeNew: boolean): boolean {
    const cur = this.counts.get(sym);
    let count: number;
    let created = false;
    if (cur !== undefined) {
      count = cur + 1;
    } else if (makeNew) {
      count = 1;
      created = true;
    } else {
      return false;
    }
    this.counts.set(sym, count);
    if (count > this.best || (count === this.best && sym > this.prediction)) {
      this.prediction = sym;
      this.best = count;
    }
    return created;
  }
}

/**
 * Contexts for MultiMMC / LZ78Y stored as a trie walked from the newest symbol backwards, so all
 * context lengths ending at the same position share one path. A node only counts as a dictionary
 * entry when it carries a Postfix; other nodes are structural.
 */
interface TrieNode {
  kids?: Map<number, TrieNode>;
  pf?: Postfix;
}

class ContextTrie {
  private readonly root: TrieNode = {};
  /** nodes[len] = node for the context of that length ending before `end`, if present. */
  readonly nodes: (TrieNode | undefined)[] = [];

  walk(data: Uint8Array, end: number, maxLen: number): void {
    let n: TrieNode | undefined = this.root;
    for (let len = 1; len <= maxLen; len++) {
      n = n?.kids?.get(data[end - len]);
      this.nodes[len] = n;
    }
  }

  /** Creates (structurally) the path to `len`, updating `nodes`, and returns that node. */
  ensure(data: Uint8Array, end: number, len: number): TrieNode {
    let n = this.root;
    for (let l = 1; l <= len; l++) {
      let next = this.nodes[l];
      if (!next) {
        n.kids ??= new Map();
        next = n.kids.get(data[end - l]);
        if (!next) {
          next = {};
          n.kids.set(data[end - l], next);
        }
        this.nodes[l] = next;
      }
      n = next;
    }
    return n;
  }
}

export function multiMmc(data: Uint8Array, k: number): PredictionResult | undefined {
  if (k === 2) {
    return multiMmcBinary(data);
  }
  const D = 16;
  const MAX = 100_000;
  const len = data.length;
  if (len < 3) {
    return undefined;
  }
  const N = len - 2;
  const trie = new ContextTrie();
  const entries = new Array<number>(D).fill(0);
  const scoreboard = new Array<number>(D).fill(0);
  let winner = 0;
  let C = 0;
  let run = 0;
  let maxRun = 0;
  const insert = (end: number, ctxLen: number, sym: number) => {
    const node = trie.ensure(data, end, ctxLen);
    node.pf ??= new Postfix();
    node.pf.increment(sym, true);
  };
  for (let d = 0; d < D; d++) {
    if (d < N) {
      trie.walk(data, d + 1, d + 1);
      insert(d + 1, d + 1, data[d + 1]);
      entries[d] = 1;
    }
  }
  for (let i = 2; i < len; i++) {
    let found = false;
    const curWinner = winner;
    let cur: Postfix | undefined;
    const maxD = Math.min(D, i - 1);
    trie.walk(data, i, maxD);
    for (let d = 0; d < maxD; d++) {
      if (d === 0 || found) {
        cur = trie.nodes[d + 1]?.pf;
        found = cur !== undefined;
      }
      if (found && cur) {
        if (cur.prediction === data[i]) {
          if (++scoreboard[d] >= scoreboard[winner]) {
            winner = d;
          }
          if (d === curWinner) {
            C++;
            if (++run > maxRun) {
              maxRun = run;
            }
          }
        } else if (d === curWinner) {
          run = 0;
        }
        if (cur.increment(data[i], entries[d] < MAX)) {
          entries[d]++;
        }
      } else if (entries[d] < MAX) {
        insert(i, d + 1, data[i]);
        entries[d]++;
      }
    }
  }
  return predictionEstimate(C, N, maxRun, k);
}

/** Binary MultiMMC with array dictionaries (binaryMultiMMCPredictionEstimate). */
function multiMmcBinary(S: Uint8Array): PredictionResult | undefined {
  const D = 16;
  const MAX = 100_000;
  const L = S.length;
  if (L <= 3) {
    return undefined;
  }
  // dict[d][(pattern << 1) | y]: counts for contexts of d+1 bits (pattern = newest bit in bit 0).
  const dict = Array.from({ length: D }, (_, d) => new Int32Array(1 << (d + 2)));
  const elems = new Int32Array(D);
  const scoreboard = new Float64Array(D);
  let winner = 0;
  let C = 0;
  let run = 0;
  let maxRun = 0;
  let pattern = 0;
  for (let d = 0; d < D; d++) {
    pattern = ((pattern << 1) | (S[d] & 1)) >>> 0;
    const mask = (1 << (d + 1)) - 1;
    dict[d][((pattern & mask) << 1) | (S[d + 1] & 1)] = 1;
    elems[d] = 1;
  }
  for (let i = 2; i < L; i++) {
    let found = false;
    const curWinner = winner;
    pattern = 0;
    for (let d = 0; d < D && d <= i - 2; d++) {
      pattern = (pattern | ((S[i - d - 1] & 1) << d)) >>> 0;
      const base = pattern << 1;
      const e = dict[d];
      let prediction = 2;
      if (d === 0 || found) {
        let count: number;
        if (e[base] > e[base + 1]) {
          prediction = 0;
          count = e[base];
        } else {
          prediction = 1;
          count = e[base + 1];
        }
        found = count !== 0;
      }
      const y = S[i] & 1;
      if (found) {
        if (prediction === S[i]) {
          if (++scoreboard[d] >= scoreboard[winner]) {
            winner = d;
          }
          if (d === curWinner) {
            C++;
            if (++run > maxRun) {
              maxRun = run;
            }
          }
        } else if (d === curWinner) {
          run = 0;
        }
        if (e[base + y] !== 0) {
          e[base + y]++;
        } else if (elems[d] < MAX) {
          e[base + y] = 1;
          elems[d]++;
        }
      } else if (elems[d] < MAX) {
        e[base + y] = 1;
        elems[d]++;
      }
    }
  }
  return predictionEstimate(C, L - 2, maxRun, 2);
}

export function lz78y(data: Uint8Array, k: number): PredictionResult | undefined {
  if (k === 2) {
    return lz78yBinary(data);
  }
  const B = 16;
  const MAX = 65_536;
  const len = data.length;
  if (len < B + 2) {
    return undefined;
  }
  const N = len - B - 1;
  const trie = new ContextTrie();
  let dictSize = 0;
  let C = 0;
  let run = 0;
  let maxRun = 0;
  const insert = (end: number, ctxLen: number, sym: number) => {
    const node = trie.ensure(data, end, ctxLen);
    node.pf ??= new Postfix();
    node.pf.increment(sym, true);
  };
  trie.walk(data, B, B);
  for (let j = 1; j <= B; j++) {
    insert(B, j, data[B]);
    dictSize++;
  }
  for (let i = B + 1; i < len; i++) {
    let have = false;
    let prediction = 0;
    let maxCount = 0;
    trie.walk(data, i, B);
    for (let j = B; j > 0; j--) {
      const cur = trie.nodes[j]?.pf;
      if (cur) {
        if (cur.best > maxCount) {
          maxCount = cur.best;
          prediction = cur.prediction;
          have = true;
        }
        cur.increment(data[i], true);
      } else if (dictSize < MAX) {
        insert(i, j, data[i]);
        dictSize++;
      }
    }
    if (have && prediction === data[i]) {
      C++;
      if (++run > maxRun) {
        maxRun = run;
      }
    } else {
      run = 0;
    }
  }
  return predictionEstimate(C, N, maxRun, k);
}

/** Binary LZ78Y with array dictionaries (binaryLZ78YPredictionEstimate). */
function lz78yBinary(S: Uint8Array): PredictionResult | undefined {
  const B = 16;
  const MAX = 65_536;
  const L = S.length;
  if (L < B + 3) {
    return undefined;
  }
  const dict = Array.from({ length: B }, (_, j) => new Int32Array(1 << (j + 2)));
  let elems = 0;
  let C = 0;
  let run = 0;
  let maxRun = 0;
  let pattern = 0;
  for (let j = 0; j < B; j++) {
    pattern = (pattern | ((S[B - j - 1] & 1) << j)) >>> 0;
    dict[j][(pattern << 1) | (S[B] & 1)] = 1;
    elems++;
  }
  for (let i = B + 1; i < L; i++) {
    let have = false;
    let curPrediction = 2;
    let maxCount = 0;
    // compressedBitSymbols(S+i-B, B): oldest bit is the most significant.
    let full = 0;
    for (let b = 0; b < B; b++) {
      full = ((full << 1) | (S[i - B + b] & 1)) >>> 0;
    }
    const y = S[i] & 1;
    for (let j = B; j > 0; j--) {
      const p = (full & ((1 << j) - 1)) >>> 0;
      const e = dict[j - 1];
      const base = p << 1;
      let round: number;
      let count: number;
      if (e[base] > e[base + 1]) {
        round = 0;
        count = e[base];
      } else {
        round = 1;
        count = e[base + 1];
      }
      if (count !== 0) {
        if (count > maxCount) {
          maxCount = count;
          have = true;
          curPrediction = round;
        }
        e[base + y]++;
      } else if (elems < MAX) {
        e[base + y] = 1;
        elems++;
      }
    }
    if (have && curPrediction === S[i]) {
      C++;
      if (++run > maxRun) {
        maxRun = run;
      }
    } else {
      run = 0;
    }
  }
  return predictionEstimate(C, L - B - 1, maxRun, 2);
}

// --- Full non-IID assessment (non_iid_main.cpp) ------------------------------------------------

export type EstimatorId =
  | 'mcv'
  | 'collision'
  | 'markov'
  | 'compression'
  | 'tTuple'
  | 'lrs'
  | 'multiMcw'
  | 'lag'
  | 'multiMmc'
  | 'lz78y';

export const ESTIMATORS: { id: EstimatorId; section: string; title: string }[] = [
  { id: 'mcv', section: '6.3.1', title: 'Most Common Value' },
  { id: 'collision', section: '6.3.2', title: 'Collision' },
  { id: 'markov', section: '6.3.3', title: 'Markov' },
  { id: 'compression', section: '6.3.4', title: 'Compression' },
  { id: 'tTuple', section: '6.3.5', title: 't-Tuple' },
  { id: 'lrs', section: '6.3.6', title: 'Longest Repeated Substring (LRS)' },
  { id: 'multiMcw', section: '6.3.7', title: 'Multi Most Common in Window' },
  { id: 'lag', section: '6.3.8', title: 'Lag Prediction' },
  { id: 'multiMmc', section: '6.3.9', title: 'Multi Markov Model with Counting' },
  { id: 'lz78y', section: '6.3.10', title: 'LZ78Y Prediction' },
];

export interface NonIidResult {
  wordSize: number;
  alphSize: number;
  samples: number;
  bitstringLength: number;
  /** Per-estimator entropy for the literal samples (bits/symbol) and bitstring (bits/bit); undefined = not applicable. */
  literal: Partial<Record<EstimatorId, number>>;
  bitstring: Partial<Record<EstimatorId, number>>;
  hOriginal?: number;
  hBitstring?: number;
  /** min(H_original, wordSize × H_bitstring), the value to claim per sample. */
  hAssessed: number;
  warnings: string[];
}

export function nonIidAssessment(
  raw: Uint8Array,
  opts: { wordSize?: number; initialEntropy?: boolean; allBits?: boolean; onProgress?: (id: EstimatorId) => void } = {},
): NonIidResult {
  const initial = opts.initialEntropy ?? true;
  const ds = prepareDataset(raw, opts.wordSize ?? 0, opts.allBits ?? false);
  const warnings: string[] = [];
  if (ds.alphSize <= 1) {
    throw new Error('Symbol alphabet consists of 1 symbol. No entropy awarded.');
  }
  if (ds.len < MIN_SIZE) {
    warnings.push(`SP 800-90B requires at least 1,000,000 samples; this dataset has ${ds.len.toLocaleString()}. Results are indicative only.`);
  }
  const useBits = ds.alphSize > 2 || !initial;
  const binaryLiteral = initial && ds.alphSize === 2;
  const lit: NonIidResult['literal'] = {};
  const bit: NonIidResult['bitstring'] = {};
  const step = (id: EstimatorId, fn: () => void) => {
    opts.onProgress?.(id);
    fn();
  };
  const ok = (x: number | undefined) => (x !== undefined && x >= 0 ? x : undefined);

  step('mcv', () => {
    if (useBits) {
      bit.mcv = mostCommonValue(ds.bits, 2);
    }
    if (initial) {
      lit.mcv = mostCommonValue(ds.symbols, ds.alphSize);
    }
  });
  step('collision', () => {
    if (useBits) {
      bit.collision = collision(ds.bits);
    }
    if (binaryLiteral) {
      lit.collision = collision(ds.symbols);
    }
  });
  step('markov', () => {
    if (useBits) {
      bit.markov = markov(ds.bits);
    }
    if (binaryLiteral) {
      lit.markov = markov(ds.symbols);
    }
  });
  step('compression', () => {
    if (useBits) {
      bit.compression = ok(compression(ds.bits));
    }
    if (binaryLiteral) {
      lit.compression = ok(compression(ds.symbols));
    }
  });
  step('tTuple', () => {
    if (useBits) {
      const r = tTupleAndLrs(ds.bits);
      bit.tTuple = ok(r.tTuple);
      bit.lrs = ok(r.lrs);
    }
    if (initial) {
      const r = tTupleAndLrs(ds.symbols);
      lit.tTuple = ok(r.tTuple);
      lit.lrs = ok(r.lrs);
    }
  });
  step('multiMcw', () => {
    if (useBits) {
      bit.multiMcw = multiMcw(ds.bits, 2)?.entropy;
    }
    if (initial) {
      lit.multiMcw = multiMcw(ds.symbols, ds.alphSize)?.entropy;
    }
  });
  step('lag', () => {
    if (useBits) {
      bit.lag = lag(ds.bits, 2).entropy;
    }
    if (initial) {
      lit.lag = lag(ds.symbols, ds.alphSize).entropy;
    }
  });
  step('multiMmc', () => {
    if (useBits) {
      bit.multiMmc = multiMmc(ds.bits, 2)?.entropy;
    }
    if (initial) {
      lit.multiMmc = multiMmc(ds.symbols, ds.alphSize)?.entropy;
    }
  });
  step('lz78y', () => {
    if (useBits) {
      bit.lz78y = lz78y(ds.bits, 2)?.entropy;
    }
    if (initial) {
      lit.lz78y = lz78y(ds.symbols, ds.alphSize)?.entropy;
    }
  });

  const minOf = (r: NonIidResult['literal'], cap: number) =>
    Object.values(r).reduce<number>((m, v) => (v !== undefined ? Math.min(m, v) : m), cap);
  const hOriginal = initial ? minOf(lit, ds.wordSize) : undefined;
  const hBitstring = useBits ? minOf(bit, 1) : undefined;
  let hAssessed = ds.wordSize;
  if (hBitstring !== undefined) {
    hAssessed = Math.min(hAssessed, hBitstring * ds.wordSize);
  }
  if (hOriginal !== undefined) {
    hAssessed = Math.min(hAssessed, hOriginal);
  }
  return {
    wordSize: ds.wordSize,
    alphSize: ds.alphSize,
    samples: ds.len,
    bitstringLength: ds.bits.length,
    literal: lit,
    bitstring: bit,
    hOriginal,
    hBitstring,
    hAssessed,
    warnings,
  };
}
