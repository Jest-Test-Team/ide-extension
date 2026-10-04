/** Results of `scripts/bench.jl` and BenchmarkTools-style judging of two runs. */

export interface BenchEntry {
  name: string;
  median_ns: number;
  min_ns: number;
  mean_ns: number;
  memory: number;
  allocs: number;
  samples: number;
}

export interface BenchRun {
  version: 1;
  julia: string;
  benchmarks: BenchEntry[];
}

export type Verdict = 'regression' | 'improvement' | 'invariant' | 'added' | 'removed';

export interface Judgement {
  name: string;
  baseline?: BenchEntry;
  current?: BenchEntry;
  /** current / baseline median time. */
  timeRatio?: number;
  memoryRatio?: number;
  time: Verdict;
  memory: Verdict;
}

export function parseBenchRun(text: string): BenchRun {
  const raw = JSON.parse(text) as Partial<BenchRun>;
  if (raw.version !== 1 || !Array.isArray(raw.benchmarks)) {
    throw new Error('Not a benchmark result file.');
  }
  return raw as BenchRun;
}

function verdict(ratio: number, tolerance: number): Verdict {
  if (ratio > 1 + tolerance) {
    return 'regression';
  }
  if (ratio < 1 - tolerance) {
    return 'improvement';
  }
  return 'invariant';
}

const ratio = (a: number, b: number) => (b === 0 ? (a === 0 ? 1 : Infinity) : a / b);

/** Same semantics as BenchmarkTools.judge on medians (default tolerances 5% time, 1% memory). */
export function judge(baseline: BenchRun, current: BenchRun, timeTolerance = 0.05, memoryTolerance = 0.01): Judgement[] {
  const base = new Map(baseline.benchmarks.map((b) => [b.name, b]));
  const cur = new Map(current.benchmarks.map((b) => [b.name, b]));
  const names = [...new Set([...base.keys(), ...cur.keys()])];
  const out = names.map((name): Judgement => {
    const b = base.get(name);
    const c = cur.get(name);
    if (!b || !c) {
      const v: Verdict = b ? 'removed' : 'added';
      return { name, baseline: b, current: c, time: v, memory: v };
    }
    const timeRatio = ratio(c.median_ns, b.median_ns);
    const memoryRatio = ratio(c.memory, b.memory);
    return { name, baseline: b, current: c, timeRatio, memoryRatio, time: verdict(timeRatio, timeTolerance), memory: verdict(memoryRatio, memoryTolerance) };
  });
  const rank: Record<Verdict, number> = { regression: 0, improvement: 1, added: 2, removed: 3, invariant: 4 };
  return out.sort((a, b) => rank[a.time] - rank[b.time] || (b.timeRatio ?? 0) - (a.timeRatio ?? 0) || a.name.localeCompare(b.name));
}

export function formatNs(ns: number): string {
  if (ns < 1e3) {
    return `${ns.toFixed(1)} ns`;
  }
  if (ns < 1e6) {
    return `${(ns / 1e3).toFixed(2)} μs`;
  }
  if (ns < 1e9) {
    return `${(ns / 1e6).toFixed(2)} ms`;
  }
  return `${(ns / 1e9).toFixed(2)} s`;
}

export function formatBytes(b: number): string {
  if (b < 1024) {
    return `${b} B`;
  }
  if (b < 1024 ** 2) {
    return `${(b / 1024).toFixed(1)} KiB`;
  }
  return `${(b / 1024 ** 2).toFixed(1)} MiB`;
}

export const BENCHMARK_TEMPLATE = (pkg: string) => `# PkgBenchmark-style suite used by "Julia Profiler: Run Benchmarks" and AirspeedVelocity.jl.
using BenchmarkTools
${pkg ? `using ${pkg}\n` : ''}
const SUITE = BenchmarkGroup()

SUITE["example"] = BenchmarkGroup()
SUITE["example"]["sum"] = @benchmarkable sum(x) setup = (x = rand(1000))
`;

export const WORKFLOW_TEMPLATE = `# Benchmarks every pull request against its base branch with AirspeedVelocity.jl and comments the
# comparison table on the PR. See https://github.com/MilesCranmer/AirspeedVelocity.jl
name: Benchmark this PR
on:
  pull_request_target:
    branches: [main, master]
permissions:
  pull-requests: write

jobs:
  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: MilesCranmer/AirspeedVelocity.jl@action-v1
        with:
          julia-version: '1'
`;
