import { describe, expect, it } from 'vitest';
import { formatNs, judge, parseBenchRun, type BenchEntry } from '../../src/bench';

const e = (name: string, median_ns: number, memory = 100): BenchEntry => ({ name, median_ns, min_ns: median_ns, mean_ns: median_ns, memory, allocs: 1, samples: 10 });
const run = (...benchmarks: BenchEntry[]) => ({ version: 1 as const, julia: '1.13.1', benchmarks });

describe('judge', () => {
  it('classifies time and memory like BenchmarkTools.judge', () => {
    const rows = judge(
      run(e('a', 100), e('b', 100), e('c', 100, 100), e('gone', 5)),
      run(e('a', 120), e('b', 90), e('c', 103, 200), e('new', 7)),
    );
    const byName = Object.fromEntries(rows.map((r) => [r.name, r]));
    expect(byName.a.time).toBe('regression');
    expect(byName.b.time).toBe('improvement');
    expect(byName.c.time).toBe('invariant');
    expect(byName.c.memory).toBe('regression');
    expect(byName.gone.time).toBe('removed');
    expect(byName.new.time).toBe('added');
    expect(rows[0].name).toBe('a'); // regressions first
  });

  it('parses bench.jl output', () => {
    // Shape produced by scripts/bench.jl (Julia 1.13.1, BenchmarkTools) on the InvDemo fixture.
    const r = parseBenchRun('{"version":1,"julia":"1.13.1","benchmarks":[{"name":"process / float","median_ns":2842.5,"min_ns":2569.4,"mean_ns":3665.1,"memory":8048,"allocs":305,"samples":10000}]}');
    expect(r.benchmarks[0].name).toBe('process / float');
    expect(() => parseBenchRun('{}')).toThrow();
  });

  it('formats durations', () => {
    expect(formatNs(950)).toBe('950.0 ns');
    expect(formatNs(2842.5)).toBe('2.84 μs');
    expect(formatNs(3.2e9)).toBe('3.20 s');
  });
});
