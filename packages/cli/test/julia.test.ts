import { cpSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../src/julia';
import { captureIo, REPO } from './io';

const FX = join(REPO, 'extensions/julia-profiler/test/fixtures');
const julia = process.env.JULIA_PROFILER_TEST_JULIA;

describe('jest-julia', () => {
  it('lints Julia sources', async () => {
    const io = captureIo(FX);
    expect(await main(['lint', 'InvDemo', '--fail-on', 'warning'], io)).toBe(1);
    expect(io.stdout()).toContain('InvDemo/src/InvDemo.jl');
    expect(io.stdout()).toContain('julia/abstract-field');
  });

  it('adds runtime findings from a profile', async () => {
    // The recorded profile uses /work/InvDemo paths; point them at a copy of the fixture there.
    const dir = mkdtempSync(join(tmpdir(), 'cli-jl-'));
    cpSync(join(FX, 'InvDemo'), join(dir, 'InvDemo'), { recursive: true });
    const profile = readFileSync(join(FX, 'invdemo.profile.json'), 'utf8').split('/work/InvDemo').join(join(dir, 'InvDemo'));
    writeFileSync(join(dir, 'p.json'), profile);
    const io = captureIo(dir);
    await main(['lint', 'InvDemo', '--profile', 'p.json', '--format', 'json'], io);
    const files = JSON.parse(io.stdout()) as { file: string; findings: { ruleId: string; range: { start: { line: number } } }[] }[];
    const runtime = files.flatMap((f) => f.findings).find((f) => f.ruleId === 'julia/runtime-invalidation');
    expect(runtime?.range.start.line).toBe(9);
  });

  it('summarises a recorded profile', async () => {
    const io = captureIo(FX);
    expect(await main(['report', 'invdemo.profile.json', '--top', '3'], io)).toBe(0);
    expect(io.stdout()).toMatch(/Invalidation trees: 1\s+MethodInstances invalidated: \d+/);
    expect(io.stdout()).toContain('InvDemo.==  (inserting)');
    expect(io.stdout()).toContain('Top methods by self inference time:');
  });

  it('creates templates', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cli-jl-'));
    cpSync(join(FX, 'InvDemo'), join(dir, 'Pkg'), { recursive: true });
    const io = captureIo(join(dir, 'Pkg'));
    expect(await main(['init', 'bench'], io)).toBe(1); // exists in the fixture
    expect(await main(['init', 'workflow'], io)).toBe(0);
    expect(existsSync(join(dir, 'Pkg', '.github/workflows/benchmark.yml'))).toBe(true);
    expect(await main(['init', 'nope'], captureIo(join(dir, 'Pkg')))).toBe(2);
  });

  it('explains a missing Julia', async () => {
    const io = captureIo(FX);
    expect(await main(['analyze', 'InvDemo', '--julia', '/nonexistent/julia'], io)).toBe(2);
    expect(io.stderr()).toMatch(/ENOENT|julia/);
  });

  (julia ? it : it.skip)('profiles with real Julia', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cli-jl-'));
    const io = captureIo(FX);
    expect(await main(['analyze', 'InvDemo', '--julia', julia!, '--out', join(dir, 'p.json')], io)).toBe(0);
    expect(io.stdout()).toContain('InvDemo.==');
  }, 900_000);
});
