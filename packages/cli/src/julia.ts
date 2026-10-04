import type { Finding } from '@ide-ext/core';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { BENCHMARK_TEMPLATE, formatNs, judge, parseBenchRun, WORKFLOW_TEMPLATE, type BenchRun, type Judgement } from '../../../extensions/julia-profiler/src/bench';
import { flattenInference, parseProfile, summarize, triggersByCaller, type Profile } from '../../../extensions/julia-profiler/src/profile';
import { findProject, WORKLOAD_TEMPLATE, type JuliaProject } from '../../../extensions/julia-profiler/src/project';
import { JULIA_RULES } from '../../../extensions/julia-profiler/src/rules';
import { runtimeFindings } from '../../../extensions/julia-profiler/src/runtimeFindings';
import { runTool, UsageError, VERSION, type Command, type Io, type Tool } from './lib/args';
import { assetDir } from './lib/assets';
import { lintFiles, effectiveRules } from './lib/lint';
import { emit, exitFor, failThreshold, formatOf, LINT_FLAGS, renderFindings, REPORT_FLAGS } from './lib/output';
import { cacheDir, run, which } from './lib/proc';
import { collectFiles } from './lib/files';

/** --julia, then $JULIA, then PATH, then ~/.juliaup/bin/julia. */
export function resolveJulia(flag: unknown): string {
  const exe = process.platform === 'win32' ? 'julia.exe' : 'julia';
  const found = (typeof flag === 'string' && flag) || process.env.JULIA || which('julia') || (existsSync(join(homedir(), '.juliaup', 'bin', exe)) ? join(homedir(), '.juliaup', 'bin', exe) : undefined);
  if (!found) {
    throw new Error('Julia not found: pass --julia <path>, set $JULIA, or add julia to PATH');
  }
  return found;
}

function projectAt(io: Io, dir: string | undefined): JuliaProject {
  const start = resolve(io.cwd, dir ?? '.');
  const p = findProject(start);
  if (!p) {
    throw new Error(`no Project.toml at or above ${start}`);
  }
  return p;
}

const lint: Command = {
  name: 'lint',
  summary: 'Lint Julia code for invalidation / inference problems (abstract fields, non-const globals, piracy…)',
  args: '[paths…]',
  flags: {
    profile: { type: 'string', value: '<profile.json>', description: 'Also report methods / call sites recorded in a SnoopCompile profile (from `jest-julia analyze`)' },
    threshold: { type: 'number', description: 'Recorded invalidations at or above this count are warnings', default: 10 },
    ...LINT_FLAGS,
  },
  examples: ['jest-julia lint src/', 'jest-julia lint . --profile julia-profile.json --format sarif --out julia.sarif'],
  async run({ positionals, flags }, io) {
    const format = formatOf(flags.format);
    const threshold = failThreshold(flags['fail-on']);
    const rules = effectiveRules(JULIA_RULES, flags, io);
    const findings = await lintFiles(rules, positionals, io, !!flags.quiet);
    if (typeof flags.profile === 'string') {
      const profile = parseProfile(readFileSync(resolve(io.cwd, flags.profile), 'utf8'));
      for (const f of collectFiles(positionals, io.cwd, (lang) => lang === 'julia')) {
        const extra: Finding[] = runtimeFindings(profile, f.path, flags.threshold as number);
        if (extra.length) {
          findings.set(f.rel, [...(findings.get(f.rel) ?? []), ...extra]);
        }
      }
    }
    emit(io, renderFindings(format, io, { toolName: 'jest-julia', title: 'Julia invalidation / inference findings', rules, findings }), flags.out);
    return exitFor(findings, threshold);
  },
};

export function profileText(p: Profile, top: number): string {
  const s = summarize(p, top);
  const lines = [
    `Julia ${p.julia} · ${p.package || p.project} · ${p.createdAt}${p.workload ? ` · workload ${p.workload}` : ''}`,
    '',
    `Invalidation trees: ${s.trees}   MethodInstances invalidated: ${s.invalidated}`,
    ...(s.inferenceTime !== undefined ? [`Inference time: ${s.inferenceTime.toFixed(3)} s of ${s.totalTime!.toFixed(3)} s   Inference triggers: ${s.triggers}`] : ['No inference data (run analyze with a workload).']),
    '',
    'Top invalidating methods:',
    ...p.invalidations.slice(0, top).map((t) => `  ${String(t.ninvalidated).padStart(6)}  ${t.module}.${t.method}  (${t.reason})  ${t.file}:${t.line}`),
  ];
  if (!p.invalidations.length) {
    lines.push('  none');
  }
  if (p.inference) {
    lines.push('', 'Top methods by self inference time:');
    for (const r of flattenInference(p.inference.root).slice(0, top)) {
      lines.push(`  ${(r.self * 1000).toFixed(2).padStart(9)} ms  ${r.module}.${r.method}  ${r.file ? `${r.file}:${r.line}` : ''}`);
    }
  }
  const sites = [...triggersByCaller(p).values()].sort((a, b) => b.time - a.time).slice(0, top);
  if (sites.length) {
    lines.push('', 'Inference triggers (runtime dispatch):');
    sites.forEach((t) => lines.push(`  ${(t.time * 1000).toFixed(2).padStart(9)} ms  ${t.file}:${t.line} → ${t.callees.join(', ')}`));
  }
  p.warnings.forEach((w) => lines.push(`warning: ${w}`));
  return lines.join('\n') + '\n';
}

const report: Command = {
  name: 'report',
  summary: 'Summarise a profile JSON written by `jest-julia analyze` or the VS Code extension',
  args: '<profile.json>',
  flags: { top: { type: 'number', description: 'Rows per section', default: 10 }, json: { type: 'boolean', description: 'Print the parsed profile as JSON' }, out: REPORT_FLAGS.out },
  async run({ positionals, flags }, io) {
    if (!positionals[0]) {
      throw new UsageError('expected a profile JSON file');
    }
    const p = parseProfile(readFileSync(resolve(io.cwd, positionals[0]), 'utf8'));
    emit(io, flags.json ? JSON.stringify(p, null, 2) + '\n' : profileText(p, flags.top as number), flags.out);
    return 0;
  },
};

const analyze: Command = {
  name: 'analyze',
  summary: 'Record invalidations (@snoop_invalidations) and inference (@snoop_inference) with SnoopCompile.jl',
  args: '[project dir]',
  flags: {
    workload: { type: 'string', value: '<file.jl>', description: 'Workload run under @snoop_inference (default: snoop/workload.jl if present)' },
    julia: { type: 'string', value: '<path>', description: 'Julia executable' },
    out: { type: 'string', alias: 'o', value: '<file>', description: 'Where to write the profile JSON', default: 'julia-profile.json' },
    timeout: { type: 'number', value: '<minutes>', description: 'Abort after this many minutes', default: 30 },
    'max-invalidated': { type: 'number', description: 'Exit 1 if more MethodInstances are invalidated' },
  },
  examples: ['jest-julia analyze', 'jest-julia analyze MyPkg --workload snoop/workload.jl --out profile.json', 'jest-julia analyze --max-invalidated 0   # CI gate'],
  async run({ positionals, flags }, io) {
    const project = projectAt(io, positionals[0]);
    const julia = resolveJulia(flags.julia);
    const workload =
      typeof flags.workload === 'string'
        ? resolve(io.cwd, flags.workload)
        : existsSync(join(project.dir, 'snoop', 'workload.jl'))
          ? join(project.dir, 'snoop', 'workload.jl')
          : '';
    const toolEnv = join(cacheDir('jest-julia'), 'snoop-env');
    mkdirSync(toolEnv, { recursive: true });
    const out = resolve(io.cwd, flags.out as string);
    io.err(`profiling ${project.name || project.dir} with ${julia}${workload ? ` (workload ${relative(io.cwd, workload)})` : ' (invalidations only)'}\n`);
    const res = await run(julia, ['--startup-file=no', `--project=${project.dir}`, join(assetDir('scripts'), 'collect.jl'), out, toolEnv, project.name, workload], {
      cwd: project.dir,
      io,
      timeoutMs: (flags.timeout as number) * 60_000,
    });
    if (res.code !== 0) {
      io.err(`julia exited with code ${res.code}\n`);
      return 2;
    }
    const profile = parseProfile(readFileSync(out, 'utf8'));
    io.out(profileText(profile, 10));
    const max = flags['max-invalidated'] as number | undefined;
    return max !== undefined && summarize(profile).invalidated > max ? 1 : 0;
  },
};

function benchText(rows: Judgement[], baseline: string | null, tolerance: number): string {
  const lines = [baseline ? `Benchmarks vs ${baseline} (median time, tolerance ±${(tolerance * 100).toFixed(0)}%)` : 'Benchmarks (current tree)', ''];
  for (const r of rows) {
    const c = r.current;
    const b = r.baseline;
    lines.push(
      baseline
        ? `${r.time.toUpperCase().padEnd(11)} ${r.timeRatio !== undefined ? `${r.timeRatio.toFixed(3)}×` : '   —  '}  ${b ? formatNs(b.median_ns) : '—'} → ${c ? formatNs(c.median_ns) : '—'}  ${r.name}`
        : `${formatNs(c!.median_ns).padStart(10)}  ${c!.allocs} allocs  ${r.name}`,
    );
  }
  return lines.join('\n') + '\n';
}

const bench: Command = {
  name: 'bench',
  summary: 'Run benchmark/benchmarks.jl on a git baseline (temporary worktree) and the working tree, then judge',
  args: '[project dir]',
  flags: {
    baseline: { type: 'string', value: '<ref|none>', description: 'Git ref to compare against', default: 'HEAD' },
    seconds: { type: 'number', description: 'BenchmarkTools time budget per benchmark', default: 1 },
    tolerance: { type: 'number', description: 'Median-time change treated as noise', default: 0.05 },
    julia: { type: 'string', value: '<path>', description: 'Julia executable' },
    json: { type: 'boolean', description: 'Print judgements as JSON' },
    out: REPORT_FLAGS.out,
  },
  examples: ['jest-julia bench', 'jest-julia bench --baseline main --tolerance 0.1', 'jest-julia bench --baseline none'],
  async run({ positionals, flags }, io) {
    const project = projectAt(io, positionals[0]);
    const julia = resolveJulia(flags.julia);
    const suite = join(project.dir, 'benchmark', 'benchmarks.jl');
    if (!existsSync(suite)) {
      throw new Error(`no ${relative(io.cwd, suite)}; create one with "jest-julia init bench"`);
    }
    const toolEnv = join(cacheDir('jest-julia'), 'bench-env');
    mkdirSync(toolEnv, { recursive: true });
    const script = join(assetDir('scripts'), 'bench.jl');
    const runOne = async (dir: string, label: string): Promise<BenchRun> => {
      const out = join(cacheDir('jest-julia'), `bench-${label}-${process.pid}.json`);
      io.err(`running ${label} benchmarks…\n`);
      const res = await run(julia, ['--startup-file=no', `--project=${dir}`, script, suite, out, toolEnv, String(flags.seconds)], { cwd: dir, io });
      if (res.code !== 0) {
        throw new Error(`${label} benchmark run failed (julia exit ${res.code})`);
      }
      return parseBenchRun(readFileSync(out, 'utf8'));
    };
    const ref = flags.baseline === 'none' ? null : String(flags.baseline);
    let baseline: BenchRun | undefined;
    if (ref) {
      const git = (args: string[], cwd: string) => run('git', args, { cwd, io, quiet: true });
      const top = (await git(['rev-parse', '--show-toplevel'], project.dir)).stdout.trim();
      if (!top) {
        throw new Error('not a git repository; use --baseline none');
      }
      const wt = join(cacheDir('jest-julia'), `bench-baseline-${process.pid}`);
      await git(['worktree', 'remove', '--force', wt], top);
      if ((await git(['worktree', 'add', '--detach', wt, ref], top)).code !== 0) {
        throw new Error(`cannot check out ${ref}`);
      }
      try {
        baseline = await runOne(join(wt, relative(top, project.dir)), 'baseline');
      } finally {
        await git(['worktree', 'remove', '--force', wt], top);
      }
    }
    const current = await runOne(project.dir, 'current');
    const rows = judge(baseline ?? current, current, flags.tolerance as number);
    emit(io, flags.json ? JSON.stringify(rows, null, 2) + '\n' : benchText(rows, baseline ? ref : null, flags.tolerance as number), flags.out);
    return baseline && rows.some((r) => r.time === 'regression') ? 1 : 0;
  },
};

const init: Command = {
  name: 'init',
  summary: 'Create snoop/workload.jl, benchmark/benchmarks.jl or a GitHub Actions benchmark workflow',
  args: '<workload|bench|workflow> [project dir]',
  flags: { force: { type: 'boolean', description: 'Overwrite an existing file' } },
  async run({ positionals, flags }, io) {
    const [what, dir] = positionals;
    const project = projectAt(io, dir);
    const targets: Record<string, [string, string]> = {
      workload: [join(project.dir, 'snoop', 'workload.jl'), WORKLOAD_TEMPLATE(project.name)],
      bench: [join(project.dir, 'benchmark', 'benchmarks.jl'), BENCHMARK_TEMPLATE(project.name)],
      workflow: [join(project.dir, '.github', 'workflows', 'benchmark.yml'), WORKFLOW_TEMPLATE],
    };
    const t = targets[what];
    if (!t) {
      throw new UsageError('expected workload, bench or workflow');
    }
    if (existsSync(t[0]) && !flags.force) {
      io.err(`${relative(io.cwd, t[0])} exists (use --force to overwrite)\n`);
      return 1;
    }
    mkdirSync(join(t[0], '..'), { recursive: true });
    writeFileSync(t[0], t[1]);
    io.out(`created ${relative(io.cwd, t[0])}\n`);
    return 0;
  },
};

export const JULIA_TOOL: Tool = {
  name: 'jest-julia',
  version: VERSION,
  summary: 'Julia Invalidation & Compiler Profiler',
  commands: [lint, analyze, report, bench, init],
  footer: 'Julia is located via --julia, $JULIA, PATH or ~/.juliaup. SnoopCompile / BenchmarkTools are installed into a private cache environment; your Project.toml is not modified.',
};

export const main = (argv: readonly string[], io?: Io) => runTool(JULIA_TOOL, argv, io);
