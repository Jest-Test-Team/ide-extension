import { openWebview, runProcess } from '@ide-ext/core/vscode';
import { existsSync, mkdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import * as vscode from 'vscode';
import { BENCHMARK_TEMPLATE, judge, parseBenchRun, WORKFLOW_TEMPLATE, type BenchRun, type Judgement } from './bench';
import { currentProject } from './analyze';
import { resolveJulia } from './julia';

async function git(args: string[], cwd: string, output: vscode.OutputChannel): Promise<string | undefined> {
  try {
    const res = await runProcess('git', args, { cwd, output });
    return res.code === 0 ? res.stdout.trim() : undefined;
  } catch {
    return undefined; // git not installed
  }
}

async function pickBaseline(repo: string, output: vscode.OutputChannel): Promise<string | null | undefined> {
  const branches = ((await git(['for-each-ref', '--format=%(refname:short)', 'refs/heads', 'refs/remotes'], repo, output)) ?? '')
    .split('\n')
    .filter((b) => b && !b.endsWith('/HEAD'));
  const items: (vscode.QuickPickItem & { ref: string | null })[] = [
    { label: 'HEAD', description: 'last commit (compare uncommitted changes)', ref: 'HEAD' },
    ...branches.map((b) => ({ label: b, ref: b })),
    { label: '$(edit) Enter a commit, tag or ref…', ref: '' },
    { label: '$(circle-slash) No baseline', description: 'run the current tree only', ref: null },
  ];
  const pick = await vscode.window.showQuickPick(items, { title: 'Baseline to compare against' });
  if (!pick) {
    return undefined;
  }
  if (pick.ref === '') {
    return (await vscode.window.showInputBox({ prompt: 'Git ref for the baseline' }))?.trim() || undefined;
  }
  return pick.ref;
}

export async function createBenchmarkSuite(): Promise<void> {
  const project = currentProject();
  if (!project) {
    void vscode.window.showWarningMessage('No Julia project (Project.toml) found in the workspace.');
    return;
  }
  const uri = vscode.Uri.file(join(project.dir, 'benchmark', 'benchmarks.jl'));
  if (!existsSync(uri.fsPath)) {
    await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(BENCHMARK_TEMPLATE(project.name)));
  }
  await vscode.window.showTextDocument(uri);
}

export async function createBenchmarkWorkflow(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return;
  }
  const uri = vscode.Uri.joinPath(folder.uri, '.github', 'workflows', 'benchmark.yml');
  if (existsSync(uri.fsPath)) {
    const ok = await vscode.window.showWarningMessage(`${vscode.workspace.asRelativePath(uri)} exists. Overwrite?`, { modal: true }, 'Overwrite');
    if (!ok) {
      return;
    }
  }
  await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(WORKFLOW_TEMPLATE));
  await vscode.window.showTextDocument(uri);
}

export interface RunBenchmarksArgs {
  /** Git ref for the baseline, or null for no comparison. Skips the picker when given. */
  baseline?: string | null;
}

export async function runBenchmarks(
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
  args: RunBenchmarksArgs = {},
): Promise<Judgement[] | undefined> {
  const julia = resolveJulia();
  const project = currentProject();
  if (!julia || !project) {
    void vscode.window.showErrorMessage(!julia ? 'Julia executable not found (juliaProfiler.executablePath).' : 'No Julia project found.');
    return undefined;
  }
  const suite = join(project.dir, 'benchmark', 'benchmarks.jl');
  if (!existsSync(suite)) {
    const create = await vscode.window.showWarningMessage('No benchmark/benchmarks.jl in this project.', 'Create Suite');
    if (create) {
      await createBenchmarkSuite();
    }
    return undefined;
  }
  const repo = await git(['rev-parse', '--show-toplevel'], project.dir, output);
  const baselineRef = !repo ? null : args.baseline !== undefined ? args.baseline : await pickBaseline(repo, output);
  if (baselineRef === undefined) {
    return undefined;
  }
  const cfg = vscode.workspace.getConfiguration('juliaProfiler');
  const seconds = cfg.get<number>('benchmark.seconds', 1);
  const tolerance = cfg.get<number>('benchmark.timeTolerance', 0.05);
  const storage = context.globalStorageUri.fsPath;
  const toolEnv = join(storage, 'bench-env');
  mkdirSync(toolEnv, { recursive: true });
  const script = join(context.extensionPath, 'dist', 'scripts', 'bench.jl');
  output.show(true);

  return vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Julia benchmarks', cancellable: true },
    async (progress, token) => {
      const runOne = async (dir: string, label: string): Promise<BenchRun | undefined> => {
        progress.report({ message: label });
        const out = join(storage, `bench-${label}-${Date.now()}.json`);
        const res = await runProcess(julia, ['--startup-file=no', `--project=${dir}`, script, suite, out, toolEnv, String(seconds)], {
          cwd: dir,
          token,
          output,
        });
        if (res.code !== 0) {
          if (!res.cancelled) {
            void vscode.window.showErrorMessage(`Benchmark run (${label}) failed; see the "Julia Profiler" output.`);
          }
          return undefined;
        }
        return parseBenchRun(new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.file(out))));
      };

      let baseline: BenchRun | undefined;
      if (baselineRef && repo) {
        const wt = join(storage, 'bench-baseline');
        await git(['worktree', 'remove', '--force', wt], repo, output);
        await git(['worktree', 'prune'], repo, output);
        if ((await git(['worktree', 'add', '--detach', wt, baselineRef], repo, output)) === undefined) {
          void vscode.window.showErrorMessage(`Could not check out ${baselineRef}; see the output channel.`);
          return undefined;
        }
        try {
          baseline = await runOne(join(wt, relative(repo, project.dir)), 'baseline');
        } finally {
          await git(['worktree', 'remove', '--force', wt], repo, output);
        }
        if (!baseline) {
          return undefined;
        }
      }
      const current = await runOne(project.dir, 'current');
      if (!current) {
        return undefined;
      }
      const rows = judge(baseline ?? current, current, tolerance);
      openWebview({
        context,
        viewType: 'juliaProfiler.bench',
        title: 'Julia Benchmarks',
        script: 'bench.js',
        initialMessage: {
          type: 'bench',
          rows,
          baselineRef: baseline ? baselineRef : null,
          tolerance,
          julia: current.julia,
          createdAt: new Date().toISOString(),
        },
      });
      return rows;
    },
  );
}
