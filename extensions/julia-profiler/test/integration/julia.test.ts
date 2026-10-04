import * as assert from 'assert';
import * as vscode from 'vscode';

// Runs real Julia only when JULIA_PROFILER_TEST_JULIA points at a julia binary (slow: installs
// SnoopCompile/BenchmarkTools on first use). CI without Julia skips these.
const julia = process.env.JULIA_PROFILER_TEST_JULIA;

(julia ? suite : suite.skip)('with Julia', function () {
  this.timeout(15 * 60_000);
  const root = vscode.workspace.workspaceFolders![0].uri;
  const pkgFile = vscode.Uri.joinPath(root, 'InvDemo', 'src', 'InvDemo.jl');

  suiteSetup(async () => {
    await vscode.workspace.getConfiguration('juliaProfiler').update('executablePath', julia, vscode.ConfigurationTarget.Global);
    await vscode.workspace.getConfiguration('juliaProfiler').update('benchmark.seconds', 0.2, vscode.ConfigurationTarget.Global);
    await vscode.window.showTextDocument(pkgFile);
  });

  test('profiles invalidations and inference with SnoopCompile', async () => {
    const profile = (await vscode.commands.executeCommand('juliaProfiler.analyze')) as
      | { invalidations: { method: string; ninvalidated: number }[]; inference: { root: unknown } | null }
      | undefined;
    assert.ok(profile, 'analysis failed');
    assert.ok(profile.invalidations.some((t) => t.method === '==' && t.ninvalidated > 0));
    assert.ok(profile.inference?.root, 'no inference data');
  });

  test('compares benchmarks against HEAD in a git worktree', async () => {
    const rows = (await vscode.commands.executeCommand('juliaProfiler.runBenchmarks', { baseline: 'HEAD' })) as
      | { name: string; time: string; timeRatio?: number }[]
      | undefined;
    assert.ok(rows, 'no benchmark results');
    assert.deepStrictEqual(rows.map((r) => r.name).sort(), ['process / float', 'process / range']);
    assert.ok(rows.every((r) => r.timeRatio !== undefined && r.timeRatio > 0));
  });
});
