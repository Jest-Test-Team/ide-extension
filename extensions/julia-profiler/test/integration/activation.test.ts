import * as assert from 'assert';
import * as vscode from 'vscode';

suite('activation', () => {
  test('extension activates and registers commands', async () => {
    const ext = vscode.extensions.getExtension('jest-test-team.julia-profiler');
    assert.ok(ext, 'extension not found');
    await ext.activate();
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.some((c) => c.startsWith('juliaProfiler.')));
  });
});
