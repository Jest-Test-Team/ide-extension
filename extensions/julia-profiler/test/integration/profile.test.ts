import * as assert from 'assert';
import * as vscode from 'vscode';

suite('profile views', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;

  test('loads a recorded profile and opens the report', async () => {
    const profile = (await vscode.commands.executeCommand(
      'juliaProfiler.openProfile',
      vscode.Uri.joinPath(root, 'invdemo.profile.json'),
    )) as { invalidations: unknown[] } | undefined;
    assert.ok(profile, 'profile not loaded');
    assert.strictEqual(profile.invalidations.length, 1);
    await vscode.commands.executeCommand('juliaProfiler.showFlameGraph');
    let tabs: string[] = [];
    for (let i = 0; i < 40 && !tabs.includes('Julia Compiler Profile'); i++) {
      await new Promise((r) => setTimeout(r, 50));
      tabs = vscode.window.tabGroups.all.flatMap((g) => g.tabs).map((t) => t.label);
    }
    assert.ok(tabs.includes('Julia Compiler Profile'), `tabs: ${tabs.join(', ')}`);
  });
});
