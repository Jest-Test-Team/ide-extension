import * as assert from 'assert';
import * as vscode from 'vscode';

suite('activation', () => {
  test('pack activates and registers its CLI commands', async () => {
    const ext = vscode.extensions.getExtension('jest-test-team.security-pack');
    assert.ok(ext, 'extension not found');
    await ext.activate();
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.includes('securityPack.installCli'));
  });
});
