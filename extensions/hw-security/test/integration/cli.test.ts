import * as assert from 'assert';
import { execFileSync } from 'child_process';
import { existsSync, mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import * as vscode from 'vscode';

suite('command-line tool', () => {
  test('installs a working jest-hw shim and removes it again', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jest-cli-'));
    const paths = (await vscode.commands.executeCommand('hwSecurity.installCli', { dir })) as string[];
    assert.ok(paths.length > 0, 'nothing installed');
    const shim = paths[0];
    assert.ok(readFileSync(shim, 'utf8').includes('jest-cli-shim'));
    const out = process.platform === 'win32'
      ? execFileSync('cmd.exe', ['/c', shim, '--version'], { encoding: 'utf8' })
      : execFileSync(shim, ['--version'], { encoding: 'utf8' });
    const expected = (vscode.extensions.getExtension('jest-test-team.hw-security')!.packageJSON as { version: string }).version;
    assert.strictEqual(out.trim(), expected);
    const removed = (await vscode.commands.executeCommand('hwSecurity.uninstallCli', { dir })) as string[];
    assert.deepStrictEqual(removed, paths);
    assert.ok(!existsSync(shim));
  });
});
