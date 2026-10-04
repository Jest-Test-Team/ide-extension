import * as assert from 'assert';
import * as vscode from 'vscode';

suite('entropy & PUF', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;

  test('assesses a NIST sample file in a worker thread', async () => {
    const result = (await vscode.commands.executeCommand('hwSecurity.assessEntropy', vscode.Uri.joinPath(root, 'entropy', 'rand8_short.bin'), {
      wordSize: 8,
    })) as { hAssessed: number; wordSize: number } | undefined;
    assert.ok(result, 'no result');
    assert.strictEqual(result.wordSize, 8);
    // NIST ea_non_iid reports 5.860893744485249 for this file.
    assert.ok(Math.abs(result.hAssessed - 5.860893744485249) < 1e-9, String(result.hAssessed));
  });

  test('analyses PUF responses', async () => {
    const out = (await vscode.commands.executeCommand('hwSecurity.analyzePuf', vscode.Uri.joinPath(root, 'puf', 'sram.csv'))) as
      | { report: { devices: number; uniqueness: number; reliability: number }; ecc: { t?: number } }
      | undefined;
    assert.ok(out);
    assert.strictEqual(out.report.devices, 8);
    assert.ok(out.report.uniqueness > 0.4 && out.report.uniqueness < 0.6);
    assert.ok(out.report.reliability > 0.9);
    assert.ok(out.ecc.t !== undefined && out.ecc.t > 0);
  });
});
