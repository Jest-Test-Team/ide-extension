import * as assert from 'assert';
import * as vscode from 'vscode';

interface ScanSummary {
  id: string;
  level: string;
  score: number;
  signals: string[];
}

suite('installed extension scan', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;
  let summaries: ScanSummary[];

  suiteSetup(async () => {
    await vscode.extensions.getExtension('jest-test-team.endpoint-security')!.activate();
    summaries = (await vscode.commands.executeCommand<ScanSummary[]>('endpointSecurity.scanExtensions', { force: true }))!;
  });

  test('scans the development extension through the worker', () => {
    // The test host runs with --disable-extensions and built-ins are skipped by default, so the
    // extension under test is what gets scanned. Its folder holds the scanner's own test fixtures
    // (test/fixtures/extensions), so the code signals prove the worker and rules ran end to end.
    const self = summaries.find((s) => s.id === 'jest-test-team.endpoint-security');
    assert.ok(self, `not scanned; got ${summaries.map((s) => s.id).join(', ')}`);
    for (const id of ['ext/credential-path', 'ext/exfil-endpoint', 'ext/obfuscated', 'ext/native-binary', 'ext/unknown-publisher']) {
      assert.ok(self.signals.includes(id), `${id} missing: ${self.signals.join(', ')}`);
    }
    assert.ok(!summaries.some((s) => s.id.startsWith('vscode.')), 'built-in extensions should be skipped');
  });

  test('exports SARIF and Markdown', async () => {
    const sarifUri = vscode.Uri.joinPath(root, '..', '..', 'out', 'extension-risk.sarif');
    await vscode.commands.executeCommand('endpointSecurity.exportExtensionReport', sarifUri);
    const sarif = JSON.parse(new TextDecoder().decode(await vscode.workspace.fs.readFile(sarifUri))) as {
      version: string;
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; message: { text: string } }[] }[];
    };
    assert.strictEqual(sarif.version, '2.1.0');
    const results = sarif.runs[0].results;
    assert.ok(results.some((r) => r.ruleId === 'ext/risk' && r.message.text.startsWith('jest-test-team.endpoint-security@')));
    assert.ok(results.some((r) => r.ruleId === 'ext/obfuscated.obfuscator'));
    const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((r) => r.id));
    assert.ok(results.every((r) => ruleIds.has(r.ruleId)), 'every result has rule metadata');

    const mdUri = vscode.Uri.joinPath(root, '..', '..', 'out', 'extension-risk.md');
    await vscode.commands.executeCommand('endpointSecurity.exportExtensionReport', mdUri);
    const md = new TextDecoder().decode(await vscode.workspace.fs.readFile(mdUri));
    assert.match(md, /^# Installed extension risk report/);
    assert.match(md, /\| Extension \| Version \| Risk \| Score \| Main reasons \|/);
  });

  test('allowlisting zeroes the score and is undone again', async () => {
    const cfg = () => vscode.workspace.getConfiguration('endpointSecurity.extensionScan');
    await cfg().update('allowlist', ['jest-test-team.endpoint-security'], vscode.ConfigurationTarget.Global);
    try {
      const again = (await vscode.commands.executeCommand<ScanSummary[]>('endpointSecurity.scanExtensions'))!;
      const self = again.find((s) => s.id === 'jest-test-team.endpoint-security')!;
      assert.deepStrictEqual([self.level, self.score], ['low', 0]);
      assert.ok(self.signals.length > 0, 'reasons are kept for allowlisted extensions');
    } finally {
      await cfg().update('allowlist', undefined, vscode.ConfigurationTarget.Global);
    }
  });
});
