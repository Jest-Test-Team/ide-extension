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

  test('makes no network request unless the Marketplace lookup is opted in', async () => {
    // The test runs in the extension host, so stubbing fetch here also covers the extension. Other
    // built-in extensions share the host (e.g. the experiments service), so only the endpoints this
    // scanner can contact are counted.
    const ours = /^https:\/\/(marketplace\.visualstudio\.com|raw\.githubusercontent\.com)\//;
    const cfg = () => vscode.workspace.getConfiguration('endpointSecurity.extensionScan');
    const original = globalThis.fetch;
    const requested: string[] = [];
    globalThis.fetch = ((input: string | URL | Request) => {
      const url = String(input instanceof Request ? input.url : input);
      if (ours.test(url)) {
        requested.push(url);
      }
      return Promise.reject(new Error('network disabled in test'));
    }) as typeof fetch;
    try {
      await vscode.commands.executeCommand('endpointSecurity.scanExtensions', { force: true });
      assert.deepStrictEqual(requested, [], 'no request with the defaults');
      // Positive control: the stub does see the extension's requests once the user opts in.
      await cfg().update('marketplaceLookup', true, vscode.ConfigurationTarget.Global);
      await vscode.commands.executeCommand('endpointSecurity.scanExtensions');
      assert.deepStrictEqual(requested, ['https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery']);
    } finally {
      globalThis.fetch = original;
      await cfg().update('marketplaceLookup', undefined, vscode.ConfigurationTarget.Global);
    }
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
