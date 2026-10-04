import * as assert from 'assert';
import * as vscode from 'vscode';

suite('compliance scan', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;

  test('scans the workspace and exports SARIF', async () => {
    const out = vscode.Uri.joinPath(root, '..', '..', 'out', 'compliance.sarif');
    await vscode.commands.executeCommand('endpointSecurity.exportReport', out);
    const sarif = JSON.parse(new TextDecoder().decode(await vscode.workspace.fs.readFile(out))) as {
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[];
    };
    const results = sarif.runs[0].results;
    assert.ok(results.some((r) => r.ruleId === 'pci/tls-verification-disabled'));
    assert.ok(results.some((r) => r.locations[0].physicalLocation.artifactLocation.uri === 'backend/payments.go'));
    assert.ok(results.every((r) => /^(pci|ccsp)\//.test(r.ruleId)));
    assert.ok(sarif.runs[0].tool.driver.rules.length > 5);
  });
});
