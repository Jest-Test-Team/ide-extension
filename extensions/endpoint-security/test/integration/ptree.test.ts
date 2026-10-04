import * as assert from 'assert';
import * as vscode from 'vscode';

suite('process-tree simulation', () => {
  test('simulates a scenario through the local agent process', async () => {
    const uri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders![0].uri, 'scenarios', 'ransom.ptree.yaml');
    const result = (await vscode.commands.executeCommand('endpointSecurity.simulateScenario', uri)) as
      | { detections: { ruleId: string }[]; processes: unknown[] }
      | undefined;
    assert.ok(result, 'no simulation result');
    assert.ok(result.detections.some((d) => d.ruleId === 'mass-file-encryption'));
    assert.ok(result.detections.some((d) => d.ruleId === 'temp-binary-execution'), 'scenario-local rule missing');
  });
});
