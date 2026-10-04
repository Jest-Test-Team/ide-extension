import * as assert from 'assert';
import * as vscode from 'vscode';

suite('side-channel tags', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;
  const script = vscode.Uri.joinPath(root, 'sca', 'analysis', 'cpa_attack.py');

  suiteSetup(async () => {
    await vscode.commands.executeCommand('hwSecurity.refreshSca');
  });

  test('jumps from @sca-ref in Python to the firmware tag', async () => {
    const doc = await vscode.workspace.openTextDocument(script);
    const line = doc.getText().split('\n').findIndex((l) => l.includes('@sca-ref(aes-sbox)'));
    const col = doc.lineAt(line).text.indexOf('aes-sbox') + 2;
    const locs = await vscode.commands.executeCommand<(vscode.Location | vscode.LocationLink)[]>(
      'vscode.executeDefinitionProvider',
      script,
      new vscode.Position(line, col),
    );
    const uris = locs.map((l) => ('uri' in l ? l.uri : l.targetUri).path);
    assert.ok(uris.some((p) => p.endsWith('firmware/aes.c')), uris.join(', '));
  });

  test('flags references without a firmware tag', async () => {
    let diags: vscode.Diagnostic[] = [];
    for (let i = 0; i < 50 && !diags.length; i++) {
      await new Promise((r) => setTimeout(r, 100));
      diags = vscode.languages.getDiagnostics(script);
    }
    assert.ok(diags.some((d) => d.code === 'sca/orphan-ref' && d.message.includes('modexp-branch')), diags.map((d) => d.message).join('\n'));
  });
});
