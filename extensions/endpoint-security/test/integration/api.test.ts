import * as assert from 'assert';
import * as vscode from 'vscode';

const code = (d: vscode.Diagnostic) => (typeof d.code === 'object' ? String(d.code.value) : String(d.code));

suite('WFP / ETW / ESF API support', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;
  const esf = vscode.Uri.joinPath(root, 'agent', 'esf_client.c');

  test('reports a leaked ES client and missing AUTH response', async () => {
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(esf));
    let diags: vscode.Diagnostic[] = [];
    for (let i = 0; i < 100 && !diags.some((d) => code(d) === 'edr/esf-auth-no-response'); i++) {
      await new Promise((r) => setTimeout(r, 100));
      diags = vscode.languages.getDiagnostics(esf);
    }
    const codes = diags.map(code);
    assert.ok(codes.includes('edr/missing-cleanup'), codes.join(','));
    assert.ok(codes.includes('edr/esf-auth-no-response'), codes.join(','));
  });

  test('hovers API documentation', async () => {
    const doc = await vscode.workspace.openTextDocument(esf);
    const line = doc.getText().split('\n').findIndex((l) => l.includes('es_new_client('));
    const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
      'vscode.executeHoverProvider',
      esf,
      new vscode.Position(line, doc.lineAt(line).text.indexOf('es_new_client') + 3),
    );
    const text = hovers.flatMap((h) => h.contents.map((c) => (typeof c === 'string' ? c : c.value))).join('\n');
    assert.ok(text.includes('es_new_client_result_t es_new_client('), text);
    assert.ok(text.includes('es_delete_client'));
  });
});
