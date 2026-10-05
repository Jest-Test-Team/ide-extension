import * as assert from 'assert';
import * as vscode from 'vscode';

async function diagnosticsFor(uri: vscode.Uri, predicate: (d: vscode.Diagnostic[]) => boolean): Promise<vscode.Diagnostic[]> {
  for (let i = 0; i < 100; i++) {
    const d = vscode.languages.getDiagnostics(uri);
    if (predicate(d)) {
      return d;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return vscode.languages.getDiagnostics(uri);
}

const code = (d: vscode.Diagnostic) => (typeof d.code === 'object' ? String(d.code.value) : String(d.code));

suite('julia linter', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;
  const file = vscode.Uri.joinPath(root, 'InvDemo', 'src', 'InvDemo.jl');

  test('reports static findings with quick fixes', async () => {
    const doc = await vscode.workspace.openTextDocument(file);
    await vscode.window.showTextDocument(doc);
    const diags = await diagnosticsFor(file, (d) => d.some((x) => code(x) === 'julia/abstract-field'));
    const codes = new Set(diags.map(code));
    for (const id of ['julia/abstract-field', 'julia/nonconst-global', 'julia/untyped-container', 'julia/base-method-extension']) {
      assert.ok(codes.has(id), `missing ${id}; got ${[...codes].join(', ')}`);
    }
    const field = diags.find((d) => code(d) === 'julia/abstract-field')!;
    const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
      'vscode.executeCodeActionProvider',
      file,
      field.range,
    );
    assert.ok(actions.some((a) => a.title.startsWith('Make `x` a type parameter')), actions.map((a) => a.title).join(' | '));
    assert.ok(actions.some((a) => a.title.startsWith('Suppress julia/abstract-field')));
  });

  test('adds runtime findings from a loaded profile', async () => {
    const text = new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(root, 'invdemo.profile.json')));
    const local = text.split('/work/InvDemo').join(JSON.stringify(vscode.Uri.joinPath(root, 'InvDemo').fsPath).slice(1, -1));
    const tmp = vscode.Uri.joinPath(root, '..', '..', 'out', 'invdemo.local.json');
    await vscode.workspace.fs.writeFile(tmp, new TextEncoder().encode(local));
    await vscode.commands.executeCommand('juliaProfiler.openProfile', tmp);
    const diags = await diagnosticsFor(file, (d) => d.some((x) => code(x) === 'julia/runtime-invalidation'));
    const runtime = diags.find((d) => code(d) === 'julia/runtime-invalidation');
    assert.ok(runtime, 'no runtime invalidation diagnostic');
    assert.strictEqual(runtime.range.start.line, 9);
    assert.ok(runtime.message.includes('InvDemo.=='));
  });
});
