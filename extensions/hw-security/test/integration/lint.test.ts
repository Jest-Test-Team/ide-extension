import * as assert from 'assert';
import * as vscode from 'vscode';

const code = (d: vscode.Diagnostic) => (typeof d.code === 'object' ? String(d.code.value) : String(d.code));

async function waitFor(uri: vscode.Uri, id: string): Promise<vscode.Diagnostic[]> {
  for (let i = 0; i < 100; i++) {
    const d = vscode.languages.getDiagnostics(uri);
    if (d.some((x) => code(x) === id)) {
      return d;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return vscode.languages.getDiagnostics(uri);
}

suite('ESP32 linter', () => {
  const root = vscode.workspace.workspaceFolders![0].uri;

  test('lints C sources and wraps ignored esp_err_t', async () => {
    const uri = vscode.Uri.joinPath(root, 'esp-app', 'main', 'csi_main.c');
    const doc = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(doc);
    const diags = await waitFor(uri, 'esp32/unchecked-esp-err');
    const err = diags.find((d) => code(d) === 'esp32/unchecked-esp-err');
    assert.ok(err, diags.map(code).join(','));
    assert.ok(diags.some((d) => code(d) === 'esp32/csi-callback-heavy'));
    const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>('vscode.executeCodeActionProvider', uri, err.range);
    const wrap = actions.find((a) => a.title === 'Wrap in ESP_ERROR_CHECK()');
    assert.ok(wrap?.edit, actions.map((a) => a.title).join(' | '));
  });

  test('scans sdkconfig and ESPHome YAML from disk', async () => {
    const n = await vscode.commands.executeCommand<number>('hwSecurity.scanWorkspace');
    assert.ok(n > 0);
    const sdk = vscode.languages.getDiagnostics(vscode.Uri.joinPath(root, 'esp-app', 'sdkconfig')).map(code);
    assert.ok(sdk.includes('esp32/secure-boot-disabled'), sdk.join(','));
    const yaml = vscode.languages.getDiagnostics(vscode.Uri.joinPath(root, 'esphome', 'livingroom.yaml')).map(code);
    assert.ok(yaml.includes('esphome/api-unencrypted'), yaml.join(','));
  });
});
