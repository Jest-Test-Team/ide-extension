import * as vscode from 'vscode';

export interface WebviewOptions<In> {
  context: vscode.ExtensionContext;
  viewType: string;
  title: string;
  /** Bundled browser script under `dist/web/`, e.g. `flame.js`. */
  script: string;
  /** Sent once the page reports `ready` (and again whenever `update` is called). */
  initialMessage?: unknown;
  onMessage?: (msg: In, panel: vscode.WebviewPanel) => void;
  column?: vscode.ViewColumn;
  /** Panels with the same key are reused instead of opening another tab. */
  key?: string;
}

export interface WebviewHandle {
  panel: vscode.WebviewPanel;
  /** Replaces the page's data: posts now if ready, otherwise once the page loads. */
  update(msg: unknown): void;
  post(msg: unknown): Thenable<boolean>;
}

const open = new Map<string, WebviewHandle>();

export function openWebview<In extends { type: string } = { type: string }>(opts: WebviewOptions<In>): WebviewHandle {
  const key = `${opts.viewType}:${opts.key ?? ''}`;
  const existing = open.get(key);
  if (existing) {
    existing.panel.title = opts.title;
    existing.panel.reveal(opts.column);
    if (opts.initialMessage !== undefined) {
      existing.update(opts.initialMessage);
    }
    return existing;
  }
  const webRoot = vscode.Uri.joinPath(opts.context.extensionUri, 'dist', 'web');
  const panel = vscode.window.createWebviewPanel(opts.viewType, opts.title, opts.column ?? vscode.ViewColumn.Beside, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [webRoot],
  });
  let ready = false;
  let pending = opts.initialMessage;
  const handle: WebviewHandle = {
    panel,
    post: (msg) => panel.webview.postMessage(msg),
    update: (msg) => {
      pending = msg;
      if (ready) {
        void panel.webview.postMessage(msg);
      }
    },
  };
  panel.webview.html = html(panel.webview, vscode.Uri.joinPath(webRoot, opts.script), opts.title);
  panel.webview.onDidReceiveMessage((msg: In) => {
    if (msg?.type === 'ready') {
      ready = true;
      if (pending !== undefined) {
        void panel.webview.postMessage(pending);
      }
      return;
    }
    if (msg?.type === 'openLocation') {
      void openLocation(msg as unknown as { file: string; line?: number });
      return;
    }
    opts.onMessage?.(msg, panel);
  });
  panel.onDidDispose(() => open.delete(key));
  open.set(key, handle);
  return handle;
}

/** Shared handler for `{type: 'openLocation', file, line}` messages (1-based line). */
export async function openLocation(loc: { file: string; line?: number }): Promise<void> {
  let uri: vscode.Uri;
  if (/^[a-z][\w+.-]+:/i.test(loc.file) && !/^[a-z]:[\\/]/i.test(loc.file)) {
    uri = vscode.Uri.parse(loc.file);
  } else if (loc.file.startsWith('/') || /^[a-z]:[\\/]/i.test(loc.file)) {
    uri = vscode.Uri.file(loc.file);
  } else {
    const matches = await vscode.workspace.findFiles(`**/${loc.file}`, '**/node_modules/**', 1);
    if (!matches.length) {
      void vscode.window.showWarningMessage(`Cannot find ${loc.file} in the workspace.`);
      return;
    }
    uri = matches[0];
  }
  const line = Math.max(0, (loc.line ?? 1) - 1);
  await vscode.window.showTextDocument(uri, {
    selection: new vscode.Range(line, 0, line, 0),
    viewColumn: vscode.ViewColumn.One,
  });
}

function html(webview: vscode.Webview, script: vscode.Uri, title: string): string {
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data:; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title.replace(/</g, '&lt;')}</title>
<style>${BASE_CSS}</style>
</head>
<body>
<div id="app"><p class="muted">Loading…</p></div>
<script nonce="${nonce}" src="${webview.asWebviewUri(script)}"></script>
</body>
</html>`;
}

/** Theme-aware base styles shared by every webview. */
const BASE_CSS = `
:root { color-scheme: light dark; }
body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 0 16px 24px; }
h1 { font-size: 1.4em; font-weight: 600; } h2 { font-size: 1.15em; font-weight: 600; margin-top: 1.6em; }
.muted { color: var(--vscode-descriptionForeground); }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,.3)); font-variant-numeric: tabular-nums; }
th { font-weight: 600; color: var(--vscode-descriptionForeground); }
td.num, th.num { text-align: right; }
a, .link { color: var(--vscode-textLink-foreground); cursor: pointer; text-decoration: none; } a:hover, .link:hover { text-decoration: underline; }
button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 4px 12px; border-radius: 2px; cursor: pointer; }
button:hover { background: var(--vscode-button-hoverBackground); }
button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
input, select { background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, transparent); padding: 3px 6px; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 8px; font-size: .85em; }
.pass { color: var(--vscode-testing-iconPassed, #3fb950); } .fail { color: var(--vscode-testing-iconFailed, #f85149); } .warn { color: var(--vscode-editorWarning-foreground, #d29922); }
.toolbar { display: flex; gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 8px; margin: 12px 0; }
.card { border: 1px solid var(--vscode-panel-border, rgba(128,128,128,.3)); border-radius: 4px; padding: 8px 12px; }
.card .v { font-size: 1.5em; font-weight: 600; font-variant-numeric: tabular-nums; } .card .k { color: var(--vscode-descriptionForeground); font-size: .9em; }
svg text { fill: var(--vscode-foreground); font-family: var(--vscode-font-family); }
.tooltip { position: fixed; pointer-events: none; background: var(--vscode-editorHoverWidget-background); border: 1px solid var(--vscode-editorHoverWidget-border); padding: 4px 8px; font-size: .9em; max-width: 520px; white-space: pre-wrap; z-index: 10; }
`;
