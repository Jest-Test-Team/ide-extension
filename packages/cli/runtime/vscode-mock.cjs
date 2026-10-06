'use strict';
// A recording stand-in for the `vscode` module, used by the headless harness. Calls that matter for
// the audit (terminals, commands, webviews, debug hooks, settings, clipboard, auth) are recorded via
// the audit agent; everything else returns harmless values so activation code keeps running.
const fs = require('fs');
const path = require('path');

const HONEY = 'DECOY-JEST-AUDIT';

function createMock({ workspace: wsDir, record }) {
  const rec = (api, data = {}) => record('vscode', { api, ...data }, true);
  const listeners = new Map();
  const commands = new Map();

  class Disposable {
    constructor(fn) {
      this._fn = fn;
    }
    static from(...ds) {
      return new Disposable(() => ds.forEach((d) => d && d.dispose && d.dispose()));
    }
    dispose() {
      if (this._fn) {
        this._fn();
      }
    }
  }
  const disposable = () => new Disposable(() => undefined);
  class EventEmitter {
    constructor() {
      this._l = [];
      this.event = (fn) => (this._l.push(fn), disposable());
    }
    fire(e) {
      this._l.forEach((fn) => fn(e));
    }
    dispose() {}
  }
  /** An event whose listeners the harness can fire later. */
  const event = (name) => (fn) => {
    const list = listeners.get(name) || [];
    list.push(fn);
    listeners.set(name, list);
    rec(`listen:${name}`);
    return disposable();
  };
  const uri = (p) => ({ scheme: 'file', fsPath: p, path: p.replace(/\\/g, '/'), toString: () => `file://${p}`, with: () => uri(p) });
  const Uri = { file: uri, parse: (s) => uri(String(s).replace(/^file:\/\//, '')), joinPath: (base, ...parts) => uri(path.join(base.fsPath, ...parts)) };

  const document = (file, text) => ({
    uri: uri(file),
    fileName: file,
    languageId: 'plaintext',
    version: 1,
    lineCount: text.split('\n').length,
    getText: () => (rec('document.getText', { file }), text),
    lineAt: (n) => ({ text: text.split('\n')[n] || '' }),
    save: async () => true,
  });
  const decoyDoc = () => document(path.join(wsDir, 'app.js'), `const token = "ghp_${HONEY}_DOCUMENT";\n`);

  const terminal = (opts) => ({
    name: (opts && opts.name) || String(opts || 'terminal'),
    processId: Promise.resolve(undefined),
    sendText: (text, addNewLine) => rec('terminal.sendText', { text: String(text).slice(0, 300), addNewLine }),
    show: () => undefined,
    hide: () => undefined,
    dispose: () => undefined,
  });
  const webview = (options) => {
    let html = '';
    return {
      options,
      cspSource: 'vscode-resource:',
      get html() {
        return html;
      },
      set html(v) {
        html = String(v);
        rec('webview.html', { html: html.slice(0, 2000), enableScripts: !!(options && options.enableScripts) });
      },
      onDidReceiveMessage: event('webview.onDidReceiveMessage'),
      postMessage: async () => true,
      asWebviewUri: (u) => u,
    };
  };
  const outputChannel = () => ({ name: 'out', append() {}, appendLine() {}, replace() {}, clear() {}, show() {}, hide() {}, dispose() {}, trace() {}, debug() {}, info() {}, warn() {}, error() {}, logLevel: 2, onDidChangeLogLevel: event('log') });
  const config = (section) => ({
    get: (_k, d) => d,
    has: () => false,
    inspect: () => undefined,
    update: async (key, value) => rec('configuration.update', { key: section ? `${section}.${key}` : key, value: JSON.stringify(value).slice(0, 200) }),
  });

  /** Fallback for APIs not modelled: callable, constructible, never thenable or iterable trouble. */
  const generic = (name) =>
    new Proxy(function () {}, {
      get: (t, k) => {
        if (k === 'then') {return undefined;}
        if (k === Symbol.iterator) {return function* () {};}
        if (k === Symbol.toPrimitive) {return () => '';}
        if (k === 'dispose') {return () => undefined;}
        if (typeof k === 'symbol') {return undefined;}
        return generic(`${name}.${k}`);
      },
      apply: () => generic(`${name}()`),
      construct: () => generic(`new ${name}`),
    });

  const vscode = {
    version: '1.99.0',
    Disposable,
    EventEmitter,
    Uri,
    Range: class {},
    Position: class {},
    Selection: class {},
    ThemeIcon: class {},
    ThemeColor: class {},
    MarkdownString: class {
      constructor(v) {
        this.value = v || '';
      }
      appendMarkdown(v) {
        this.value += v;
        return this;
      }
    },
    TreeItem: class {},
    StatusBarAlignment: { Left: 1, Right: 2 },
    ViewColumn: { Active: -1, Beside: -2, One: 1, Two: 2 },
    ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
    ExtensionMode: { Production: 1, Development: 2, Test: 3 },
    commands: {
      registerCommand: (id, fn) => (commands.set(id, fn), rec('commands.registerCommand', { id }), disposable()),
      registerTextEditorCommand: (id, fn) => (commands.set(id, fn), rec('commands.registerCommand', { id }), disposable()),
      executeCommand: async (id, ...args) => rec('commands.executeCommand', { id, args: JSON.stringify(args).slice(0, 200) }),
      getCommands: async () => [...commands.keys()],
    },
    window: {
      activeTextEditor: undefined,
      visibleTextEditors: [],
      showInformationMessage: async () => undefined,
      showWarningMessage: async () => undefined,
      showErrorMessage: async () => undefined,
      showQuickPick: async () => undefined,
      showInputBox: async () => undefined,
      createOutputChannel: outputChannel,
      createStatusBarItem: () => ({ show() {}, hide() {}, dispose() {} }),
      createTerminal: (opts) => (rec('window.createTerminal', { options: JSON.stringify(opts || {}).slice(0, 300) }), terminal(opts)),
      createWebviewPanel: (viewType, title, col, options) => {
        rec('window.createWebviewPanel', { viewType, enableScripts: !!(options && options.enableScripts), enableCommandUris: !!(options && options.enableCommandUris) });
        return { webview: webview(options), onDidDispose: event('panel.dispose'), onDidChangeViewState: event('panel.state'), reveal() {}, dispose() {} };
      },
      registerWebviewViewProvider: (id) => (rec('window.registerWebviewViewProvider', { id }), disposable()),
      onDidChangeActiveTextEditor: event('window.onDidChangeActiveTextEditor'),
      onDidChangeTextEditorSelection: event('window.onDidChangeTextEditorSelection'),
      withProgress: async (_o, task) => task({ report() {} }, { isCancellationRequested: false, onCancellationRequested: event('cancel') }),
    },
    workspace: {
      workspaceFolders: [{ uri: uri(wsDir), name: path.basename(wsDir), index: 0 }],
      rootPath: wsDir,
      textDocuments: [],
      getConfiguration: config,
      onDidChangeConfiguration: event('workspace.onDidChangeConfiguration'),
      onDidChangeTextDocument: event('workspace.onDidChangeTextDocument'),
      onDidSaveTextDocument: event('workspace.onDidSaveTextDocument'),
      onDidOpenTextDocument: event('workspace.onDidOpenTextDocument'),
      findFiles: async (include) => {
        rec('workspace.findFiles', { include: String(include) });
        const out = [];
        const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : out.push(uri(path.join(d, e.name)))));
        walk(wsDir);
        return out;
      },
      openTextDocument: async (u) => {
        const file = typeof u === 'string' ? u : u && u.fsPath;
        return document(file, file && fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '');
      },
      fs: {
        readFile: async (u) => fs.readFileSync(u.fsPath),
        writeFile: async (u, data) => fs.writeFileSync(u.fsPath, data),
        stat: async (u) => fs.statSync(u.fsPath),
        readDirectory: async (u) => fs.readdirSync(u.fsPath, { withFileTypes: true }).map((e) => [e.name, e.isDirectory() ? 2 : 1]),
      },
      isTrusted: true,
    },
    env: {
      appName: 'Visual Studio Code',
      appRoot: path.dirname(process.execPath),
      uriScheme: 'vscode',
      language: 'en',
      machineId: 'decoy-machine-id',
      sessionId: 'decoy-session',
      isTelemetryEnabled: false,
      onDidChangeTelemetryEnabled: event('env.onDidChangeTelemetryEnabled'),
      clipboard: {
        readText: async () => (rec('env.clipboard.readText'), `ghp_${HONEY}_CLIPBOARD`),
        writeText: async () => undefined,
      },
      openExternal: async (u) => (rec('env.openExternal', { uri: String(u && (u.fsPath || u)) }), true),
      asExternalUri: async (u) => u,
    },
    extensions: { all: [], getExtension: () => undefined, onDidChange: event('extensions.onDidChange') },
    debug: {
      registerDebugAdapterTrackerFactory: (type) => (rec('debug.registerDebugAdapterTrackerFactory', { type }), disposable()),
      onDidStartDebugSession: event('debug.onDidStartDebugSession'),
      onDidReceiveDebugSessionCustomEvent: event('debug.onDidReceiveDebugSessionCustomEvent'),
      onDidTerminateDebugSession: event('debug.onDidTerminateDebugSession'),
      startDebugging: async () => (rec('debug.startDebugging'), true),
    },
    authentication: { getSession: async (provider, scopes) => (rec('authentication.getSession', { provider, scopes: JSON.stringify(scopes) }), undefined) },
    languages: { createDiagnosticCollection: () => ({ set() {}, delete() {}, clear() {}, dispose() {} }) },
  };
  const proxied = (obj, name) =>
    new Proxy(obj, {
      get: (t, k) => (k in t ? t[k] : typeof k === 'symbol' || k === 'then' ? undefined : generic(`${name}.${String(k)}`)),
    });
  for (const k of ['commands', 'window', 'workspace', 'env', 'extensions', 'debug', 'authentication', 'languages']) {
    vscode[k] = proxied(vscode[k], k);
  }
  return {
    vscode: proxied(vscode, 'vscode'),
    commands,
    listeners,
    decoyDoc,
    honey: HONEY,
  };
}

module.exports = { createMock, HONEY };
