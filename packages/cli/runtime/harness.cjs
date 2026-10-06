'use strict';
// Headless harness: `node --require audit-agent.cjs harness.cjs <extension dir> <workspace> <seconds> [--invoke-commands]`
// Loads the extension with a recording `vscode` mock, activates it, fires document / editor events
// with decoy content, optionally runs every registered command, then deactivates after <seconds>.
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');
const { createMock } = require('./vscode-mock.cjs');

const [extDir, wsDir, secondsArg, ...flags] = process.argv.slice(2);
const seconds = Number(secondsArg) || 30;
const audit = globalThis.__jestAudit || { record() {}, wrapVscode: (x) => x };
const mock = createMock({ workspace: wsDir, record: audit.record });
const api = audit.wrapVscode(mock.vscode);

const load = Module._load;
Module._load = function (request, ...rest) {
  return request === 'vscode' ? api : load.call(this, request, ...rest);
};

process.on('uncaughtException', (e) => audit.record('error', { where: 'uncaught', message: String(e && e.stack ? e.stack : e).slice(0, 500) }, true));
process.on('unhandledRejection', (e) => audit.record('error', { where: 'unhandledRejection', message: String(e && e.stack ? e.stack : e).slice(0, 500) }, true));

const memento = () => {
  const m = new Map();
  return { get: (k, d) => (m.has(k) ? m.get(k) : d), update: async (k, v) => void m.set(k, v), keys: () => [...m.keys()], setKeysForSync() {} };
};
const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'jest-audit-storage-'));
const context = {
  subscriptions: [],
  extensionPath: extDir,
  extensionUri: api.Uri.file(extDir),
  globalState: memento(),
  workspaceState: memento(),
  secrets: {
    get: async (k) => (audit.record('vscode', { api: 'secrets.get', key: String(k) }, true), `${mock.honey}_SECRET`),
    store: async (k) => audit.record('vscode', { api: 'secrets.store', key: String(k) }, true),
    delete: async () => undefined,
    onDidChange: () => ({ dispose() {} }),
  },
  globalStorageUri: api.Uri.file(path.join(storage, 'global')),
  storageUri: api.Uri.file(path.join(storage, 'workspace')),
  logUri: api.Uri.file(path.join(storage, 'log')),
  globalStoragePath: path.join(storage, 'global'),
  storagePath: path.join(storage, 'workspace'),
  logPath: path.join(storage, 'log'),
  extensionMode: 1,
  asAbsolutePath: (p) => path.join(extDir, p),
  environmentVariableCollection: { replace() {}, append() {}, prepend() {}, get() {}, delete() {}, clear() {}, persistent: true },
  extension: { id: 'audited.extension', extensionPath: extDir, packageJSON: {} },
};

const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(r, ms))]);

async function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(extDir, 'package.json'), 'utf8'));
  context.extension.packageJSON = pkg;
  const entry = pkg.main ? path.resolve(extDir, pkg.main) : undefined;
  if (!entry) {
    audit.record('harness', { phase: 'skip', reason: 'no main entry (web or declarative extension)' }, true);
    return;
  }
  audit.record('harness', { phase: 'load', entry }, true);
  const ext = require(entry);
  if (typeof ext.activate === 'function') {
    audit.record('harness', { phase: 'activate' }, true);
    await withTimeout(Promise.resolve().then(() => ext.activate(context)), 15000).catch((e) => audit.record('error', { where: 'activate', message: String(e && e.stack ? e.stack : e).slice(0, 500) }, true));
  }
  // Simulated user activity with decoy content, so listeners that leak documents get exercised.
  const doc = mock.decoyDoc();
  const fire = (name, arg) => (mock.listeners.get(name) || []).forEach((fn) => { try { fn(arg); } catch (e) { audit.record('error', { where: name, message: String(e).slice(0, 300) }, true); } });
  fire('workspace.onDidOpenTextDocument', doc);
  fire('workspace.onDidChangeTextDocument', { document: doc, contentChanges: [{ text: 'x' }] });
  fire('workspace.onDidSaveTextDocument', doc);
  fire('window.onDidChangeActiveTextEditor', { document: doc, selection: {} });
  fire('webview.onDidReceiveMessage', { command: 'run', text: `${mock.honey}_WEBVIEW` });
  if (flags.includes('--invoke-commands')) {
    for (const [id, fn] of mock.commands) {
      audit.record('harness', { phase: 'invoke', id }, true);
      await withTimeout(Promise.resolve().then(() => fn()), 3000).catch((e) => audit.record('error', { where: id, message: String(e).slice(0, 300) }, true));
    }
  }
  await new Promise((r) => setTimeout(r, seconds * 1000));
  if (typeof ext.deactivate === 'function') {
    await withTimeout(Promise.resolve().then(() => ext.deactivate()), 3000).catch(() => undefined);
  }
}

main()
  .catch((e) => audit.record('error', { where: 'load', message: String(e && e.stack ? e.stack : e).slice(0, 500) }, true))
  .finally(() => {
    audit.record('harness', { phase: 'done' }, true);
    process.exit(0);
  });
