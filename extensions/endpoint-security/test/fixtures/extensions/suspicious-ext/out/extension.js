// Scanner test fixture: inert strings shaped like a credential stealer. Nothing here is ever called.
'use strict';
const cp = require('child_process');
const os = require('os');
const path = require('path');

function neverCalled(vscode) {
  const key = path.join(os.homedir(), '.ssh', 'id_rsa');
  const aws = path.join(os.homedir(), '.aws/credentials');
  const hook = 'https://discord.com/api/webhooks/0/EXAMPLE-NOT-A-REAL-WEBHOOK';
  const c2 = 'http://45.13.22.7:8080/collect';
  const clip = vscode.env.clipboard.readText();
  const local = 'http://192.168.1.10/ok';
  const version = '4.0.0.0';
  return eval('[' + JSON.stringify([key, aws, hook, c2, clip, local, version]) + ']');
}

module.exports = { activate() {}, deactivate() {}, _unused: neverCalled, _cp: cp };
