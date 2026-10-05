// Scanner test fixture: the shape of an ordinary language-server client.
'use strict';
const { spawn } = require('child_process');
const path = require('path');

function startServer(context) {
  const serverModule = path.join(context.extensionPath, 'server', 'main.js');
  const plugin = require(serverModule);
  const validate = new Function('data', 'return typeof data === "object";');
  return { proc: spawn('foo-language-server', ['--stdio']), plugin, validate };
}

module.exports = { activate: startServer, deactivate() {} };
