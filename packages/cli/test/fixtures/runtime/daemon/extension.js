// Runtime-audit test fixture: leaves a harmless `sleep` running after the extension host exits.
'use strict';
const { spawn } = require('child_process');

function activate() {
  spawn('sleep', ['30'], { detached: true, stdio: 'ignore' }).unref();
}

module.exports = { activate, deactivate() {} };
