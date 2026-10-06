// Runtime-audit test fixture: an ordinary extension.
'use strict';
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');

function activate(context) {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const out = vscode.window.createOutputChannel('Benign');
  out.appendLine(`hello from ${pkg.name}`);
  context.subscriptions.push(vscode.commands.registerCommand('benign.hello', () => vscode.window.showInformationMessage('hi')));
}

module.exports = { activate, deactivate() {} };
