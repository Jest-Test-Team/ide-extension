import type { Signal } from '../../../../extensions/endpoint-security/src/extscan/signals';
import type { Classified } from './classify';
import type { RuntimeEvent } from './run';

const PROC = 'runtime/child-process-spawned';
const FS = 'runtime/fs-access-violation';
const EVAL = 'runtime/dynamic-eval-execution';
const NET = 'runtime/dns-and-http-destinations';
const CLIP = 'runtime/clipboard-poll-frequency';
const RAW = 'runtime/network-raw-socket';
const RWX = 'runtime/mprotect-rwx';
const ORPHAN = 'runtime/orphan-process-daemon';

const ids = (...xs: string[]) => xs.map((x) => `ext/${x}`);

/** Static vector → runtime vectors that would confirm it. */
export const RUNTIME_FOR: Record<string, string[]> = Object.fromEntries([
  ...ids('process-exec', 'shell-exec', 'shell-interpreter', 'pipe-to-shell', 'chmod-exec', 'download-exec', 'privilege-escalation', 'service-control', 'process-kill', 'ui-automation', 'screen-capture', 'tcc-tamper', 'trust-store', 'shell-script-download', 'powershell-script', 'python-exec', 'julia-exec').map((v) => [v, [PROC, ORPHAN]]),
  ...ids('persistence-launchagent', 'persistence-cron', 'persistence-shell-rc', 'persistence-windows', 'other-extension-write', 'vscode-config-write', 'self-modifying', 'storage-payload').map((v) => [v, [FS, PROC, ORPHAN]]),
  ...ids('credential-path', 'ssh-keys', 'cloud-credentials', 'registry-tokens', 'git-credentials', 'kube-docker-config', 'browser-data', 'keychain-access', 'crypto-wallet', 'shell-history', 'env-file-harvest', 'sensitive-dotfiles', 'workspace-secret-harvest', 'workspace-harvest').map((v) => [v, [FS]]),
  ...ids('dynamic-code', 'decode-eval', 'encrypted-payload', 'packer', 'obfuscated', 'charcode-chain', 'wasm-blob', 'hex-or-unicode-escape-density', 'high-entropy-string', 'encoded-blob').map((v) => [v, [EVAL]]),
  ...ids(
    'network-outbound',
    'hardcoded-ip',
    'hardcoded-ip-or-raw-url',
    'exfil-endpoint',
    'tor-endpoint',
    'mining-pool',
    'ip-lookup',
    'cleartext-endpoint',
    'executable-download',
    'websocket-c2',
    'telemetry-unauthorized',
    'dns-exfil',
    'encoded-url',
    'document-exfil',
    'secret-storage-abuse',
    'python-network',
    'binary-network-strings',
  ).map((v) => [v, [NET]]),
  ...ids('input-capture', 'clipboard-exfil').map((v) => [v, [CLIP, NET]]),
  ...ids('raw-socket').map((v) => [v, [RAW]]),
  ...ids('native-binary', 'binary-dangerous-imports', 'packed-binary', 'binary-entropy', 'unsigned-binary').map((v) => [v, [RWX, RAW, PROC]]),
]);

const PROTECTED_COMMAND = /^(type|default:type|paste|cut|copy|workbench\.action\.terminal\.|git\.(commit|push|pushTo|sync)|editor\.action\.clipboard|workbench\.action\.files\.save|workbench\.action\.quickOpen)/;
const SECURITY_SETTING = /^(security\.|http\.proxy|terminal\.integrated\.env|extensions\.(autoUpdate|autoCheckUpdates))/;
const REMOTE_SCRIPT = /<(script|iframe)[^>]+src\s*=\s*\\?["']https?:/i;

/** Static vector → predicate over recorded editor API calls that confirms it. */
const API_FOR: Record<string, (e: RuntimeEvent) => boolean> = {
  'ext/terminal-injection': (e) => e.api === 'terminal.sendText' || (e.api === 'window.createTerminal' && /hideFromUser"?\s*:\s*true/.test(String(e.options))),
  'ext/terminal-sequence': (e) => e.api === 'commands.executeCommand' && e.id === 'workbench.action.terminal.sendSequence',
  'ext/command-override': (e) => e.api === 'commands.registerCommand' && PROTECTED_COMMAND.test(String(e.id)),
  'ext/debug-session-hook': (e) => e.api === 'debug.registerDebugAdapterTrackerFactory' || String(e.api).startsWith('listen:debug.'),
  'ext/settings-tamper': (e) => e.api === 'configuration.update' && SECURITY_SETTING.test(String(e.key)),
  'ext/security-setting-defaults': (e) => e.api === 'configuration.update' && SECURITY_SETTING.test(String(e.key)),
  'ext/webview-remote-content': (e) => e.api === 'webview.html' && !!e.enableScripts && REMOTE_SCRIPT.test(String(e.html)),
  'ext/webview-remote-script': (e) => e.api === 'webview.html' && REMOTE_SCRIPT.test(String(e.html)),
  'ext/webview-no-csp': (e) => e.api === 'webview.html' && !!e.enableScripts && !/Content-Security-Policy/i.test(String(e.html)),
  'ext/command-uris': (e) => e.api === 'window.createWebviewPanel' && !!e.enableCommandUris,
  'ext/extension-install': (e) => e.api === 'commands.executeCommand' && /installExtension/.test(String(e.id)),
  'ext/extension-uninstall': (e) => e.api === 'commands.executeCommand' && /uninstallExtension|disable/.test(String(e.id)),
  'ext/open-external-startup': (e) => e.api === 'env.openExternal',
  'ext/uri-handler': (e) => e.api === 'env.openExternal',
  'ext/broad-auth-session': (e) => e.api === 'authentication.getSession',
  'ext/secret-storage-abuse': (e) => e.api === 'secrets.get',
  'ext/clipboard-exfil': (e) => e.api === 'env.clipboard.readText',
  'ext/document-exfil': (e) => String(e.api).startsWith('listen:workspace.onDidChangeTextDocument'),
};

export type Verdict = 'confirmed' | 'not-observed' | 'no-runtime-check';

export interface Link {
  /** The static signal (vector id, message, where in the code). */
  vector: string;
  message: string;
  locations: { file: string; line: number }[];
  verdict: Verdict;
  /** Runtime vectors or recorded API calls that confirm it. */
  confirmedBy: { kind: 'runtime' | 'api'; id: string; detail: string }[];
}

export interface EvidenceChain {
  links: Link[];
  /** Runtime findings no static rule predicted (hidden in native code, downloaded at run time…). */
  runtimeOnly: Signal[];
  confirmed: number;
}

const apiDetail = (e: RuntimeEvent) =>
  [e.api, e.id, e.key, e.type, e.text, e.uri].filter((x) => x !== undefined && x !== '').map(String).join(' ').slice(0, 160);

/** Cross-references static signals with what the extension actually did. */
export function buildEvidence(staticSignals: readonly Signal[], runtime: Classified): EvidenceChain {
  const rt = new Map(runtime.signals.map((s) => [s.id, s]));
  const used = new Set<string>();
  const links: Link[] = staticSignals
    .filter((s) => s.weight > 0)
    .map((s) => {
      const confirmedBy: Link['confirmedBy'] = [];
      for (const r of RUNTIME_FOR[s.id] ?? []) {
        const hit = rt.get(r);
        if (hit) {
          used.add(r);
          confirmedBy.push({ kind: 'runtime', id: r, detail: hit.message });
        }
      }
      const pred = API_FOR[s.id];
      const apis = pred ? runtime.api.filter(pred) : [];
      for (const e of apis.slice(0, 3)) {
        confirmedBy.push({ kind: 'api', id: String(e.api), detail: apiDetail(e) });
      }
      const checkable = !!RUNTIME_FOR[s.id] || !!pred;
      return {
        vector: s.id,
        message: s.message,
        locations: s.locations.slice(0, 3).map((l) => ({ file: l.file, line: l.finding.range.start.line + 1 })),
        verdict: confirmedBy.length ? 'confirmed' : checkable ? 'not-observed' : 'no-runtime-check',
        confirmedBy,
      };
    });
  links.sort((a, b) => ['confirmed', 'not-observed', 'no-runtime-check'].indexOf(a.verdict) - ['confirmed', 'not-observed', 'no-runtime-check'].indexOf(b.verdict));
  return { links, runtimeOnly: runtime.signals.filter((s) => !used.has(s.id)), confirmed: links.filter((l) => l.verdict === 'confirmed').length };
}
