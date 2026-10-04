import type { CustomRule, Finding, Rule, RuleRef, Severity } from '@ide-ext/core';

export type RiskLevel = 'low' | 'medium' | 'high';

/** A finding located in a file of an installed extension (absolute path). */
export interface Located {
  file: string;
  finding: Finding;
}

/** One reason contributing to an extension's risk score. */
export interface Signal {
  /** Signal id from {@link SIGNALS} (code rules map `ext/foo.bar` → `ext/foo`). */
  id: string;
  weight: number;
  message: string;
  /** Forces at least this level regardless of the score (known-malware entries). */
  force?: RiskLevel;
  /** Where the signal was observed; empty for signals without a location. */
  locations: Located[];
  /** Total number of hits, which may exceed `locations.length` (locations are capped). */
  count: number;
}

export interface SignalInfo {
  title: string;
  weight: number;
  severity: Severity;
  description: string;
  refs?: RuleRef[];
}

const ATTACK = (id: string, name: string): RuleRef => ({ label: `MITRE ATT&CK ${id} — ${name}`, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` });
const EXT_SECURITY: RuleRef = { label: 'VS Code — Extension runtime security', url: 'https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security' };
const REMOVED: RuleRef = { label: 'microsoft/vsmarketplace — RemovedPackages.md', url: 'https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md' };
const ACTIVATION: RuleRef = { label: 'VS Code API — Activation events', url: 'https://code.visualstudio.com/api/references/activation-events' };
const TRUST: RuleRef = { label: 'VS Code API — Workspace Trust extension guide', url: 'https://code.visualstudio.com/api/extension-guides/workspace-trust' };

/**
 * Every signal the extension scanner can raise. Weights feed {@link scoreExtension}; weight 0 marks
 * informational signals that only amplify others through combination rules.
 */
export const SIGNALS: Record<string, SignalInfo> = {
  // ---- manifest
  'ext/activates-on-startup': {
    title: 'Activates on every startup (`*`)',
    weight: 2,
    severity: 'warning',
    description: 'The `*` activation event runs the extension as soon as VS Code starts, whether or not its features are used.',
    refs: [ACTIVATION],
  },
  'ext/activates-after-startup': {
    title: 'Activates after startup (`onStartupFinished`)',
    weight: 1,
    severity: 'info',
    description: 'The extension runs shortly after every startup, independent of the files or commands in use.',
    refs: [ACTIVATION],
  },
  'ext/untrusted-workspace': {
    title: 'Runs in untrusted workspaces',
    weight: 1,
    severity: 'info',
    description: 'The extension declares full support for Restricted Mode, so it is active in workspaces the user has not trusted.',
    refs: [TRUST],
  },
  'ext/many-dependencies': {
    title: 'Pulls in many other extensions',
    weight: 1,
    severity: 'info',
    description: 'More than three `extensionDependencies` are installed and activated together with this extension.',
  },
  'ext/unknown-publisher': {
    title: 'Publisher not in the built-in trusted list',
    weight: 0,
    severity: 'hint',
    description: 'Offline check only: the publisher is not one of the well-known publishers bundled with the scanner. This is not a negative verdict; it only amplifies other signals. Enable the Marketplace lookup for real publisher verification.',
  },
  'ext/typosquat': {
    title: 'Identifier resembles a popular extension',
    weight: 4,
    severity: 'warning',
    description: 'The identifier is a near-miss of a popular extension (edit distance or look-alike characters), a common impersonation technique.',
    refs: [ATTACK('T1036.005', 'Masquerading: Match Legitimate Name or Location'), REMOVED],
  },
  'ext/sideloaded': {
    title: 'Installed from a VSIX file',
    weight: 1,
    severity: 'info',
    description: 'The extension was installed from a local file rather than the Marketplace, so it bypassed Marketplace scanning.',
    refs: [EXT_SECURITY],
  },
  // ---- known-bad list
  'ext/known-bad': {
    title: 'Removed from the Marketplace',
    weight: 6,
    severity: 'error',
    description: "The identifier appears in Microsoft's list of extensions removed from the VS Marketplace.",
    refs: [REMOVED],
  },
  // ---- code
  'ext/process-exec': {
    title: 'Runs external programs',
    weight: 1,
    severity: 'info',
    description: 'The code loads `child_process`. Common for language servers, linters and formatters; suspicious together with other signals.',
    refs: [ATTACK('T1059', 'Command and Scripting Interpreter')],
  },
  'ext/dynamic-code': {
    title: 'Evaluates dynamically built code',
    weight: 2,
    severity: 'warning',
    description: '`eval`, `new Function`, `vm.run*` or `require()` with a computed module name can run code that is not visible in the package.',
    refs: [ATTACK('T1027', 'Obfuscated Files or Information'), { label: 'CWE-95: Eval Injection', url: 'https://cwe.mitre.org/data/definitions/95.html' }],
  },
  'ext/hardcoded-ip': {
    title: 'Hard-coded public IP address',
    weight: 2,
    severity: 'warning',
    description: 'Connections to a literal public IP address bypass DNS and are typical for command-and-control endpoints.',
    refs: [ATTACK('T1071', 'Application Layer Protocol')],
  },
  'ext/exfil-endpoint': {
    title: 'Known exfiltration / tunnelling endpoint',
    weight: 3,
    severity: 'warning',
    description: 'Webhook, paste, tunnelling or IP-lookup services that malware commonly uses to send data out or to locate the victim.',
    refs: [ATTACK('T1567', 'Exfiltration Over Web Service')],
  },
  'ext/credential-path': {
    title: 'References credential stores',
    weight: 3,
    severity: 'warning',
    description: 'Paths of SSH keys, cloud / package-registry credentials, browser password and cookie stores, VS Code state or crypto wallets.',
    refs: [ATTACK('T1552.001', 'Unsecured Credentials: Credentials In Files'), ATTACK('T1555.003', 'Credentials from Web Browsers')],
  },
  'ext/input-capture': {
    title: 'Reads the clipboard or keystrokes',
    weight: 2,
    severity: 'warning',
    description: 'Clipboard reads or global keyboard hooks can capture secrets the user copies or types.',
    refs: [ATTACK('T1115', 'Clipboard Data'), ATTACK('T1056.001', 'Input Capture: Keylogging')],
  },
  'ext/native-binary': {
    title: 'Ships native binaries',
    weight: 1,
    severity: 'info',
    description: 'Native modules and libraries cannot be inspected by the code scan.',
  },
  'ext/obfuscated': {
    title: 'Obfuscated code',
    weight: 3,
    severity: 'warning',
    description: 'javascript-obfuscator style identifiers or a high-entropy payload next to code evaluation. Plain minification does not trigger this.',
    refs: [ATTACK('T1027', 'Obfuscated Files or Information')],
  },
  'ext/scan-incomplete': {
    title: 'Some files were not scanned',
    weight: 0,
    severity: 'hint',
    description: 'Files above the size limit, beyond the per-extension file budget, or unreadable were skipped.',
  },
  // ---- Marketplace (opt-in)
  'ext/not-on-marketplace': {
    title: 'Not found on the Marketplace',
    weight: 3,
    severity: 'warning',
    description: 'The Marketplace has no extension with this identifier: it was sideloaded, renamed or taken down.',
    refs: [EXT_SECURITY],
  },
  'ext/unverified-publisher': {
    title: 'Publisher not verified',
    weight: 1,
    severity: 'info',
    description: 'The Marketplace publisher has not verified a domain.',
    refs: [EXT_SECURITY],
  },
  'ext/low-installs': {
    title: 'Few installs',
    weight: 1,
    severity: 'info',
    description: 'Fewer than 1,000 Marketplace installs.',
  },
  'ext/stale': {
    title: 'Not updated for over two years',
    weight: 0,
    severity: 'hint',
    description: 'The latest Marketplace version is more than two years old.',
  },
  'ext/verified-publisher': {
    title: 'Verified publisher',
    weight: -1,
    severity: 'hint',
    description: 'The Marketplace publisher has a verified domain.',
    refs: [EXT_SECURITY],
  },
};

/** Code rules are named `ext/<signal>.<variant>`; the signal is the part before the dot. */
export function signalIdOf(ruleId: string): string {
  const dot = ruleId.indexOf('.', ruleId.indexOf('/'));
  return dot < 0 ? ruleId : ruleId.slice(0, dot);
}

/** Signal registry entries as rules, so SARIF / Markdown exports carry titles and references. */
export function signalRules(): Rule[] {
  return Object.entries(SIGNALS).map(
    ([id, s]): CustomRule => ({
      kind: 'custom',
      id,
      title: s.title,
      severity: s.severity,
      message: s.title,
      description: s.description,
      languages: [],
      refs: s.refs ?? [],
      tags: ['extension-scan'],
      check: () => [],
    }),
  );
}

/** Builds a signal with the registry weight; `overrides` adjust weight / message / force. */
export function signal(id: string, message: string, locations: Located[] = [], overrides: Partial<Signal> = {}): Signal {
  const info = SIGNALS[id];
  if (!info) {
    throw new Error(`unknown signal ${id}`);
  }
  return { id, weight: info.weight, message, locations, count: Math.max(1, locations.length), ...overrides };
}
