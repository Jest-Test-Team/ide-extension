import { SIGNALS, type RiskLevel, type Signal } from './signals';

export const HIGH_THRESHOLD = 9;
export const MEDIUM_THRESHOLD = 5;

export interface Boost {
  label: string;
  weight: number;
  /** Signal ids that triggered the boost. */
  because: string[];
}

export interface RiskScore {
  score: number;
  level: RiskLevel;
  /** One entry per signal id, heaviest first. */
  signals: Signal[];
  boosts: Boost[];
  allowlisted: boolean;
  /** Allowlisted, but a known-bad entry still forced the level. */
  allowlistOverridden: boolean;
  /** The score reached high, but no combination or known-bad entry backs it, so it shows as medium. */
  capped: boolean;
  /** Score per vector category (before combinations), highest first. */
  categories: { category: string; score: number }[];
}

/**
 * Signals that only mean something together. Each signal is counted once, so a language server
 * that spawns processes stays low, while credential access plus an exfiltration channel is high.
 */
const CREDENTIALS = [
  'ext/credential-path',
  'ext/ssh-keys',
  'ext/cloud-credentials',
  'ext/registry-tokens',
  'ext/git-credentials',
  'ext/kube-docker-config',
  'ext/browser-data',
  'ext/keychain-access',
  'ext/crypto-wallet',
  'ext/shell-history',
  'ext/env-file-harvest',
  'ext/env-dump',
];
const EXFIL = ['ext/hardcoded-ip', 'ext/exfil-endpoint', 'ext/tor-endpoint', 'ext/websocket-c2'];
const PERSISTENCE = ['ext/persistence-launchagent', 'ext/persistence-cron', 'ext/persistence-shell-rc', 'ext/persistence-windows'];

const COMBINATIONS: { label: string; weight: number; all: string[][] }[] = [
  { label: 'Credential access plus a network endpoint (possible exfiltration)', weight: 4, all: [CREDENTIALS, EXFIL] },
  { label: 'Obfuscated code that evaluates code at run time', weight: 2, all: [['ext/obfuscated', 'ext/packer', 'ext/charcode-chain'], ['ext/dynamic-code', 'ext/decode-eval']] },
  { label: 'Downloads code and makes it persistent', weight: 3, all: [['ext/pipe-to-shell', 'ext/executable-download'], PERSISTENCE] },
  { label: 'Input or screen capture plus a network endpoint (possible spyware)', weight: 3, all: [['ext/input-capture', 'ext/screen-capture'], EXFIL] },
  { label: 'Evades analysis and hides what it runs', weight: 2, all: [['ext/anti-debug', 'ext/sandbox-evasion'], ['ext/obfuscated', 'ext/packer', 'ext/decode-eval', 'ext/terminal-injection']] },
  {
    label: 'Unknown publisher running programs or capturing input from startup',
    weight: 2,
    all: [['ext/activates-on-startup', 'ext/activates-after-startup'], ['ext/process-exec', 'ext/input-capture'], ['ext/unknown-publisher']],
  },
];

/** Merges signals with the same id: locations and counts add up, the heaviest weight wins. */
export function mergeSignals(signals: readonly Signal[]): Signal[] {
  const byId = new Map<string, Signal>();
  for (const s of signals) {
    const prev = byId.get(s.id);
    if (!prev) {
      byId.set(s.id, { ...s, locations: [...s.locations] });
      continue;
    }
    prev.locations.push(...s.locations);
    prev.count += s.count;
    if (s.weight > prev.weight) {
      prev.weight = s.weight;
      prev.message = s.message;
    }
    prev.force = maxLevel(prev.force, s.force);
  }
  return [...byId.values()].sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id));
}

const RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

function maxLevel(a?: RiskLevel, b?: RiskLevel): RiskLevel | undefined {
  if (!a || !b) {
    return a ?? b;
  }
  return RANK[a] >= RANK[b] ? a : b;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

/** Categories whose vectors describe overlapping abilities of the code. */
const CAPABILITY_CATEGORIES = new Set(['process', 'data', 'network', 'obfuscation', 'webview', 'vscode-api', 'scripts', 'native']);

/**
 * In capability categories, positive weights sorted high to low count 1, 1/2, 1/4, …: a
 * remote-development tool that spawns, chmods and kills processes is not ten times riskier than one
 * that only spawns. Other categories (manifest, reputation, supply chain…) hold independent
 * evidence and add up. Negative weights (trust) always count fully.
 */
export function categoryScores(signals: readonly Signal[]): { category: string; score: number }[] {
  const by = new Map<string, number[]>();
  for (const s of signals) {
    const cat = SIGNALS[s.id]?.category ?? 'other';
    by.set(cat, [...(by.get(cat) ?? []), s.weight]);
  }
  return [...by]
    .map(([category, ws]) => {
      const pos = ws.filter((w) => w > 0).sort((a, b) => b - a);
      const neg = ws.filter((w) => w < 0).reduce((n, w) => n + w, 0);
      const damp = CAPABILITY_CATEGORIES.has(category);
      return { category, score: round1(pos.reduce((n, w, i) => n + (damp ? w / 2 ** i : w), 0) + neg) };
    })
    .sort((a, b) => b.score - a.score || a.category.localeCompare(b.category));
}

export function levelFor(score: number): RiskLevel {
  return score >= HIGH_THRESHOLD ? 'high' : score >= MEDIUM_THRESHOLD ? 'medium' : 'low';
}

export function scoreExtension(raw: readonly Signal[], opts: { allowlisted?: boolean } = {}): RiskScore {
  const signals = mergeSignals(raw);
  const ids = new Set(signals.map((s) => s.id));
  const boosts: Boost[] = [];
  for (const c of COMBINATIONS) {
    const because = c.all.map((anyOf) => anyOf.find((id) => ids.has(id)));
    if (because.every(Boolean)) {
      boosts.push({ label: c.label, weight: c.weight, because: because as string[] });
    }
  }
  const categories = categoryScores(signals);
  const total = Math.max(0, round1(categories.reduce((n, c) => n + c.score, 0) + boosts.reduce((n, b) => n + b.weight, 0)));
  const forced = signals.reduce<RiskLevel | undefined>((lvl, s) => maxLevel(lvl, s.force), undefined);
  const allowlisted = !!opts.allowlisted;
  if (allowlisted && !forced) {
    return { score: 0, level: 'low', signals, boosts, allowlisted, allowlistOverridden: false, capped: false, categories };
  }
  // Capabilities alone (process, keychain, clipboard) describe many legitimate tools; reaching high
  // takes signals that only mean something together, or a known-bad entry.
  const capped = levelFor(total) === 'high' && !boosts.length && !forced && !signals.some((s) => s.id === 'ext/known-bad' && s.weight > 0);
  return {
    score: total,
    level: capped ? 'medium' : maxLevel(levelFor(total), forced)!,
    signals,
    boosts,
    allowlisted,
    allowlistOverridden: allowlisted && !!forced,
    capped,
    categories,
  };
}

/**
 * Allowlist entries are `publisher.name` (any version) or `publisher.name@version` (that version
 * only, so an update is scored again). Comparison ignores case.
 */
export function isAllowlisted(id: string, version: string, entries: readonly string[]): boolean {
  const lower = id.toLowerCase();
  return entries.some((e) => {
    const [eid, ever] = e.trim().toLowerCase().split('@');
    return eid === lower && (ever === undefined || ever === version.toLowerCase());
  });
}
