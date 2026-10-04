import type { RiskLevel, Signal } from './signals';

export const HIGH_THRESHOLD = 8;
export const MEDIUM_THRESHOLD = 4;

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
}

/**
 * Signals that only mean something together. Each signal is counted once, so a language server
 * that spawns processes stays low, while credential access plus an exfiltration channel is high.
 */
const COMBINATIONS: { label: string; weight: number; all: string[][] }[] = [
  { label: 'Credential access plus a network endpoint (possible exfiltration)', weight: 4, all: [['ext/credential-path'], ['ext/hardcoded-ip', 'ext/exfil-endpoint']] },
  { label: 'Obfuscated code that evaluates code at run time', weight: 2, all: [['ext/obfuscated'], ['ext/dynamic-code']] },
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
  const total = Math.max(0, signals.reduce((n, s) => n + s.weight, 0) + boosts.reduce((n, b) => n + b.weight, 0));
  const forced = signals.reduce<RiskLevel | undefined>((lvl, s) => maxLevel(lvl, s.force), undefined);
  const allowlisted = !!opts.allowlisted;
  if (allowlisted && !forced) {
    return { score: 0, level: 'low', signals, boosts, allowlisted, allowlistOverridden: false };
  }
  return {
    score: total,
    level: maxLevel(levelFor(total), forced)!,
    signals,
    boosts,
    allowlisted,
    allowlistOverridden: allowlisted && !!forced,
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
