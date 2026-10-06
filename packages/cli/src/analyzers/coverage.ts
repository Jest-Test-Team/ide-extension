import { SIGNALS } from '../../../../extensions/endpoint-security/src/extscan/signals';
import { CATEGORY_TITLES, type VectorCategory } from '../../../../extensions/endpoint-security/src/extscan/vectorTypes';
import type { ScanCoverage } from '../endpoint';
import { ENGINE_BINARIES, ENGINE_NAMES, type EngineId } from './protocol';

export interface CategoryCoverage {
  category: VectorCategory;
  title: string;
  total: number;
  ran: number;
  /** Why the remaining vectors did not run, with counts. */
  skipped: Record<string, number>;
}

/** Explains why a vector did not run, given which engines are installed and whether --online is on. */
function skipReason(id: string, cov: ScanCoverage): string {
  const s = SIGNALS[id];
  if (s.online && !cov.online) {
    return 'needs --online';
  }
  const engines = (s.engines as string[]).filter((e) => e !== 'ts' && e !== 'rt') as EngineId[];
  const installed = new Set(cov.analyzers.map((a) => a.engine));
  const usable = engines.filter((e) => installed.has(e));
  if (!usable.length) {
    return engines.length ? `needs ${engines.map((e) => ENGINE_BINARIES[e]).join(' or ')}` : 'not implemented yet';
  }
  return `not implemented by installed ${usable.map((e) => ENGINE_BINARIES[e]).join(', ')} yet`;
}

/** Static vectors: everything except the runtime evidence that only `audit-extension` produces. */
export const STATIC_SIGNALS = Object.fromEntries(Object.entries(SIGNALS).filter(([, s]) => s.category !== 'runtime'));

export function categoryCoverage(cov: ScanCoverage): CategoryCoverage[] {
  const out = new Map<VectorCategory, CategoryCoverage>();
  for (const [id, s] of Object.entries(STATIC_SIGNALS)) {
    const c = out.get(s.category) ?? { category: s.category, title: CATEGORY_TITLES[s.category], total: 0, ran: 0, skipped: {} };
    c.total++;
    if (cov.ran.has(id)) {
      c.ran++;
    } else {
      const r = skipReason(id, cov);
      c.skipped[r] = (c.skipped[r] ?? 0) + 1;
    }
    out.set(s.category, c);
  }
  return Object.keys(CATEGORY_TITLES)
    .map((k) => out.get(k as VectorCategory))
    .filter((c): c is CategoryCoverage => !!c);
}

export function coverageSummary(cov: ScanCoverage): string {
  const total = Object.keys(STATIC_SIGNALS).length;
  const engines = ['TypeScript core', ...cov.analyzers.map((a) => `${ENGINE_NAMES[a.engine]} ${a.version}`)];
  return `Coverage: ${cov.ran.size}/${total} vectors ran (${engines.join(', ')})${cov.online ? ', online checks on' : ''}.`;
}

export function coverageText(cov: ScanCoverage, full: boolean): string {
  const lines = [coverageSummary(cov)];
  if (!full) {
    const missing = cov.missing.map((m) => ENGINE_BINARIES[m.engine]);
    lines.push(
      `  Run with --deep to use the Rust / Go / Python / Julia analyzers${missing.length ? ` (not installed: ${missing.join(', ')})` : ''}${cov.online ? '' : ' and --online for reputation / supply-chain lookups'}.`,
    );
  } else {
    const rows = categoryCoverage(cov);
    const w = Math.max(...rows.map((r) => r.title.length));
    for (const r of rows) {
      const why = Object.entries(r.skipped)
        .map(([k, n]) => `${n} ${k}`)
        .join('; ');
      const bar = '█'.repeat(Math.round((10 * r.ran) / r.total)).padEnd(10, '·');
      lines.push(`  ${r.title.padEnd(w)}  ${bar}  ${String(r.ran).padStart(3)}/${String(r.total).padEnd(3)} ${why ? ` skipped: ${why}` : ''}`);
    }
    for (const a of cov.analyzers) {
      lines.push(`  ✔ ${ENGINE_NAMES[a.engine]} ${a.version} (${a.path}): ${a.ran} vector(s)${a.errors.length ? `; ${a.errors.length} problem(s): ${a.errors.slice(0, 3).join(' | ')}` : ''}`);
    }
    for (const m of cov.missing) {
      lines.push(`  – ${ENGINE_NAMES[m.engine]}: ${m.reason}`);
    }
  }
  for (const w of cov.warnings) {
    lines.push(`  warning: ${w}`);
  }
  return lines.join('\n') + '\n';
}

/** --deep / --analyzers / --online / --analyzer-timeout, shared by every extension-scanning command. */
export const DEEP_FLAGS = {
  deep: { type: 'boolean' as const, description: 'Also run the installed Rust / Go / Python / Julia analyzers (deep inspection)' },
  analyzers: { type: 'string' as const, multiple: true, value: '<rs|go|py|jl>', description: 'Run only these analyzers (implies --deep)' },
  online: { type: 'boolean' as const, description: 'Allow network lookups: Marketplace reputation and online analyzer vectors (off by default)' },
  'analyzer-timeout': { type: 'number' as const, value: '<seconds>', description: 'Per-analyzer time limit', default: 600 },
};

const ALL_ENGINES: EngineId[] = ['rs', 'go', 'py', 'jl'];

export function deepOptions(flags: Record<string, unknown>): { analyzers: EngineId[]; online: boolean; analyzerTimeoutMs: number; deep: boolean } {
  const picked = (flags.analyzers as string[] | undefined) ?? [];
  const bad = picked.filter((a) => !ALL_ENGINES.includes(a as EngineId));
  if (bad.length) {
    throw new Error(`unknown analyzer ${bad.join(', ')} (expected rs, go, py or jl)`);
  }
  const deep = !!flags.deep || picked.length > 0;
  return {
    deep,
    analyzers: picked.length ? (picked as EngineId[]) : deep ? ALL_ENGINES : [],
    online: !!flags.online,
    analyzerTimeoutMs: ((flags['analyzer-timeout'] as number | undefined) ?? 600) * 1000,
  };
}

/** Coverage as plain data for JSON / SARIF output. */
export function coverageData(cov: ScanCoverage): object {
  return {
    vectorsTotal: Object.keys(SIGNALS).length,
    vectorsRan: cov.ran.size,
    online: cov.online,
    ran: Object.fromEntries([...cov.ran].sort()),
    categories: categoryCoverage(cov),
    analyzers: cov.analyzers,
    missingAnalyzers: cov.missing,
    warnings: cov.warnings,
  };
}
