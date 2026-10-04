import type { Finding, RuleRef } from '@ide-ext/core';
import { existsSync, realpathSync } from 'node:fs';
import { hasSource, triggersByCaller, type Profile } from './profile';

export const RUNTIME_INVALIDATION_ID = 'julia/runtime-invalidation';
export const RUNTIME_TRIGGER_ID = 'julia/runtime-inference-trigger';

const REFS: RuleRef[] = [
  { label: 'SnoopCompile.jl — Tutorial on @snoop_invalidations', url: 'https://timholy.github.io/SnoopCompile.jl/stable/tutorials/invalidations/' },
  { label: 'SnoopCompile.jl — Tutorial on @snoop_inference', url: 'https://timholy.github.io/SnoopCompile.jl/stable/tutorials/snoop_inference/' },
];

export function normalizePath(p: string): string {
  let out = p;
  try {
    if (existsSync(p)) {
      out = realpathSync.native(p);
    }
  } catch {
    // keep the original path
  }
  out = out.replace(/\\/g, '/');
  return process.platform === 'win32' || process.platform === 'darwin' ? out.toLowerCase() : out;
}

const lineRange = (line: number) => ({ start: { line: line - 1, character: 0 }, end: { line: line - 1, character: 10_000 } });

/**
 * Findings backed by recorded SnoopCompile data for one file: methods defined in it that caused
 * invalidations, and call sites in it whose runtime dispatch triggered fresh inference.
 */
export function runtimeFindings(profile: Profile | undefined, fsPath: string, threshold: number): Finding[] {
  if (!profile) {
    return [];
  }
  const target = normalizePath(fsPath);
  const out: Finding[] = [];
  for (const t of profile.invalidations) {
    if (!hasSource(t) || normalizePath(t.file) !== target) {
      continue;
    }
    out.push({
      ruleId: RUNTIME_INVALIDATION_ID,
      severity: t.ninvalidated >= threshold ? 'warning' : 'info',
      message:
        `Defining \`${t.module}.${t.method}\` here invalidated ${t.ninvalidated} compiled MethodInstance(s) (${t.reason}). ` +
        'Narrow the argument types, avoid extending Base on types you do not own, or fix type instabilities in the invalidated callers.',
      range: lineRange(t.line),
      refs: REFS,
      data: { sig: t.sig },
    });
  }
  for (const site of triggersByCaller(profile).values()) {
    if (normalizePath(site.file) !== target) {
      continue;
    }
    const callees = site.callees.slice(0, 3).join(', ') + (site.callees.length > 3 ? ', …' : '');
    out.push({
      ruleId: RUNTIME_TRIGGER_ID,
      severity: 'info',
      message: `Runtime dispatch here triggered fresh inference of ${callees} (${(site.time * 1000).toFixed(1)} ms). Annotate types or add a function barrier.`,
      range: lineRange(site.line),
      refs: REFS,
    });
  }
  return out;
}
