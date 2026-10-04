/** Data model of the JSON written by `scripts/collect.jl`. Times are in seconds. */

export interface MiInfo {
  sig: string;
  method: string;
  module: string;
  file: string;
  line: number;
}

export interface InstanceNode extends MiInfo {
  /** Number of descendants (MethodInstances invalidated through this one). */
  total: number;
  children: InstanceNode[];
}

export interface InvalidationTree extends MiInfo {
  reason: string;
  ninvalidated: number;
  backedges: InstanceNode[];
  mt_backedges: { trigger: string; root: InstanceNode }[];
  mt_cache: number;
  mt_disable: number;
}

export interface FlameNode extends MiInfo {
  name: string;
  self: number;
  total: number;
  children: FlameNode[];
}

export interface InferenceTrigger {
  callee: MiInfo;
  caller: { func: string; file: string; line: number };
  /** First caller frame inside the profiled project, when the immediate caller is library code. */
  site?: { func: string; file: string; line: number } | null;
  time: number;
}

export interface Profile {
  version: 1;
  julia: string;
  project: string;
  package: string;
  workload: string;
  createdAt: string;
  invalidations: InvalidationTree[];
  inference: { total: number; inferenceTime: number; root: FlameNode } | null;
  triggers: InferenceTrigger[];
  warnings: string[];
}

export function parseProfile(text: string): Profile {
  const raw = JSON.parse(text) as Partial<Profile>;
  if (raw.version !== 1 || !Array.isArray(raw.invalidations)) {
    throw new Error('Not a profiler JSON file (expected version 1 with an "invalidations" list).');
  }
  return {
    version: 1,
    julia: raw.julia ?? '',
    project: raw.project ?? '',
    package: raw.package ?? '',
    workload: raw.workload ?? '',
    createdAt: raw.createdAt ?? '',
    invalidations: [...raw.invalidations].sort((a, b) => b.ninvalidated - a.ninvalidated),
    inference: raw.inference ?? null,
    triggers: raw.triggers ?? [],
    warnings: raw.warnings ?? [],
  };
}

/** Julia reports `none`/`REPL[1]`-style pseudo files for code without a source location. */
export function hasSource(loc: { file: string; line: number }): boolean {
  return !!loc.file && loc.line > 0 && !/^(none|REPL\[\d+\])$/.test(loc.file);
}

export interface ProfileSummary {
  trees: number;
  invalidated: number;
  topRoots: { label: string; count: number }[];
  inferenceTime?: number;
  totalTime?: number;
  triggers: number;
}

export function summarize(p: Profile, top = 5): ProfileSummary {
  return {
    trees: p.invalidations.length,
    invalidated: p.invalidations.reduce((n, t) => n + t.ninvalidated, 0),
    topRoots: p.invalidations.slice(0, top).map((t) => ({ label: `${t.module}.${t.method}`, count: t.ninvalidated })),
    inferenceTime: p.inference?.inferenceTime,
    totalTime: p.inference?.total,
    triggers: p.triggers.length,
  };
}

/** Aggregates self inference time per method across the flame tree (the "flatten" view). */
export function flattenInference(root: FlameNode): { key: string; method: string; module: string; file: string; line: number; self: number; count: number }[] {
  const acc = new Map<string, { key: string; method: string; module: string; file: string; line: number; self: number; count: number }>();
  const visit = (n: FlameNode, isRoot: boolean) => {
    if (!isRoot && n.name !== '(other)') {
      const key = `${n.module}.${n.method}@${n.file}:${n.line}`;
      const e = acc.get(key) ?? { key, method: n.method, module: n.module, file: n.file, line: n.line, self: 0, count: 0 };
      e.self += n.self;
      e.count += 1;
      acc.set(key, e);
    }
    n.children.forEach((c) => visit(c, false));
  };
  visit(root, true);
  return [...acc.values()].sort((a, b) => b.self - a.self);
}

/** Groups inference triggers by caller location, summing time; used for runtime diagnostics. */
export function triggersByCaller(p: Profile): Map<string, { file: string; line: number; callees: string[]; time: number }> {
  const out = new Map<string, { file: string; line: number; callees: string[]; time: number }>();
  for (const t of p.triggers) {
    const at = t.site ?? t.caller;
    if (!hasSource(at)) {
      continue;
    }
    const key = `${at.file}:${at.line}`;
    const e = out.get(key) ?? { file: at.file, line: at.line, callees: [], time: 0 };
    const callee = `${t.callee.method}(${t.callee.sig.replace(/^Tuple\{[^,}]*,?\s*/, '').replace(/\}$/, '')})`;
    if (!e.callees.includes(callee)) {
      e.callees.push(callee);
    }
    e.time += t.time;
    out.set(key, e);
  }
  return out;
}
