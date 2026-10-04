/**
 * Process-tree scenario simulator. A scenario is a synthetic, ordered stream of process events
 * (spawn, exec, terminate, inject, file, registry, network, module); detection rules are matched
 * against it. Nothing is executed — this is pure data replay, safe on any workstation.
 */
import { LineCounter, parseDocument, isSeq, type Node as YamlNode } from 'yaml';

export const EVENT_TYPES = ['spawn', 'exec', 'terminate', 'inject', 'file', 'registry', 'network', 'module'] as const;
export type EventType = (typeof EVENT_TYPES)[number];
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ProcessInfo {
  id: string;
  image: string;
  cmdline?: string;
  user?: string;
  integrity?: string;
  parent?: string;
  /** Time the process started / terminated (ms since scenario start). */
  start?: number;
  end?: number;
}

export interface SimEvent {
  t: number;
  type: EventType;
  /** Acting process (for spawn: the new child). */
  process: string;
  parent?: string;
  target?: string;
  image?: string;
  cmdline?: string;
  user?: string;
  op?: string;
  path?: string;
  key?: string;
  value?: string;
  remote?: string;
  count?: number;
  /** 1-based line of the event in the scenario file. */
  line?: number;
}

/** Field → value condition: string = regex (prefix `(?i)` for case-insensitive), number, boolean or a list of alternatives. Strings `$X` reference sequence bindings. */
export type Conditions = Record<string, string | number | boolean | (string | number)[]>;

export interface DetectionRule {
  id: string;
  title: string;
  severity: Severity;
  description?: string;
  mitre?: string[];
  match?: Conditions;
  threshold?: { match: Conditions; count: number; within?: number; by?: 'process' | 'parent' | 'none' };
  sequence?: { steps: { match: Conditions; bind?: Record<string, string> }[]; within?: number };
  line?: number;
}

export interface Scenario {
  name: string;
  description?: string;
  processes: ProcessInfo[];
  events: SimEvent[];
  rules: DetectionRule[];
}

export interface Detection {
  ruleId: string;
  title: string;
  severity: Severity;
  mitre: string[];
  t: number;
  events: number[];
  processes: string[];
}

export interface SimulationResult {
  scenario: string;
  processes: (ProcessInfo & { children: string[]; detections: string[]; terminatedBy?: string; injectedBy?: string[] })[];
  timeline: (SimEvent & { index: number; summary: string; detections: string[] })[];
  detections: Detection[];
  warnings: string[];
}

export class ScenarioError extends Error {
  constructor(
    message: string,
    readonly line?: number,
  ) {
    super(line ? `line ${line}: ${message}` : message);
  }
}

// --- parsing --------------------------------------------------------------------------------------

function lineOf(node: YamlNode | null | undefined, lc: LineCounter): number | undefined {
  const r = (node as { range?: [number, number, number] } | null)?.range;
  return r ? lc.linePos(r[0]).line : undefined;
}

/** Parses a scenario (and optional extra rule files) from YAML text. */
export function parseScenario(text: string, extraRules: DetectionRule[] = []): Scenario {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, prettyErrors: false });
  if (doc.errors.length) {
    const e = doc.errors[0];
    throw new ScenarioError(e.message.split('\n')[0], e.linePos?.[0].line);
  }
  const root = doc.toJS() as Record<string, unknown> | null;
  if (!root || typeof root !== 'object') {
    throw new ScenarioError('Scenario must be a YAML mapping with `events`.');
  }
  const events = Array.isArray(root.events) ? (root.events as Record<string, unknown>[]) : [];
  const eventNodes = (() => {
    const n = doc.get('events', true);
    return isSeq(n) ? n.items : [];
  })();
  const parsedEvents = events.map((e, i): SimEvent => {
    const line = lineOf(eventNodes[i] as YamlNode, lc);
    if (!e || typeof e !== 'object') {
      throw new ScenarioError('event must be a mapping', line);
    }
    if (!EVENT_TYPES.includes(e.type as EventType)) {
      throw new ScenarioError(`unknown event type "${String(e.type)}" (expected ${EVENT_TYPES.join(', ')})`, line);
    }
    if (typeof e.process !== 'string') {
      throw new ScenarioError('event needs a `process` id', line);
    }
    return { ...(e as object), t: typeof e.t === 'number' ? e.t : NaN, line } as SimEvent;
  });
  // Events without `t` follow the previous one by 1 ms.
  let last = 0;
  for (const e of parsedEvents) {
    e.t = Number.isFinite(e.t) ? e.t : last + 1;
    last = e.t;
  }
  const ruleNodes = (() => {
    const n = doc.get('rules', true);
    return isSeq(n) ? n.items : [];
  })();
  const rules = (Array.isArray(root.rules) ? (root.rules as DetectionRule[]) : []).map((r, i) => validateRule(r, lineOf(ruleNodes[i] as YamlNode, lc)));
  const processes = Array.isArray(root.processes) ? (root.processes as ProcessInfo[]) : [];
  return {
    name: String(root.scenario ?? root.name ?? 'scenario'),
    description: root.description ? String(root.description) : undefined,
    processes,
    events: parsedEvents,
    rules: [...rules, ...extraRules],
  };
}

/** Parses a rules-only YAML file (`rules:` list). */
export function parseRules(text: string): DetectionRule[] {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc });
  if (doc.errors.length) {
    throw new ScenarioError(doc.errors[0].message.split('\n')[0], doc.errors[0].linePos?.[0].line);
  }
  const n = doc.get('rules', true);
  const items = isSeq(n) ? n.items : [];
  const js = (doc.toJS() as { rules?: DetectionRule[] })?.rules ?? [];
  return js.map((r, i) => validateRule(r, lineOf(items[i] as YamlNode, lc)));
}

function validateRule(r: DetectionRule, line?: number): DetectionRule {
  if (!r || typeof r !== 'object' || typeof r.id !== 'string') {
    throw new ScenarioError('rule needs an `id`', line);
  }
  const kinds = [r.match, r.threshold, r.sequence].filter(Boolean).length;
  if (kinds !== 1) {
    throw new ScenarioError(`rule ${r.id}: exactly one of match / threshold / sequence is required`, line);
  }
  if (r.sequence && (!Array.isArray(r.sequence.steps) || r.sequence.steps.length < 2)) {
    throw new ScenarioError(`rule ${r.id}: a sequence needs at least two steps`, line);
  }
  const sev = r.severity ?? 'medium';
  if (!['low', 'medium', 'high', 'critical'].includes(sev)) {
    throw new ScenarioError(`rule ${r.id}: severity must be low, medium, high or critical`, line);
  }
  // Compile every regex now so errors point at the rule.
  const conds = [r.match, r.threshold?.match, ...(r.sequence?.steps.map((s) => s.match) ?? [])].filter(Boolean) as Conditions[];
  for (const c of conds) {
    for (const [k, v] of Object.entries(c)) {
      for (const alt of Array.isArray(v) ? v : [v]) {
        if (typeof alt === 'string' && !alt.startsWith('$')) {
          try {
            toRegex(alt);
          } catch (err) {
            throw new ScenarioError(`rule ${r.id}: invalid pattern for ${k}: ${(err as Error).message}`, line);
          }
        }
      }
    }
  }
  return { ...r, title: r.title ?? r.id, severity: sev, mitre: r.mitre ?? [], line };
}

const regexCache = new Map<string, RegExp>();
function toRegex(p: string): RegExp {
  let re = regexCache.get(p);
  if (!re) {
    re = p.startsWith('(?i)') ? new RegExp(p.slice(4), 'i') : new RegExp(p);
    regexCache.set(p, re);
  }
  return re;
}

// --- evaluation -----------------------------------------------------------------------------------

interface EvalContext {
  event: SimEvent;
  proc: (id?: string) => ProcessInfo | undefined;
  ancestors: (id?: string) => ProcessInfo[];
}

function fieldValues(field: string, ctx: EvalContext): (string | number | undefined)[] {
  const e = ctx.event;
  const p = ctx.proc(e.process);
  const parentId = e.type === 'spawn' ? (e.parent ?? p?.parent) : p?.parent;
  const [scope, prop] = field.includes('.') ? (field.split('.', 2) as [string, string]) : ['', field];
  const pick = (proc: ProcessInfo | undefined) => (proc ? (proc as unknown as Record<string, string | number | undefined>)[prop] : undefined);
  switch (scope) {
    case '':
      if (['image', 'cmdline', 'user', 'integrity'].includes(prop)) {
        return [(e as unknown as Record<string, string | undefined>)[prop] ?? pick(p)];
      }
      if (prop === 'count') {
        return [e.count ?? 1];
      }
      return [(e as unknown as Record<string, string | number | undefined>)[prop]];
    case 'process':
      return [prop === 'id' ? e.process : pick(p)];
    case 'parent':
      return [prop === 'id' ? parentId : pick(ctx.proc(parentId))];
    case 'target': {
      // A terminate event without a target is the process exiting itself.
      const target = e.target ?? (e.type === 'terminate' ? e.process : undefined);
      return [prop === 'id' ? target : pick(ctx.proc(target))];
    }
    case 'ancestor':
      return ctx.ancestors(e.process).map((a) => (prop === 'id' ? a.id : pick(a)));
    default:
      return [undefined];
  }
}

function matches(conds: Conditions, ctx: EvalContext, vars: Record<string, string> = {}): boolean {
  return Object.entries(conds).every(([field, expected]) => {
    const values = fieldValues(field, ctx);
    const alts = Array.isArray(expected) ? expected : [expected];
    return values.some((v) =>
      alts.some((alt) => {
        if (v === undefined) {
          return false;
        }
        if (typeof alt === 'number' || typeof alt === 'boolean') {
          return field === 'count' ? Number(v) >= Number(alt) : String(v) === String(alt);
        }
        if (alt.startsWith('$')) {
          return vars[alt.slice(1)] !== undefined && String(v) === vars[alt.slice(1)];
        }
        return toRegex(alt).test(String(v));
      }),
    );
  });
}

function describe(e: SimEvent, proc: (id?: string) => ProcessInfo | undefined): string {
  const name = (id?: string) => {
    const p = proc(id);
    return p ? `${p.image.split(/[\\/]/).pop()} (${p.id})` : (id ?? '?');
  };
  switch (e.type) {
    case 'spawn':
      return `${name(e.parent)} → spawns ${name(e.process)}${e.cmdline ? `: ${e.cmdline}` : ''}`;
    case 'exec':
      return `${name(e.process)} execs ${e.image ?? ''}${e.cmdline ? `: ${e.cmdline}` : ''}`;
    case 'terminate':
      return e.target && e.target !== e.process ? `${name(e.process)} terminates ${name(e.target)}` : `${name(e.process)} exits`;
    case 'inject':
      return `${name(e.process)} injects into ${name(e.target)}`;
    case 'file':
      return `${name(e.process)} ${e.op ?? 'touches'} ${e.path ?? ''}${(e.count ?? 1) > 1 ? ` ×${e.count}` : ''}`;
    case 'registry':
      return `${name(e.process)} ${e.op ?? 'sets'} ${e.key ?? ''}${e.value ? ` = ${e.value}` : ''}`;
    case 'network':
      return `${name(e.process)} connects to ${e.remote ?? '?'}`;
    case 'module':
      return `${name(e.process)} loads ${e.path ?? ''}`;
  }
}

export function simulate(s: Scenario): SimulationResult {
  const warnings: string[] = [];
  const procs = new Map<string, ProcessInfo>();
  for (const p of s.processes) {
    procs.set(p.id, { ...p, start: p.start ?? 0 });
  }
  const proc = (id?: string) => (id ? procs.get(id) : undefined);
  const ancestors = (id?: string) => {
    const out: ProcessInfo[] = [];
    const seen = new Set<string>();
    let cur = proc(proc(id)?.parent);
    while (cur && !seen.has(cur.id)) {
      seen.add(cur.id);
      out.push(cur);
      cur = proc(cur.parent);
    }
    return out;
  };
  const events = [...s.events].map((e, index) => ({ ...e, index })).sort((a, b) => a.t - b.t || a.index - b.index);
  const timeline: SimulationResult['timeline'] = [];
  const detections: Detection[] = [];
  const thresholdState = new Map<string, { t: number; index: number; process: string; count: number }[]>();
  const seqState = new Map<string, { step: number; t0: number; events: number[]; procs: string[]; vars: Record<string, string> }[]>();
  const fired = new Set<string>();
  const terminatedBy = new Map<string, string>();
  const injectedBy = new Map<string, string[]>();

  const fire = (r: DetectionRule, t: number, evs: number[], ps: string[], key: string) => {
    if (fired.has(key)) {
      return;
    }
    fired.add(key);
    detections.push({ ruleId: r.id, title: r.title, severity: r.severity, mitre: r.mitre ?? [], t, events: evs, processes: [...new Set(ps)] });
    for (const i of evs) {
      timeline.find((x) => x.index === i)?.detections.push(r.id);
    }
  };

  for (const e of events) {
    // Update the process table first so rules see the new process.
    if (e.type === 'spawn') {
      if (procs.has(e.process) && procs.get(e.process)!.start !== undefined && s.processes.every((p) => p.id !== e.process)) {
        warnings.push(`line ${e.line}: process ${e.process} spawned twice`);
      }
      if (e.parent && !procs.has(e.parent)) {
        warnings.push(`line ${e.line}: parent ${e.parent} is not defined; add it to \`processes\``);
      }
      procs.set(e.process, { ...(procs.get(e.process) ?? {}), id: e.process, image: e.image ?? procs.get(e.process)?.image ?? '?', cmdline: e.cmdline, user: e.user ?? proc(e.parent)?.user, parent: e.parent, start: e.t });
    } else if (!procs.has(e.process)) {
      warnings.push(`line ${e.line}: process ${e.process} is used before it exists`);
      procs.set(e.process, { id: e.process, image: '?', start: e.t });
    }
    if (e.type === 'exec' && e.image) {
      Object.assign(procs.get(e.process)!, { image: e.image, cmdline: e.cmdline ?? procs.get(e.process)!.cmdline });
    }
    if (e.type === 'terminate') {
      const victim = e.target ?? e.process;
      const p = proc(victim);
      if (p) {
        p.end = e.t;
        if (e.target && e.target !== e.process) {
          terminatedBy.set(victim, e.process);
        }
      }
    }
    if (e.type === 'inject' && e.target) {
      injectedBy.set(e.target, [...(injectedBy.get(e.target) ?? []), e.process]);
    }
    timeline.push({ ...e, summary: describe(e, proc), detections: [] });

    const ctx: EvalContext = { event: e, proc, ancestors };
    for (const r of s.rules) {
      if (r.match && matches(r.match, ctx)) {
        fire(r, e.t, [e.index], [e.process, ...(e.target ? [e.target] : [])], `${r.id}:${e.index}`);
      } else if (r.threshold && matches(r.threshold.match, ctx)) {
        const by = r.threshold.by ?? 'process';
        const group = by === 'none' ? '*' : by === 'parent' ? (proc(e.process)?.parent ?? '?') : e.process;
        const key = `${r.id}:${group}`;
        const window = (thresholdState.get(key) ?? []).filter((x) => r.threshold!.within === undefined || e.t - x.t <= r.threshold!.within);
        window.push({ t: e.t, index: e.index, process: e.process, count: e.count ?? 1 });
        thresholdState.set(key, window);
        if (window.reduce((n, x) => n + x.count, 0) >= r.threshold.count) {
          fire(r, e.t, window.map((x) => x.index), window.map((x) => x.process), key);
        }
      } else if (r.sequence) {
        const seq = r.sequence;
        const partials = (seqState.get(r.id) ?? []).filter((p) => seq.within === undefined || e.t - p.t0 <= seq.within);
        const next: typeof partials = [];
        for (const p of partials) {
          const step = seq.steps[p.step];
          if (matches(step.match, ctx, p.vars)) {
            const vars = { ...p.vars, ...bind(step.bind, ctx) };
            if (p.step + 1 === seq.steps.length) {
              fire(r, e.t, [...p.events, e.index], [...p.procs, e.process], `${r.id}:${p.events[0]}`);
              continue;
            }
            next.push({ step: p.step + 1, t0: p.t0, events: [...p.events, e.index], procs: [...p.procs, e.process], vars });
          }
          next.push(p); // keep waiting: a later event may also match this step
        }
        if (matches(seq.steps[0].match, ctx)) {
          next.push({ step: 1, t0: e.t, events: [e.index], procs: [e.process], vars: bind(seq.steps[0].bind, ctx) });
        }
        seqState.set(r.id, next.slice(-200));
      }
    }
  }

  const children = new Map<string, string[]>();
  for (const p of procs.values()) {
    if (p.parent) {
      children.set(p.parent, [...(children.get(p.parent) ?? []), p.id]);
    }
  }
  return {
    scenario: s.name,
    processes: [...procs.values()].map((p) => ({
      ...p,
      children: children.get(p.id) ?? [],
      detections: [...new Set(detections.filter((d) => d.processes.includes(p.id)).map((d) => d.ruleId))],
      terminatedBy: terminatedBy.get(p.id),
      injectedBy: injectedBy.get(p.id),
    })),
    timeline: timeline.sort((a, b) => a.t - b.t || a.index - b.index),
    detections,
    warnings,
  };
}

function bind(spec: Record<string, string> | undefined, ctx: EvalContext): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, field] of Object.entries(spec ?? {})) {
    const v = fieldValues(field, ctx)[0];
    if (v !== undefined) {
      out[name] = String(v);
    }
  }
  return out;
}

