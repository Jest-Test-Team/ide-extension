import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { toExtensionMarkdown, toExtensionSarif } from '../../../../extensions/endpoint-security/src/extscan/report';
import { scoreExtension } from '../../../../extensions/endpoint-security/src/extscan/score';
import { signalIdOf, SIGNALS, type Signal } from '../../../../extensions/endpoint-security/src/extscan/signals';
import { deepOptions, DEEP_FLAGS } from '../analyzers/coverage';
import { extractVsix } from '../ci/fetch';
import type { ExtResult } from '../../../../extensions/endpoint-security/src/extscan/scanner';
import { scanExtensions } from '../endpoint';
import { UsageError, VERSION, type Command, type Io } from '../lib/args';
import { emit } from '../lib/output';
import { classify, type Classified } from './classify';
import { findOrphans, kernelTracingUnavailable } from './dast';
import { buildEvidence, type EvidenceChain } from './evidence';
import { kernelBaseline, runHarness, type RunOptions, type RunResult } from './run';
import { findVsCode, runVsCode } from './vscode';

export interface AuditReport {
  extension: { id: string; version: string; path: string };
  mode: 'harness' | 'vscode';
  options: RunOptions;
  static: ExtResult;
  runtime: Classified;
  run: { events: number; exitCode: number | null; timedOut: boolean; kernelSkipped?: string; orphans: number; baselineRwx?: number };
  chain: EvidenceChain;
  combined: ReturnType<typeof scoreExtension>;
}

const WARNING = [
  'audit-extension RUNS THE EXTENSION’S CODE on this machine to observe it. Isolation used by default:',
  '  • headless harness with a recording vscode API, a decoy HOME (fake SSH / cloud / git tokens) and a decoy workspace;',
  '  • child processes are recorded and replaced by a no-op (--allow-exec runs them);',
  '  • --offline blocks DNS and connections (recommended for unknown extensions).',
  'It is still code from the extension running as you. Prefer a VM or container for anything you suspect.',
  'Re-run with --yes to confirm.',
].join('\n');

async function materialise(input: string): Promise<string> {
  if (!existsSync(input)) {
    throw new UsageError(`no such file or folder: ${input}`);
  }
  if (statSync(input).isDirectory()) {
    if (!existsSync(join(input, 'package.json'))) {
      throw new UsageError(`${input} has no package.json; give an extension folder or a .vsix`);
    }
    return input;
  }
  if (!/\.vsix$/i.test(input)) {
    throw new UsageError('give an extension folder or a .vsix file');
  }
  const dest = mkdtempSync(join(tmpdir(), 'jest-audit-vsix-'));
  await extractVsix(readFileSync(input), dest);
  return dest;
}

function runtimeSarif(report: AuditReport): object {
  const fakeResult: ExtResult = { ext: report.static.ext, risk: scoreExtension(report.runtime.signals) };
  const sarif = toExtensionSarif([fakeResult], [], VERSION) as { runs: { tool: { driver: { name: string } }; results: { ruleId: string; properties?: object }[] }[] };
  const run = sarif.runs[0];
  run.tool.driver.name = 'jest-security-runtime';
  for (const r of run.results) {
    const evs = report.runtime.evidence.get(r.ruleId) ?? [];
    r.properties = { ...(r.properties ?? {}), evidence: evs.slice(0, 5), confirms: report.chain.links.filter((l) => l.confirmedBy.some((c) => c.id === r.ruleId)).map((l) => l.vector) };
  }
  return run;
}

export function auditSarif(report: AuditReport): object {
  const sarif = toExtensionSarif([report.static], [], VERSION) as { runs: { results: { ruleId: string; properties?: object }[] }[] };
  const verdict = new Map(report.chain.links.map((l) => [l.vector, l]));
  for (const r of sarif.runs[0].results) {
    const l = verdict.get(signalIdOf(r.ruleId));
    if (l) {
      r.properties = { ...(r.properties ?? {}), runtimeVerdict: l.verdict, confirmedBy: l.confirmedBy };
    }
  }
  sarif.runs.push(runtimeSarif(report) as never);
  return sarif;
}

const LEVEL = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW' } as const;

export function auditText(r: AuditReport): string {
  const lines = [
    `== Audit: ${r.extension.id}@${r.extension.version} ==`,
    `  mode ${r.mode}, ${r.options.duration}s, exec ${r.options.allowExec ? 'allowed' : 'blocked'}, network ${r.options.offline ? 'offline' : 'live'}, ${r.run.events} events recorded${r.run.timedOut ? ' (timed out)' : ''}`,
    `  kernel probes: ${r.run.kernelSkipped ?? `ran${r.run.baselineRwx !== undefined ? ` (JIT baseline ${r.run.baselineRwx} W+X)` : ''}`}`,
    '',
    `== Combined risk: ${LEVEL[r.combined.level]} (${r.combined.score}) — static ${LEVEL[r.static.risk.level]} ${r.static.risk.score}, runtime ${r.runtime.signals.length} finding(s) ==`,
    '',
    '== Runtime evidence ==',
    ...(r.runtime.signals.length ? r.runtime.signals.map((s) => `  ✖ ${s.id.padEnd(36)} ${s.message}`) : ['  (nothing suspicious observed)']),
    '',
    `== Evidence chain: ${r.chain.confirmed} static finding(s) confirmed at runtime ==`,
  ];
  for (const l of r.chain.links) {
    const mark = l.verdict === 'confirmed' ? '✔ confirmed   ' : l.verdict === 'not-observed' ? '· not observed' : '– static only ';
    const where = l.locations[0] ? ` (${l.locations[0].file.split(/[\\/]/).slice(-2).join('/')}:${l.locations[0].line})` : '';
    lines.push(`  ${mark} ${l.vector}${where}`);
    for (const c of l.confirmedBy) {
      lines.push(`       ↳ ${c.kind === 'api' ? 'API ' : ''}${c.id}: ${c.detail.slice(0, 140)}`);
    }
  }
  if (r.chain.runtimeOnly.length) {
    lines.push('', '== Runtime-only (no static rule predicted it) ==', ...r.chain.runtimeOnly.map((s) => `  ! ${s.id}: ${s.message}`));
  }
  if (r.runtime.errors.length) {
    lines.push('', `  note: ${r.runtime.errors.length} error(s) while running the extension, e.g. ${String(r.runtime.errors[0].message).split('\n')[0].slice(0, 140)}`);
  }
  lines.push('', '  Static signals are suspicions; "confirmed" means the behaviour was observed while the extension ran in the sandbox.', '');
  return lines.join('\n');
}

export async function auditExtension(dir: string, mode: 'harness' | 'vscode', opts: RunOptions, staticScan: (dir: string) => Promise<ExtResult>): Promise<AuditReport> {
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>;
  const st = await staticScan(dir);
  const baselineRwx = mode === 'harness' ? await kernelBaseline(opts) : undefined;
  const run: RunResult = mode === 'vscode' ? await runVsCode(dir, opts) : await runHarness(dir, opts);
  const orphans = findOrphans(run.events);
  const runtime = classify(run.events, run.sandbox, { duration: opts.duration, manifest, orphans, kernel: run.kernel, baselineRwx });
  const staticSignals: Signal[] = st.risk.signals;
  const chain = buildEvidence(staticSignals, runtime);
  return {
    extension: { id: st.ext.id, version: st.ext.version, path: dir },
    mode,
    options: opts,
    static: st,
    runtime,
    run: { events: run.events.length, exitCode: run.exitCode, timedOut: run.timedOut, kernelSkipped: run.kernelSkipped, orphans: orphans.length, baselineRwx },
    chain,
    combined: scoreExtension([...staticSignals, ...runtime.signals]),
  };
}

export const auditExtensionCmd: Command = {
  name: 'audit-extension',
  summary: 'Run one extension in a sandbox (IAST agent + OS checks) and cross-check its static findings with what it actually does',
  args: '<extension folder | .vsix>',
  flags: {
    yes: { type: 'boolean', description: 'Confirm that the extension’s code may run (required)' },
    mode: { type: 'string', value: '<harness|vscode>', description: 'harness: headless Node with a recording vscode API (default); vscode: a separate real VS Code instance', default: 'harness' },
    duration: { type: 'number', value: '<seconds>', description: 'How long the extension runs after activation', default: 30 },
    'invoke-commands': { type: 'boolean', description: 'Also run every command the extension registers (harness mode)' },
    'allow-exec': { type: 'boolean', description: 'Let child processes really run (needed to observe daemons); default: record and block' },
    offline: { type: 'boolean', description: 'Block DNS and outbound connections (they are still recorded)' },
    kernel: { type: 'boolean', description: 'Kernel probes for raw sockets / W+X memory (Linux, root, bpftrace)' },
    format: { type: 'string', alias: 'f', value: '<sarif|md|json|text>', description: 'Format of the --out file', default: 'sarif' },
    out: { type: 'string', alias: 'o', value: '<file>', description: 'Report file (--out - prints it to stdout)', default: 'audit.sarif' },
    'fail-on': { type: 'string', value: '<high|medium|none>', description: 'Exit 1 when the combined risk reaches this level', default: 'high' },
    ...DEEP_FLAGS,
  },
  examples: [
    'jest-security audit-extension ./my-extension --yes --offline',
    'jest-security audit-extension suspicious.vsix --yes --offline --invoke-commands --deep',
    'sudo -E jest-security audit-extension ./ext --yes --kernel --allow-exec   # Linux: raw sockets, W+X memory, daemons',
    'jest-security audit-extension ./ext --yes --mode vscode --duration 60',
  ],
  async run({ positionals, flags }, io: Io) {
    if (!positionals[0]) {
      throw new UsageError('give an extension folder or .vsix');
    }
    if (!flags.yes) {
      io.err(`${WARNING}\n`);
      return 2;
    }
    const mode = String(flags.mode);
    if (mode !== 'harness' && mode !== 'vscode') {
      throw new UsageError('--mode must be harness or vscode');
    }
    if (mode === 'vscode' && !findVsCode()) {
      throw new UsageError('--mode vscode needs VS Code (or JEST_AUDIT_CODE pointing at its `code` CLI)');
    }
    const format = String(flags.format);
    if (!['sarif', 'md', 'json', 'text'].includes(format)) {
      throw new UsageError('--format must be sarif, md, json or text');
    }
    const fail = String(flags['fail-on']);
    if (!['high', 'medium', 'none'].includes(fail)) {
      throw new UsageError('--fail-on must be high, medium or none');
    }
    if (flags.kernel && kernelTracingUnavailable()) {
      io.err(`note: ${kernelTracingUnavailable()}\n`);
    }
    const dir = await materialise(resolve(io.cwd, positionals[0]));
    const deep = deepOptions(flags);
    const opts: RunOptions = {
      duration: Math.max(1, Number(flags.duration) || 30),
      invokeCommands: !!flags['invoke-commands'],
      allowExec: !!flags['allow-exec'],
      offline: !!flags.offline,
      kernel: !!flags.kernel,
    };
    io.err(`static scan, then running ${dir} for ${opts.duration}s (${mode})…\n`);
    const report = await auditExtension(dir, mode, opts, async (d) => {
      const { results } = await scanExtensions([d], { allowlist: [], trusted: [], includeNodeModules: true, maxFiles: 2000, online: deep.online, analyzers: deep.analyzers, analyzerTimeoutMs: deep.analyzerTimeoutMs });
      if (!results[0]) {
        throw new Error(`no extension found in ${d}`);
      }
      return results[0];
    });
    const text = auditText(report);
    const file =
      format === 'sarif'
        ? JSON.stringify(auditSarif(report), null, 2) + '\n'
        : format === 'json'
          ? JSON.stringify({ ...report, runtime: { ...report.runtime, evidence: Object.fromEntries(report.runtime.evidence) } }, null, 2) + '\n'
          : format === 'md'
            ? `${toExtensionMarkdown([report.static], [])}\n\n## Runtime audit\n\n\`\`\`text\n${text}\`\`\`\n`
            : text;
    if (flags.out === '-') {
      io.out(file);
    } else {
      io.out(text);
      if (format !== 'text' || flags.out !== 'audit.sarif') {
        emit(io, file, flags.out);
      }
    }
    const rank = { low: 0, medium: 1, high: 2 } as const;
    return fail !== 'none' && rank[report.combined.level] >= rank[fail as 'high' | 'medium'] ? 1 : 0;
  },
};

/** Titles for the runtime vectors (used in help / docs). */
export const RUNTIME_VECTORS = Object.entries(SIGNALS)
  .filter(([, s]) => s.category === 'runtime')
  .map(([id, s]) => ({ id, title: s.title }));
