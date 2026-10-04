import type { Rule } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { CONSTANTS, FUNCTIONS, signature } from '../../../extensions/endpoint-security/src/apiDb';
import { API_RULES } from '../../../extensions/endpoint-security/src/apiRules';
import { COMPLIANCE_CUSTOM_RULES } from '../../../extensions/endpoint-security/src/complianceRules';
import { loadCodeRules, scanExtensionCode } from '../../../extensions/endpoint-security/src/extscan/codeScan';
import { loadManifestOptions } from '../../../extensions/endpoint-security/src/extscan/data';
import { readExtensionsDir } from '../../../extensions/endpoint-security/src/extscan/disk';
import { manifestSignals } from '../../../extensions/endpoint-security/src/extscan/manifest';
import { toExtensionMarkdown, toExtensionSarif } from '../../../extensions/endpoint-security/src/extscan/report';
import type { ExtResult } from '../../../extensions/endpoint-security/src/extscan/scanner';
import { isAllowlisted, scoreExtension } from '../../../extensions/endpoint-security/src/extscan/score';
import { serveHttp, serveStdio } from '../../../extensions/endpoint-security/src/ptree/agent';
import { parseRules, parseScenario, simulate, type SimulationResult } from '../../../extensions/endpoint-security/src/ptree/engine';
import { loadBuiltInPacks, rulesOf } from '../../../extensions/endpoint-security/src/rulePacks';
import { runTool, UsageError, VERSION, type Command, type Io, type Tool } from './lib/args';
import { assetDir } from './lib/assets';
import { lintCommand, treeSitter } from './lib/lint';
import { emit, formatOf, REPORT_FLAGS } from './lib/output';
import { RuleEngine } from '@ide-ext/core';

export const complianceRules = (): Rule[] => [...rulesOf(loadBuiltInPacks(assetDir('rules'))), ...COMPLIANCE_CUSTOM_RULES];

export function endpointRules(only?: unknown): Rule[] {
  if (only !== undefined && only !== 'api' && only !== 'compliance' && only !== 'all') {
    throw new UsageError('--only must be api, compliance or all');
  }
  return [...(only === 'compliance' ? [] : API_RULES), ...(only === 'api' ? [] : complianceRules())];
}

const lint = lintCommand({
  summary: 'Validate WFP/ETW/Endpoint Security API usage (C, C++, Rust) and scan Go/TS/JS for PCI DSS 4.0.1 and CCSP D2 issues',
  toolName: 'jest-endpoint',
  title: 'Endpoint Security & Compliance findings',
  rules: (flags) => endpointRules(flags.only ?? 'all'),
  extraFlags: { only: { type: 'string', value: '<api|compliance|all>', description: 'Rule group to run', default: 'all' } },
  examples: ['jest-endpoint lint src/', 'jest-endpoint lint --only api agent/ --format json', 'jest-endpoint lint . --fail-on warning'],
});

const compliance = lintCommand({
  name: 'compliance',
  summary: 'PCI DSS 4.0.1 / CCSP Domain 2 compliance scan (shortcut for lint --only compliance)',
  toolName: 'jest-endpoint',
  title: 'Compliance report (PCI DSS v4.0.1, CCSP Domain 2)',
  rules: () => endpointRules('compliance'),
  examples: ['jest-endpoint compliance services/ --format sarif --out compliance.sarif', 'jest-endpoint compliance . --format md --out report.md'],
});

function treeText(r: SimulationResult): string[] {
  const byId = new Map(r.processes.map((p) => [p.id, p]));
  const lines: string[] = [];
  const visit = (id: string, prefix: string, last: boolean, root: boolean) => {
    const p = byId.get(id)!;
    const marks = [p.end !== undefined ? 'exited' : '', p.terminatedBy ? `killed by ${p.terminatedBy}` : '', p.injectedBy ? `injected by ${p.injectedBy.join(', ')}` : '', p.detections.length ? `⚠ ${p.detections.join(', ')}` : '']
      .filter(Boolean)
      .join('; ');
    lines.push(`${prefix}${root ? '' : last ? '└─ ' : '├─ '}${p.image.split(/[\\/]/).pop()} (${p.id})${marks ? `  [${marks}]` : ''}`);
    p.children.forEach((c, i) => visit(c, root ? prefix : prefix + (last ? '   ' : '│  '), i === p.children.length - 1, false));
  };
  r.processes.filter((p) => !p.parent || !byId.has(p.parent)).forEach((p) => visit(p.id, '', true, true));
  return lines;
}

export function simulationText(r: SimulationResult): string {
  const out = [`Scenario: ${r.scenario}`, '', 'Process tree:', ...treeText(r).map((l) => `  ${l}`), ''];
  out.push(`Detections (${r.detections.length}):`);
  for (const d of r.detections) {
    out.push(`  ${d.severity.toUpperCase().padEnd(8)} ${String(d.t).padStart(6)} ms  ${d.title} (${d.ruleId})${d.mitre.length ? `  ATT&CK ${d.mitre.join(', ')}` : ''}`);
  }
  if (!r.detections.length) {
    out.push('  none');
  }
  out.push('', 'Timeline:');
  for (const e of r.timeline) {
    out.push(`  ${String(e.t).padStart(6)} ms  ${e.summary}${e.detections.length ? `  ⚠ ${e.detections.join(', ')}` : ''}`);
  }
  for (const w of r.warnings) {
    out.push(`warning: ${w}`);
  }
  return out.join('\n') + '\n';
}

const simulateCmd: Command = {
  name: 'simulate',
  summary: 'Replay a *.ptree.yaml process-tree scenario against detection rules (data only, nothing is executed)',
  args: '<scenario.ptree.yaml>',
  flags: {
    rules: { type: 'string', multiple: true, value: '<rules.yaml>', description: 'Additional rules file' },
    'default-rules': { type: 'boolean', description: 'Include the built-in ATT&CK-mapped rules (use --no-default-rules to disable)', default: true },
    expect: { type: 'string', multiple: true, value: '<rule-id>', description: 'Exit 1 unless this rule fires (detection regression tests)' },
    json: { type: 'boolean', description: 'Print the full result as JSON' },
    out: REPORT_FLAGS.out,
  },
  examples: ['jest-endpoint simulate scenarios/ransom.ptree.yaml', 'jest-endpoint simulate s.ptree.yaml --rules team.yaml --expect mass-file-encryption'],
  async run({ positionals, flags }, io) {
    if (positionals.length !== 1) {
      throw new UsageError('expected one scenario file');
    }
    const extra = [
      ...(flags['default-rules'] !== false ? [readFileSync(join(assetDir('ptree'), 'default-rules.yaml'), 'utf8')] : []),
      ...((flags.rules as string[] | undefined) ?? []).map((f) => readFileSync(resolve(io.cwd, f), 'utf8')),
    ].flatMap((t) => parseRules(t));
    const result = simulate(parseScenario(readFileSync(resolve(io.cwd, positionals[0]), 'utf8'), extra));
    emit(io, flags.json ? JSON.stringify(result, null, 2) + '\n' : simulationText(result), flags.out);
    const missing = ((flags.expect as string[] | undefined) ?? []).filter((id) => !result.detections.some((d) => d.ruleId === id));
    if (missing.length) {
      io.err(`expected detection(s) did not fire: ${missing.join(', ')}\n`);
      return 1;
    }
    return 0;
  },
};

const apiCmd: Command = {
  name: 'api',
  summary: 'Show the signature, semantics and docs of a WFP / ETW / Endpoint Security function or constant',
  args: '<name>',
  flags: { list: { type: 'boolean', description: 'List every known function and constant' } },
  examples: ['jest-endpoint api FwpmEngineOpen0', 'jest-endpoint api es_ --list'],
  async run({ positionals, flags }, io) {
    const q = positionals[0] ?? '';
    if (flags.list || !q) {
      const fns = [...FUNCTIONS.values()].filter((f) => f.name.toLowerCase().includes(q.toLowerCase()));
      const consts = [...CONSTANTS.values()].filter((c) => c.name.toLowerCase().includes(q.toLowerCase()));
      fns.forEach((f) => io.out(`${f.name.padEnd(30)} ${f.framework}${f.deprecated ? ' (deprecated)' : ''}\n`));
      consts.forEach((c) => io.out(`${c.name.padEnd(30)} ${c.framework} constant\n`));
      return 0;
    }
    const fn = FUNCTIONS.get(q);
    if (fn) {
      io.out(
        [
          signature(fn),
          '',
          fn.doc,
          `Framework: ${fn.framework}`,
          `Returns:   ${fn.returns}`,
          ...(fn.irql ? [`IRQL:      ${fn.irql}`] : []),
          ...(fn.pairedWith ? [`Release:   ${fn.pairedWith}`] : []),
          ...(fn.deprecated ? [`Deprecated: use ${fn.deprecated}`] : []),
          '',
          'Parameters:',
          ...fn.params.map((p) => `  ${p.type} ${p.name} — ${p.doc}`),
          ...(fn.notes?.length ? ['', 'Notes:', ...fn.notes.map((n) => `  - ${n}`)] : []),
          '',
          fn.url,
          '',
        ].join('\n'),
      );
      return 0;
    }
    const c = CONSTANTS.get(q);
    if (c) {
      io.out(`${c.name} — ${c.doc}\n${c.framework}\n`);
      return 0;
    }
    const near = [...FUNCTIONS.keys(), ...CONSTANTS.keys()].filter((n) => n.toLowerCase().includes(q.toLowerCase())).slice(0, 10);
    io.err(`unknown API "${q}"${near.length ? `; did you mean: ${near.join(', ')}` : ''}\n`);
    return 1;
  },
};

const agentCmd: Command = {
  name: 'agent',
  summary: 'Run the process-tree simulation agent (JSON-RPC over stdio, or HTTP with --http)',
  flags: {
    http: { type: 'number', value: '<port>', description: 'Serve JSON-RPC over HTTP POST on this port' },
    host: { type: 'string', value: '<addr>', description: 'Bind address for --http (use 0.0.0.0 inside a sandbox VM)', default: '127.0.0.1' },
  },
  examples: ['jest-endpoint agent --http 8765', 'jest-endpoint agent --http 8765 --host 0.0.0.0'],
  async run({ flags }) {
    if (flags.http !== undefined) {
      serveHttp(flags.http as number, flags.host as string);
    } else {
      serveStdio();
    }
    // Keep running until the server or stdin closes.
    await new Promise<void>(() => undefined);
    return 0;
  },
};

/** VS Code-family extension folders for the current user. */
export function defaultExtensionDirs(): string[] {
  const h = homedir();
  return ['.vscode', '.vscode-insiders', '.vscode-oss', '.cursor', '.windsurf', '.vscode-server'].map((d) => join(h, d, 'extensions'));
}

const RANK = { high: 2, medium: 1, low: 0 } as const;

export async function scanExtensions(dirs: string[], opts: { allowlist: string[]; trusted: string[]; includeNodeModules: boolean; maxFiles: number; onProgress?: (id: string) => void }): Promise<{ results: ExtResult[]; codeRules: Rule[] }> {
  const dataDir = assetDir('extscan');
  const manifestOpts = loadManifestOptions(dataDir, opts.trusted);
  const { rules: codeRules } = loadCodeRules(dataDir);
  const host = treeSitter();
  const engine = new RuleEngine(host, codeRules);
  const results: ExtResult[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    for (const e of readExtensionsDir(dir)) {
      if (seen.has(e.path)) {
        continue;
      }
      seen.add(e.path);
      opts.onProgress?.(e.id);
      const code = await scanExtensionCode(engine, host, e.path, e.packageJSON, { includeNodeModules: opts.includeNodeModules, maxFileSizeMB: 10, maxFiles: opts.maxFiles });
      const signals = [...manifestSignals(e, manifestOpts), ...code.signals];
      results.push({
        ext: { id: e.id, version: e.version, displayName: e.displayName, path: e.path, builtin: e.builtin, source: e.source },
        risk: scoreExtension(signals, { allowlisted: isAllowlisted(e.id, e.version, opts.allowlist) }),
      });
    }
  }
  results.sort((a, b) => RANK[b.risk.level] - RANK[a.risk.level] || b.risk.score - a.risk.score || a.ext.id.localeCompare(b.ext.id));
  return { results, codeRules };
}

/** `vscode`, `cursor`, … from a path like ~/.cursor/extensions/x. */
const editorOf = (p: string) => /[\\/]\.([\w-]+)[\\/]extensions[\\/]/.exec(p)?.[1] ?? 'custom';

function extensionsText(io: Io, results: ExtResult[], dirs: string[]): string {
  const c = (code: number, s: string) => (io.color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const COLOR = { high: 31, medium: 33, low: 32 } as const;
  const lines = [`Scanned ${results.length} extension(s) in ${dirs.join(', ')}`, ''];
  for (const r of results) {
    const editor = dirs.length > 1 ? `  [${editorOf(r.ext.path)}]` : '';
    lines.push(`${c(COLOR[r.risk.level], r.risk.level.toUpperCase().padEnd(6))} ${String(r.risk.score).padStart(3)}  ${r.ext.id}@${r.ext.version}${editor}${r.risk.allowlisted ? '  (allowlisted)' : ''}`);
    if (r.risk.level !== 'low') {
      for (const s of r.risk.signals.slice(0, 5)) {
        const loc = s.locations[0];
        lines.push(`         - ${s.message}${loc ? `  ${loc.file}:${loc.finding.range.start.line + 1}` : ''}`);
      }
      for (const b of r.risk.boosts) {
        lines.push(`         + ${b.label}`);
      }
    }
  }
  const n = { high: 0, medium: 0, low: 0 };
  results.forEach((r) => n[r.risk.level]++);
  lines.push('', `${n.high} high, ${n.medium} medium, ${n.low} low. Heuristic: flags risk signals, it cannot prove an extension safe.`);
  return lines.join('\n') + '\n';
}

const extensionsCmd: Command = {
  name: 'extensions',
  summary: 'Risk-scan installed VS Code / Cursor / VSCodium extensions on disk (heuristic, read-only)',
  args: '[extension dirs…]',
  flags: {
    ...REPORT_FLAGS,
    allowlist: { type: 'string', multiple: true, value: '<publisher.name[@version]>', description: 'Trust these extensions' },
    'trusted-publisher': { type: 'string', multiple: true, value: '<publisher>', description: 'Treat this publisher as known' },
    'node-modules': { type: 'boolean', description: 'Also scan bundled node_modules (--no-node-modules to skip)', default: true },
    'max-files': { type: 'number', description: 'Maximum JavaScript files scanned per extension', default: 2000 },
    'fail-on': { type: 'string', value: '<high|medium|none>', description: 'Exit 1 when an extension reaches this level', default: 'high' },
  },
  examples: ['jest-endpoint extensions', 'jest-endpoint extensions ~/.cursor/extensions --format sarif --out ext.sarif', 'jest-endpoint extensions --allowlist ms-python.python --fail-on medium'],
  async run({ positionals, flags }, io) {
    const format = formatOf(flags.format);
    const fail = flags['fail-on'];
    if (!['high', 'medium', 'none'].includes(String(fail))) {
      throw new UsageError('--fail-on must be high, medium or none');
    }
    const dirs = positionals.length ? positionals.map((p) => resolve(io.cwd, p)) : defaultExtensionDirs();
    const { results, codeRules } = await scanExtensions(dirs, {
      allowlist: (flags.allowlist as string[] | undefined) ?? [],
      trusted: (flags['trusted-publisher'] as string[] | undefined) ?? [],
      includeNodeModules: flags['node-modules'] !== false,
      maxFiles: flags['max-files'] as number,
      onProgress: (id) => io.color && io.err(`\rscanning ${id.padEnd(60).slice(0, 60)}`),
    });
    if (io.color) {
      io.err('\r' + ' '.repeat(70) + '\r');
    }
    const text =
      format === 'sarif'
        ? JSON.stringify(toExtensionSarif(results, codeRules, VERSION), null, 2) + '\n'
        : format === 'md'
          ? toExtensionMarkdown(results, codeRules) + '\n'
          : format === 'json'
            ? JSON.stringify(results, null, 2) + '\n'
            : extensionsText(io, results.filter((r) => !r.ext.builtin), dirs.filter((d) => results.some((r) => r.ext.path.startsWith(d))));
    emit(io, text, flags.out);
    const limit = fail === 'none' ? Infinity : RANK[fail as 'high' | 'medium'];
    return results.some((r) => RANK[r.risk.level] >= limit) ? 1 : 0;
  },
};

export const ENDPOINT_TOOL: Tool = {
  name: 'jest-endpoint',
  version: VERSION,
  summary: 'Endpoint Security & Compliance Toolkit',
  commands: [lint, compliance, simulateCmd, apiCmd, agentCmd, extensionsCmd],
  footer: 'Exit codes: 0 = clean, 1 = findings at/above --fail-on (or failed expectation), 2 = usage or runtime error.',
};

export const main = (argv: readonly string[], io?: Io) => runTool(ENDPOINT_TOOL, argv, io);
