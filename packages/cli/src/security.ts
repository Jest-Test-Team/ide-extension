import type { Finding, Rule } from '@ide-ext/core';
import { toExtensionMarkdown, toExtensionSarif } from '../../../extensions/endpoint-security/src/extscan/report';
import { JULIA_RULES } from '../../../extensions/julia-profiler/src/rules';
import { defaultExtensionDirs, ENDPOINT_TOOL, endpointRules, extensionsText, scanExtensions } from './endpoint';
import { analysisText, analyzeExtensions } from './extAnalysis';
import { existsSync } from 'node:fs';
import { HW_TOOL, hwRules } from './hw';
import { JULIA_TOOL } from './julia';
import { processIo, runTool, UsageError, VERSION, type Command, type Io, type Tool } from './lib/args';
import { assetDir, type AssetKind } from './lib/assets';
import { effectiveRules, lintCommand, lintFiles, patternsFrom } from './lib/lint';
import { emit, exitFor, failThreshold, formatOf, LINT_FLAGS, renderFindings, textReport } from './lib/output';
import { resolve } from 'node:path';
import { run, which } from './lib/proc';

/** Every rule of the three extensions, de-duplicated by id. */
export function allRules(): Rule[] {
  const seen = new Set<string>();
  return [...endpointRules('all'), ...hwRules(), ...JULIA_RULES].filter((r) => !seen.has(r.id) && seen.add(r.id));
}

const SUBTOOLS: Record<string, Tool> = { endpoint: ENDPOINT_TOOL, hw: HW_TOOL, embedded: HW_TOOL, julia: JULIA_TOOL };

const lint = lintCommand({
  summary: 'Run every code linter (endpoint API + compliance, ESP32 / ESPHome, Julia) over the given paths (use scan for a full audit incl. installed extensions)',
  toolName: 'jest-security',
  title: 'Security & Systems Engineering findings',
  rules: allRules,
  examples: ['jest-security lint .', 'jest-security lint src firmware --format md --out findings.md'],
});

const RISK = { high: 2, medium: 1, low: 0 } as const;

function countBySeverity(findings: ReadonlyMap<string, readonly Finding[]>) {
  const n = { error: 0, warning: 0, info: 0, hint: 0 };
  findings.forEach((fs) => fs.forEach((f) => n[f.severity]++));
  return n;
}

const scan: Command = {
  name: 'scan',
  summary: 'Full security audit: lint the code AND risk-scan installed VS Code / Cursor extensions; prints a report and writes one SARIF file (default security.sarif)',
  args: '[paths…]',
  flags: {
    ...LINT_FLAGS,
    format: { ...LINT_FLAGS.format, default: 'sarif', description: 'Format of the --out file (the terminal always gets the readable report)' },
    out: { ...LINT_FLAGS.out, default: 'security.sarif', description: 'Report file (use --out - to print the file format to stdout instead)' },
    extensions: { type: 'boolean', description: 'Include the installed-extension risk scan (--no-extensions to skip)', default: true },
    'extension-dir': { type: 'string', multiple: true, value: '<dir>', description: 'Extensions folder to scan (default: VS Code, Insiders, VSCodium, Cursor, Windsurf, remote)' },
    allowlist: { type: 'string', multiple: true, value: '<publisher.name[@version]>', description: 'Trusted extensions' },
    'extension-fail-on': { type: 'string', value: '<high|medium|none>', description: 'Exit 1 when an installed extension reaches this risk level', default: 'high' },
  },
  examples: [
    'jest-security scan                          # code in . + installed extensions → report + security.sarif',
    'jest-security scan src firmware --no-extensions',
    'jest-security scan --format md --out audit.md',
    'jest-security scan --extension-dir ~/.cursor/extensions --extension-fail-on medium',
  ],
  async run({ positionals, flags }, io) {
    const format = formatOf(flags.format);
    const threshold = failThreshold(flags['fail-on']);
    const extFail = String(flags['extension-fail-on']);
    if (!['high', 'medium', 'none'].includes(extFail)) {
      throw new UsageError('--extension-fail-on must be high, medium or none');
    }
    const rules = effectiveRules(allRules(), flags, io);
    const paths = positionals.length ? positionals : ['.'];
    const code = await lintFiles(rules, paths, io, !!flags.quiet, patternsFrom(flags, io));

    let ext: Awaited<ReturnType<typeof scanExtensions>> | undefined;
    const dirs = ((flags['extension-dir'] as string[] | undefined) ?? []).map((d) => resolve(io.cwd, d));
    const extDirs = dirs.length ? dirs : defaultExtensionDirs();
    if (flags.extensions !== false) {
      ext = await scanExtensions(extDirs, {
        allowlist: (flags.allowlist as string[] | undefined) ?? [],
        trusted: [],
        includeNodeModules: true,
        maxFiles: 2000,
        onProgress: (id) => io.color && io.err(`\rscanning extension ${id.padEnd(55).slice(0, 55)}`),
      });
      if (io.color) {
        io.err('\r' + ' '.repeat(75) + '\r');
      }
    }
    const extResults = ext?.results.filter((r) => !r.ext.builtin) ?? [];

    // 1. Report file.
    const codeTitle = 'Security & Systems Engineering findings';
    let file: string;
    if (format === 'sarif') {
      const codeLog = JSON.parse(renderFindings('sarif', io, { toolName: 'jest-security', title: codeTitle, rules, findings: code })) as { runs: unknown[] };
      const runs = [...codeLog.runs, ...(ext ? (toExtensionSarif(extResults, ext.codeRules, VERSION) as { runs: unknown[] }).runs : [])];
      file = JSON.stringify({ ...codeLog, runs }, null, 2) + '\n';
    } else if (format === 'json') {
      file = JSON.stringify({ code: [...code].map(([f, findings]) => ({ file: f, findings })), extensions: extResults }, null, 2) + '\n';
    } else if (format === 'md') {
      file = renderFindings('md', io, { toolName: 'jest-security', title: codeTitle, rules, findings: code }) + (ext ? '\n' + toExtensionMarkdown(extResults, ext.codeRules) + '\n' : '');
    } else {
      file = '';
    }

    // 2. Readable report in the terminal.
    const usedDirs = extDirs.filter((d) => extResults.some((r) => r.ext.path.startsWith(d)));
    const c = countBySeverity(code);
    const lv = { high: 0, medium: 0, low: 0 };
    extResults.forEach((r) => lv[r.risk.level]++);
    const report = [
      `== Code: ${paths.join(', ')} ==`,
      textReport(io, code).trimEnd(),
      '',
      ...(ext ? [`== Installed extensions: risk ranking and benchmark ==`, extensionsText(io, extResults, usedDirs).trimEnd(), ''] : []),
      '== Summary ==',
      `  Code:       ${c.error} error(s), ${c.warning} warning(s), ${c.info + c.hint} info in ${code.size} file(s)`,
      ext ? `  Extensions: ${lv.high} high, ${lv.medium} medium, ${lv.low} low risk (${extResults.length} scanned)` : '  Extensions: skipped (--no-extensions)',
      '',
    ].join('\n');
    const toStdout = flags.out === '-' || format === 'text';
    if (toStdout) {
      io.out(format === 'text' ? report : file);
    } else {
      io.out(report);
      emit(io, file, flags.out);
      if (format === 'sarif') {
        io.err(`  (${ext ? 2 : 1} SARIF run(s): code findings${ext ? ', installed-extension risk' : ''}; upload with github/codeql-action/upload-sarif)\n`);
      }
    }

    const extLimit = extFail === 'none' ? Infinity : RISK[extFail as 'high' | 'medium'];
    return exitFor(code, threshold) || extResults.some((r) => RISK[r.risk.level] >= extLimit) ? 1 : 0;
  },
};

const scanExtension: Command = {
  name: 'scan-extension',
  summary: 'Find every installed extension (VS Code, Insiders, VSCodium, Cursor, Windsurf, remote), scan and analyse them; report in the terminal and security.sarif',
  args: '[extensions folders or single extension folders…]',
  flags: {
    format: { type: 'string', alias: 'f', value: '<sarif|md|json|text>', description: 'Format of the --out file (the terminal always gets the readable report)', default: 'sarif' },
    out: { type: 'string', alias: 'o', value: '<file>', description: 'Report file (--out - prints the file format to stdout instead)', default: 'security.sarif' },
    details: { type: 'boolean', description: 'List the reasons for every extension, including low risk' },
    allowlist: { type: 'string', multiple: true, value: '<publisher.name[@version]>', description: 'Trust these extensions' },
    'trusted-publisher': { type: 'string', multiple: true, value: '<publisher>', description: 'Treat this publisher as known' },
    'node-modules': { type: 'boolean', description: 'Also scan bundled node_modules (--no-node-modules for a faster scan)', default: true },
    'max-files': { type: 'number', description: 'Maximum JavaScript files scanned per extension', default: 2000 },
    'fail-on': { type: 'string', value: '<high|medium|none>', description: 'Exit 1 when an extension reaches this risk level', default: 'high' },
  },
  examples: [
    'jest-security scan-extension                       # every editor → report + security.sarif',
    'jest-security scan-extension --details --format md --out extensions.md',
    'jest-security scan-extension ~/.vscode/extensions/ash-blade.postgresql-hacker-helper-1.18.0',
  ],
  async run({ positionals, flags }, io) {
    const format = String(flags.format);
    if (!['sarif', 'md', 'json', 'text'].includes(format)) {
      throw new UsageError('--format must be sarif, md, json or text');
    }
    const fail = String(flags['fail-on']);
    if (!['high', 'medium', 'none'].includes(fail)) {
      throw new UsageError('--fail-on must be high, medium or none');
    }
    const candidates = positionals.length ? positionals.map((p) => resolve(io.cwd, p)) : defaultExtensionDirs();
    const dirs = candidates.filter((d) => existsSync(d));
    if (!dirs.length) {
      throw new Error(`no extensions folder found (looked in ${candidates.join(', ')})`);
    }
    const { results: all, codeRules } = await scanExtensions(dirs, {
      allowlist: (flags.allowlist as string[] | undefined) ?? [],
      trusted: (flags['trusted-publisher'] as string[] | undefined) ?? [],
      includeNodeModules: flags['node-modules'] !== false,
      maxFiles: flags['max-files'] as number,
      onProgress: (id) => io.color && io.err(`\rscanning ${id.padEnd(60).slice(0, 60)}`),
    });
    if (io.color) {
      io.err('\r' + ' '.repeat(70) + '\r');
    }
    const results = all.filter((r) => !r.ext.builtin);
    const analysis = analyzeExtensions(results);
    const found = dirs.map((d) => `  ${d}: ${results.filter((r) => r.ext.path === d || r.ext.path.startsWith(d + '/') || r.ext.path.startsWith(d + '\\')).length} extension(s)`);
    const report = [
      '== Discovered extension folders ==',
      ...found,
      '',
      '== Risk ranking ==',
      extensionsText(io, results, dirs, flags.details ? true : undefined).trimEnd(),
      '',
      '== Analysis ==',
      analysisText(io, analysis).trimEnd(),
      '',
      '== Summary ==',
      `  ${analysis.total} extension(s): ${analysis.levels.high} high, ${analysis.levels.medium} medium, ${analysis.levels.low} low risk.`,
      '  Heuristic: risk signals and their reasons, not a verdict; many legitimate extensions run programs or read credentials.',
      '',
    ].join('\n');
    const file =
      format === 'sarif'
        ? JSON.stringify(toExtensionSarif(results, codeRules, VERSION), null, 2) + '\n'
        : format === 'md'
          ? toExtensionMarkdown(results, codeRules) + '\n'
          : format === 'json'
            ? JSON.stringify({ folders: dirs, analysis, results }, null, 2) + '\n'
            : report;
    if (flags.out === '-') {
      io.out(file);
    } else {
      io.out(report);
      // A text report is already on screen; only write it when a file name was given.
      if (format !== 'text' || flags.out !== 'security.sarif') {
        emit(io, file, flags.out);
      }
    }
    const limit = fail === 'none' ? Infinity : RISK[fail as 'high' | 'medium'];
    return results.some((r) => RISK[r.risk.level] >= limit) ? 1 : 0;
  },
};

const doctor: Command = {
  name: 'doctor',
  summary: 'Check the installation: versions, bundled data, and external tools (julia, git)',
  async run(_args, io) {
    let ok = true;
    io.out(`jest-security ${VERSION} on node ${process.version} (${process.platform}-${process.arch})\n\nBundled data:\n`);
    for (const kind of ['grammars', 'rules', 'ptree', 'extscan', 'scripts'] as AssetKind[]) {
      try {
        io.out(`  ✔ ${kind.padEnd(9)} ${assetDir(kind)}\n`);
      } catch (err) {
        ok = false;
        io.out(`  ✘ ${kind.padEnd(9)} ${(err as Error).message}\n`);
      }
    }
    io.out('\nExternal tools:\n');
    for (const [name, why] of [
      ['julia', 'jest-julia analyze / bench'],
      ['git', 'jest-julia bench baselines'],
    ]) {
      const path = which(name);
      let version = '';
      if (path) {
        version = (await run(path, ['--version'], { cwd: io.cwd, io, quiet: true }).catch(() => ({ stdout: '' }))).stdout.trim().split('\n')[0];
      }
      io.out(`  ${path ? '✔' : '–'} ${name.padEnd(9)} ${path ? `${version} (${path})` : `not found — needed for ${why}`}\n`);
    }
    return ok ? 0 : 1;
  },
};

export const SECURITY_TOOL: Tool = {
  name: 'jest-security',
  version: VERSION,
  summary: 'Security & Systems Engineering Pack — all tools in one command',
  commands: [
    { name: 'endpoint', summary: 'Endpoint Security & Compliance Toolkit (same as jest-endpoint …)', run: async () => 0 },
    { name: 'hw', summary: 'Embedded Hardware Security Workbench (same as jest-hw …)', run: async () => 0 },
    { name: 'julia', summary: 'Julia Invalidation & Compiler Profiler (same as jest-julia …)', run: async () => 0 },
    lint,
    scan,
    scanExtension,
    { ...scanExtension, name: 'scan-extensions', summary: 'Alias of scan-extension' },
    doctor,
  ],
  footer: 'Examples:\n  jest-security scan                      # full audit: code + installed extensions → report + security.sarif\n  jest-security scan-extension            # installed extensions only: discover, scan, analyse → report + security.sarif\n  jest-security endpoint simulate attack.ptree.yaml\n  jest-security hw entropy trng.bin --bits 8\n  jest-security julia report profile.json',
};

export async function main(argv: readonly string[], io: Io = processIo()): Promise<number> {
  const sub = SUBTOOLS[argv[0]];
  if (sub) {
    return runTool({ ...sub, name: `jest-security ${argv[0]}` }, argv.slice(1), io);
  }
  return runTool(SECURITY_TOOL, argv, io);
}
