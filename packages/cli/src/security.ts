import type { Rule } from '@ide-ext/core';
import { JULIA_RULES } from '../../../extensions/julia-profiler/src/rules';
import { ENDPOINT_TOOL, endpointRules } from './endpoint';
import { HW_TOOL, hwRules } from './hw';
import { JULIA_TOOL } from './julia';
import { processIo, runTool, VERSION, type Command, type Io, type Tool } from './lib/args';
import { assetDir, type AssetKind } from './lib/assets';
import { lintCommand } from './lib/lint';
import { run, which } from './lib/proc';

/** Every rule of the three extensions, de-duplicated by id. */
export function allRules(): Rule[] {
  const seen = new Set<string>();
  return [...endpointRules('all'), ...hwRules(), ...JULIA_RULES].filter((r) => !seen.has(r.id) && seen.add(r.id));
}

const SUBTOOLS: Record<string, Tool> = { endpoint: ENDPOINT_TOOL, hw: HW_TOOL, embedded: HW_TOOL, julia: JULIA_TOOL };

const lint = lintCommand({
  summary: 'Run every linter (endpoint API + compliance, ESP32 / ESPHome, Julia) over the given paths',
  toolName: 'jest-security',
  title: 'Security & Systems Engineering findings',
  rules: allRules,
  examples: ['jest-security lint .', 'jest-security lint src firmware --format md --out findings.md'],
});

const scan: Command = {
  ...lintCommand({
    name: 'scan',
    summary: 'Like lint, but writes a single SARIF file for GitHub code scanning (default security.sarif)',
    toolName: 'jest-security',
    title: 'Security & Systems Engineering findings',
    rules: allRules,
    examples: ['jest-security scan .', 'jest-security scan services firmware --out reports/all.sarif'],
  }),
};
scan.flags = { ...scan.flags, format: { ...scan.flags!.format, default: 'sarif' }, out: { ...scan.flags!.out, default: 'security.sarif' } };

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
    doctor,
  ],
  footer: 'Examples:\n  jest-security endpoint simulate attack.ptree.yaml\n  jest-security hw entropy trng.bin --bits 8\n  jest-security julia report profile.json\n  jest-security scan . --out security.sarif',
};

export async function main(argv: readonly string[], io: Io = processIo()): Promise<number> {
  const sub = SUBTOOLS[argv[0]];
  if (sub) {
    return runTool({ ...sub, name: `jest-security ${argv[0]}` }, argv.slice(1), io);
  }
  return runTool(SECURITY_TOOL, argv, io);
}
