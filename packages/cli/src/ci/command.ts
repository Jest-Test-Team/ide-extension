import { appendFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { coverageData, deepOptions, DEEP_FLAGS } from '../analyzers/coverage';
import { UsageError, VERSION, type Command } from '../lib/args';
import { emit } from '../lib/output';
import { defaultCacheDir, type Registry } from './fetch';
import { runGuard } from './guard';
import { EMPTY_POLICY, loadPolicy, type FailOn } from './policy';
import { githubAnnotations, guardJson, guardMarkdown, guardSarif, guardText } from './report';

export const DEFAULT_POLICY = '.github/jest-security.yml';

/**
 * `jest-security scan-manifest`: the CI gate. Reads the extension lists committed to a repository,
 * downloads each new or changed extension from the registry, scans it, and fails on risk or policy.
 */
export const scanManifest: Command = {
  name: 'scan-manifest',
  summary: 'CI gate: scan extensions a repository recommends (.vscode/extensions.json, dev containers, workspaces) by downloading them; fail on risk or policy',
  args: '[manifest files or folders…]',
  flags: {
    base: { type: 'string', value: '<git-ref>', description: 'Compare with this revision; only added or version-changed extensions are scanned (e.g. origin/main)' },
    all: { type: 'boolean', description: 'With --base, also scan unchanged extensions' },
    registry: { type: 'string', value: '<marketplace|open-vsx>', description: 'Where to download packages from', default: 'marketplace' },
    'registry-url': { type: 'string', value: '<url>', description: 'Registry base URL, for a private Marketplace / Open VSX mirror (default https://marketplace.visualstudio.com or https://open-vsx.org)' },
    'target-platform': { type: 'string', value: '<platform>', description: 'Build to scan for platform-specific extensions', default: 'linux-x64' },
    'cache-dir': { type: 'string', value: '<dir>', description: 'Download cache (default $RUNNER_TEMP/jest-security-vsix or the temp folder)' },
    policy: { type: 'string', value: '<file>', description: `Policy file (default ${DEFAULT_POLICY} when it exists)` },
    'fail-on': { type: 'string', value: '<high|medium|none>', description: 'Exit 1 when a new or changed extension reaches this level (default: policy, else high)' },
    format: { type: 'string', alias: 'f', value: '<sarif|md|json|text>', description: 'Format of the --out file (the terminal always gets the readable report)', default: 'sarif' },
    out: { type: 'string', alias: 'o', value: '<file>', description: 'Report file (--out - prints the file format to stdout instead)', default: 'security.sarif' },
    summary: { type: 'string', value: '<file>', description: 'Append the Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)' },
    annotations: { type: 'boolean', description: 'Print GitHub annotations on the manifest lines (default: on inside GitHub Actions)' },
    allowlist: { type: 'string', multiple: true, value: '<publisher.name[@version]>', description: 'Trust these extensions (added to the policy allowlist)' },
    'trusted-publisher': { type: 'string', multiple: true, value: '<publisher>', description: 'Treat this publisher as known' },
    'node-modules': { type: 'boolean', description: 'Also scan bundled node_modules', default: true },
    'max-files': { type: 'number', description: 'Maximum JavaScript files scanned per extension', default: 2000 },
    ...DEEP_FLAGS,
    online: { type: 'boolean', description: 'Marketplace reputation lookups (verified publisher, installs); the registry is contacted for downloads anyway', default: true },
  },
  examples: [
    'jest-security scan-manifest                               # every extension the repo recommends',
    'jest-security scan-manifest --base origin/main            # only what this branch adds or re-versions',
    'jest-security scan-manifest .devcontainer --fail-on medium',
    'jest-security scan-manifest --base "$BASE_SHA" --summary "$GITHUB_STEP_SUMMARY" --out ext.sarif',
    'jest-security scan-manifest team-extensions.txt --registry open-vsx',
  ],
  async run({ positionals, flags }, io) {
    const format = String(flags.format);
    if (!['sarif', 'md', 'json', 'text'].includes(format)) {
      throw new UsageError('--format must be sarif, md, json or text');
    }
    const registry = String(flags.registry) as Registry;
    if (registry !== 'marketplace' && registry !== 'open-vsx') {
      throw new UsageError('--registry must be marketplace or open-vsx');
    }
    const policyPath = flags.policy ? resolve(io.cwd, String(flags.policy)) : existsSync(resolve(io.cwd, DEFAULT_POLICY)) ? resolve(io.cwd, DEFAULT_POLICY) : undefined;
    if (flags.policy && !existsSync(policyPath!)) {
      throw new Error(`policy file not found: ${String(flags.policy)}`);
    }
    const policy = policyPath ? loadPolicy(policyPath) : EMPTY_POLICY;
    const failOn = String(flags['fail-on'] ?? policy.failOn ?? 'high') as FailOn;
    if (!['high', 'medium', 'none'].includes(failOn)) {
      throw new UsageError('--fail-on must be high, medium or none');
    }
    for (const p of positionals) {
      if (!existsSync(resolve(io.cwd, p))) {
        throw new UsageError(`not found: ${p}`);
      }
    }
    const deep = deepOptions(flags);
    const report = await runGuard({
      root: io.cwd,
      manifests: positionals,
      base: flags.base as string | undefined,
      all: !!flags.all,
      registry,
      fetch: flags['registry-url'] ? { [registry === 'open-vsx' ? 'openVsxUrl' : 'marketplaceUrl']: String(flags['registry-url']).replace(/\/+$/, '') } : undefined,
      targetPlatform: String(flags['target-platform']),
      cacheDir: (flags['cache-dir'] as string | undefined) ?? defaultCacheDir(),
      policy,
      failOn,
      allowlist: [...policy.allowlist, ...((flags.allowlist as string[] | undefined) ?? [])],
      trusted: [...policy.trustedPublishers, ...((flags['trusted-publisher'] as string[] | undefined) ?? [])],
      includeNodeModules: flags['node-modules'] !== false,
      maxFiles: flags['max-files'] as number,
      reputation: flags.online !== false,
      analyzers: deep.analyzers,
      analyzerTimeoutMs: deep.analyzerTimeoutMs,
      onProgress: (msg) => io.color && io.err(`\r${msg.padEnd(70).slice(0, 70)}`),
    });
    if (io.color) {
      io.err('\r' + ' '.repeat(72) + '\r');
    }
    if (!report.files.length && !report.changes.length) {
      io.err('no extension lists found (.vscode/extensions.json, devcontainer.json, *.code-workspace); nothing to scan\n');
    }

    const markdown = guardMarkdown(report);
    const text = guardText(report);
    const file =
      format === 'sarif'
        ? JSON.stringify(report.coverage ? withCoverage(guardSarif(report, VERSION), coverageData(report.coverage)) : guardSarif(report, VERSION), null, 2) + '\n'
        : format === 'md'
          ? markdown
          : format === 'json'
            ? JSON.stringify(guardJson(report), null, 2) + '\n'
            : text;
    if (flags.out === '-') {
      io.out(file);
    } else {
      io.out(text);
      if (format !== 'text' || flags.out !== 'security.sarif') {
        emit(io, file, flags.out);
      }
    }
    if (flags.summary) {
      appendFileSync(resolve(io.cwd, String(flags.summary)), markdown + '\n');
    }
    if (flags.annotations ?? process.env.GITHUB_ACTIONS === 'true') {
      io.out(githubAnnotations(report));
    }
    return report.exitCode;
  },
};

function withCoverage(sarif: object, coverage: object): object {
  const log = sarif as { runs: Record<string, unknown>[] };
  log.runs.forEach((r) => (r.properties = { ...(r.properties as object), coverage }));
  return log;
}
