import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { scanManifest } from '../src/ci/command';
import { REPO } from './io';

interface Step {
  id?: string;
  run?: string;
  uses?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
}
const action = parse(readFileSync(join(REPO, 'action.yml'), 'utf8')) as {
  inputs: Record<string, { default?: string }>;
  outputs: Record<string, { value: string }>;
  runs: { using: string; steps: Step[] };
};
const text = readFileSync(join(REPO, 'action.yml'), 'utf8');
const cliVersion = (JSON.parse(readFileSync(join(REPO, 'packages/cli/package.json'), 'utf8')) as { version: string }).version;

describe('GitHub Action (action.yml)', () => {
  it('is a composite action pinned to the CLI version in this repository', () => {
    expect(action.runs.using).toBe('composite');
    expect(action.inputs.version.default).toBe(cliVersion);
  });

  it('references only declared inputs and produced step outputs', () => {
    for (const [, name] of text.matchAll(/inputs\.([\w-]+)/g)) {
      expect(Object.keys(action.inputs), `inputs.${name}`).toContain(name);
    }
    const produced = new Map<string, Set<string>>();
    for (const s of action.runs.steps.filter((x) => x.id && x.run)) {
      const names = new Set([...s.run!.matchAll(/(?:echo "|printf '|console\.log\(`|\\n)([\w-]+)=/g)].map((m) => m[1]));
      produced.set(s.id!, names);
    }
    for (const [, id, name] of text.matchAll(/steps\.([\w-]+)\.outputs\.([\w-]+)/g)) {
      expect([...(produced.get(id) ?? [])], `steps.${id}.outputs.${name}`).toContain(name);
    }
  });

  it('never interpolates inputs or event data into scripts (injection-safe)', () => {
    for (const s of action.runs.steps.filter((x) => x.run)) {
      expect(s.run, s.id ?? s.run!.slice(0, 40)).not.toMatch(/\$\{\{/);
    }
  });

  it('passes only flags scan-manifest knows', () => {
    const scan = action.runs.steps.find((s) => s.id === 'scan')!.run!;
    const flags = new Set([...scan.matchAll(/(?:^|[\s(])--([a-z][\w-]*)/g)].map((m) => m[1]));
    for (const f of flags) {
      expect(Object.keys(scanManifest.flags!), `--${f}`).toContain(f);
    }
    expect(flags.size).toBeGreaterThan(8);
  });

  it('the scan step records the CLI exit code under GitHub\'s bash -eo pipefail instead of aborting', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jest-sec-action-'));
    const script = join(dir, 'scan.sh');
    writeFileSync(script, action.runs.steps.find((s) => s.id === 'scan')!.run!);
    const stub = join(dir, 'cli.sh');
    writeFileSync(stub, 'echo "called: $*"; exit 1\n', { mode: 0o755 });
    for (const f of ['out', 'summary']) {
      writeFileSync(join(dir, f), '');
    }
    const env = {
      PATH: process.env.PATH,
      RUNNER_TEMP: dir,
      GITHUB_OUTPUT: join(dir, 'out'),
      GITHUB_STEP_SUMMARY: join(dir, 'summary'),
      CLI: `bash ${stub}`,
      BASE: 'abc123',
      MANIFESTS: '.vscode/extensions.json\nother dir/x.code-workspace',
      SCAN_ALL: 'false',
      FAIL_ON: '',
      POLICY: '',
      REGISTRY: 'marketplace',
      REGISTRY_URL: '',
      TARGET: 'linux-x64',
      DEEP: 'false',
    };
    // Exactly how GitHub runs `shell: bash` steps.
    const res = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], { env, encoding: 'utf8' });
    expect(res.status, res.stderr).toBe(0);
    expect(readFileSync(join(dir, 'out'), 'utf8')).toMatch(/^exit-code=1$/m);
    expect(readFileSync(join(dir, 'out'), 'utf8')).toMatch(/^scanned=0$/m);
    expect(res.stdout).toContain('--base abc123');
    expect(res.stdout).toContain('.vscode/extensions.json other');
  });
});
