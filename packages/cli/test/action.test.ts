import { readFileSync } from 'node:fs';
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
});
