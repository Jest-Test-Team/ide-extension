import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { projectName } from '../../src/project';
import { flattenInference, hasSource, parseProfile, summarize, triggersByCaller } from '../../src/profile';

// Recorded with scripts/collect.jl (Julia 1.13.1, SnoopCompile 3) on test/fixtures/InvDemo.
const profile = parseProfile(readFileSync(join(__dirname, '../fixtures/invdemo.profile.json'), 'utf8'));

describe('profile', () => {
  it('parses a recorded SnoopCompile profile', () => {
    expect(profile.julia).toBe('1.13.1');
    expect(profile.package).toBe('InvDemo');
    const root = profile.invalidations[0];
    expect(root.method).toBe('==');
    expect(root.file).toBe('/work/InvDemo/src/InvDemo.jl');
    expect(root.ninvalidated).toBeGreaterThan(100);
    expect(root.backedges.length).toBeGreaterThan(0);
  });

  it('summarizes and flattens inference', () => {
    const s = summarize(profile);
    expect(s.trees).toBe(1);
    expect(s.topRoots[0].label).toBe('InvDemo.==');
    expect(s.inferenceTime).toBeGreaterThan(0);
    const flat = flattenInference(profile.inference!.root);
    expect(flat.length).toBeGreaterThan(0);
    expect(flat[0].self).toBeGreaterThanOrEqual(flat[flat.length - 1].self);
    expect(flat.some((r) => r.method === 'process' && r.module === 'InvDemo')).toBe(true);
  });

  it('groups triggers by caller location', () => {
    const map = triggersByCaller(profile);
    expect(map.size).toBe(1);
    const [entry] = map.values();
    expect(entry.callees[0]).toContain('#process##0');
  });

  it('rejects unrelated JSON', () => {
    expect(() => parseProfile('{"a":1}')).toThrow(/version 1/);
  });

  it('detects pseudo source files', () => {
    expect(hasSource({ file: 'none', line: 1 })).toBe(false);
    expect(hasSource({ file: 'REPL[3]', line: 1 })).toBe(false);
    expect(hasSource({ file: '/a.jl', line: 0 })).toBe(false);
    expect(hasSource({ file: '/a.jl', line: 3 })).toBe(true);
  });

  it('reads the package name from Project.toml', () => {
    expect(projectName('name = "Foo"\nuuid = "x"\n[deps]\nname = "Bar"')).toBe('Foo');
    expect(projectName('[deps]\nname = "Bar"')).toBe('');
  });
});

describe('runtimeFindings', () => {
  it('maps invalidation roots and triggers onto source files', async () => {
    const { runtimeFindings } = await import('../../src/runtimeFindings');
    const own = runtimeFindings(profile, '/work/InvDemo/src/InvDemo.jl', 10);
    expect(own.map((f) => [f.ruleId, f.severity, f.range.start.line])).toEqual([['julia/runtime-invalidation', 'warning', 9]]);
    expect(own[0].message).toContain('InvDemo.==');
    const base = runtimeFindings(profile, '/opt/julia-1.13.1/share/julia/base/reduce.jl', 10);
    expect(base.map((f) => f.ruleId)).toEqual(['julia/runtime-inference-trigger']);
    expect(runtimeFindings(undefined, '/x.jl', 10)).toEqual([]);
  });
});
