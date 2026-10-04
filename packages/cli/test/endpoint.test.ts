import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../src/endpoint';
import { parseArgs, UsageError } from '../src/lib/args';
import { captureIo, REPO } from './io';

const FX = join(REPO, 'extensions/endpoint-security/test/fixtures');

describe('argument parsing', () => {
  const spec = {
    format: { type: 'string' as const, alias: 'f', description: '', default: 'text' },
    disable: { type: 'string' as const, multiple: true, description: '' },
    quiet: { type: 'boolean' as const, description: '' },
    max: { type: 'number' as const, description: '' },
  };

  it('handles aliases, =, repeats, commas, negation and --', () => {
    const r = parseArgs(['a', '-f', 'json', '--disable=x,y', '--disable', 'z', '--no-quiet', '--max', '3', '--', '--b'], spec);
    expect(r).toEqual({ positionals: ['a', '--b'], flags: { format: 'json', disable: ['x', 'y', 'z'], quiet: false, max: 3 } });
  });

  it('rejects unknown options and bad numbers', () => {
    expect(() => parseArgs(['--nope'], spec)).toThrow(UsageError);
    expect(() => parseArgs(['--max', 'x'], spec)).toThrow(/number/);
  });
});

describe('jest-endpoint', () => {
  it('prints help and version', async () => {
    const io = captureIo();
    expect(await main(['--help'], io)).toBe(0);
    expect(io.stdout()).toContain('simulate');
    expect(await main([], captureIo())).toBe(2);
    const v = captureIo();
    expect(await main(['--version'], v)).toBe(0);
    expect(v.stdout().trim()).toBe('dev');
    const bad = captureIo();
    expect(await main(['lint', '--format', 'xml'], bad)).toBe(2);
    expect(bad.stderr()).toContain('--format must be one of');
  });

  it('lints API misuse and fails on errors', async () => {
    const io = captureIo(FX);
    expect(await main(['lint', 'agent', '--only', 'api'], io)).toBe(1);
    expect(io.stdout()).toContain('agent/esf_client.c');
    expect(io.stdout()).toContain('edr/missing-cleanup');
    expect(io.stdout()).toMatch(/✖ \d+ problem/);
    // Disabling the error rules leaves only warnings → exit 0 with the default --fail-on error.
    const quiet = captureIo(FX);
    expect(await main(['lint', 'agent/esf_client.c', '--disable', 'edr/esf-auth-no-response', '--disable', 'edr/wfp-server-name,edr/etw-opentrace-check'], quiet)).toBe(0);
  });

  it('writes a SARIF compliance report', async () => {
    const out = join(mkdtempSync(join(tmpdir(), 'cli-')), 'r.sarif');
    const io = captureIo(FX);
    expect(await main(['compliance', 'backend', '--format', 'sarif', '--out', out], io)).toBe(1);
    const sarif = JSON.parse(readFileSync(out, 'utf8')) as { runs: { results: { ruleId: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
    const results = sarif.runs[0].results;
    expect(results.every((r) => /^(pci|ccsp)\//.test(r.ruleId))).toBe(true);
    expect(results.some((r) => r.locations[0].physicalLocation.artifactLocation.uri === 'backend/payments.go')).toBe(true);
  });

  it('simulates scenarios and checks expectations', async () => {
    const io = captureIo(FX);
    expect(await main(['simulate', 'scenarios/ransom.ptree.yaml', '--expect', 'mass-file-encryption,lsass-access'], io)).toBe(0);
    expect(io.stdout()).toContain('Detections (10)');
    expect(io.stdout()).toContain('└─ WINWORD.EXE (word)');
    const miss = captureIo(FX);
    expect(await main(['simulate', 'scenarios/ransom.ptree.yaml', '--no-default-rules', '--expect', 'lsass-access'], miss)).toBe(1);
    const json = captureIo(FX);
    await main(['simulate', 'scenarios/ransom.ptree.yaml', '--json'], json);
    expect((JSON.parse(json.stdout()) as { detections: unknown[] }).detections).toHaveLength(10);
  });

  it('looks up API documentation', async () => {
    const io = captureIo();
    expect(await main(['api', 'es_new_client'], io)).toBe(0);
    expect(io.stdout()).toContain('Release:   es_delete_client');
    const miss = captureIo();
    expect(await main(['api', 'FwpmEngine'], miss)).toBe(1);
    expect(miss.stderr()).toContain('FwpmEngineOpen0');
  });

  it('risk-scans an extensions folder', async () => {
    const io = captureIo(FX);
    expect(await main(['extensions', 'extensions'], io)).toBe(1);
    expect(io.stdout()).toMatch(/^HIGH /m);
    const json = captureIo(FX);
    await main(['extensions', 'extensions', '--format', 'json', '--fail-on', 'none'], json);
    const results = JSON.parse(json.stdout()) as { ext: { path: string }; risk: { level: string } }[];
    expect(results.find((r) => r.ext.path.endsWith('suspicious-ext'))?.risk.level).toBe('high');
    expect(results.find((r) => r.ext.path.endsWith('benign-lsp'))?.risk.level).toBe('low');
  });
});

describe('pci/pan-literal', () => {
  it('skips test PANs in unit-test files but reports them elsewhere', async () => {
    const io = captureIo(REPO);
    await main(['compliance', 'packages/core/test', 'extensions/endpoint-security/test/fixtures/backend/payments.go', '--format', 'json'], io);
    const files = (JSON.parse(io.stdout()) as { file: string; findings: { ruleId: string }[] }[]).filter((f) => f.findings.some((x) => x.ruleId === 'pci/pan-literal'));
    expect(files.map((f) => f.file)).toEqual(['extensions/endpoint-security/test/fixtures/backend/payments.go']);
  });
});
