import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../src/security';
import { captureIo, REPO } from './io';

describe('jest-security', () => {
  it('delegates to the individual tools', async () => {
    const io = captureIo();
    expect(await main(['hw', 'puf', 'extensions/hw-security/test/fixtures/puf/sram.csv'], io)).toBe(0);
    expect(io.stdout()).toContain('PUF quality');
    const help = captureIo();
    expect(await main(['endpoint', '--help'], help)).toBe(0);
    expect(help.stdout()).toContain('Usage: jest-security endpoint <command>');
  });

  it('lints with every rule set at once', async () => {
    const io = captureIo();
    const code = await main(
      ['lint', 'extensions/endpoint-security/test/fixtures/agent', 'extensions/hw-security/test/fixtures/esp-app', 'extensions/julia-profiler/test/fixtures/InvDemo', '--format', 'json'],
      io,
    );
    expect(code).toBe(1);
    const ids = new Set((JSON.parse(io.stdout()) as { findings: { ruleId: string }[] }[]).flatMap((f) => f.findings.map((x) => x.ruleId)));
    expect(ids.has('edr/missing-cleanup')).toBe(true);
    expect(ids.has('esp32/secure-boot-disabled')).toBe(true);
    expect(ids.has('julia/abstract-field')).toBe(true);
  });

  it('writes SARIF by default for scan', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cli-sec-'));
    const io = captureIo(REPO);
    await main(['scan', 'extensions/endpoint-security/test/fixtures/backend', '--no-extensions', '--out', join(dir, 'out.sarif')], io);
    const sarif = JSON.parse(readFileSync(join(dir, 'out.sarif'), 'utf8')) as { runs: { tool: { driver: { name: string } }; results: unknown[] }[] };
    expect(sarif.runs[0].tool.driver.name).toBe('jest-security');
    expect(sarif.runs[0].results.length).toBeGreaterThan(5);
  });

  it('runs doctor', async () => {
    const io = captureIo();
    expect(await main(['doctor'], io)).toBe(0);
    expect(io.stdout()).toContain('✔ grammars');
    expect(io.stdout()).toContain('✔ scripts');
  }, 30000);
});

describe('jest-security scan (full audit)', () => {
  const EXT = join(REPO, 'extensions/endpoint-security/test/fixtures/extensions');

  it('reports code findings and installed-extension risk, and writes both into one SARIF', async () => {
    const out = join(mkdtempSync(join(tmpdir(), 'cli-scan-')), 'audit.sarif');
    const io = captureIo(REPO);
    const code = await main(['scan', 'extensions/endpoint-security/test/fixtures/backend', '--extension-dir', EXT, '--out', out], io);
    expect(code).toBe(1); // code errors and a high-risk extension
    const text = io.stdout();
    expect(text).toContain('== Code: extensions/endpoint-security/test/fixtures/backend ==');
    expect(text).toContain('pci/tls-verification-disabled');
    expect(text).toContain('== Installed extensions: risk ranking and benchmark ==');
    expect(text).toMatch(/^HIGH /m);
    expect(text).toContain('Signal benchmark');
    expect(text).toMatch(/Extensions: 1 high, \d+ medium, \d+ low risk \(3 scanned\)/);
    const sarif = JSON.parse(readFileSync(out, 'utf8')) as { runs: { tool: { driver: { name: string } }; results: { ruleId: string; level: string }[] }[] };
    expect(sarif.runs.map((r) => r.tool.driver.name)).toEqual(['jest-security', 'Endpoint Security & Compliance Toolkit — Extension Scan']);
    expect(sarif.runs[1].results.some((r) => r.ruleId === 'ext/risk' && r.level === 'error')).toBe(true);
  });

  it('can skip the extension scan and print the file format to stdout', async () => {
    const io = captureIo(REPO);
    expect(await main(['scan', 'extensions/endpoint-security/test/fixtures/backend', '--no-extensions', '--format', 'json', '--out', '-'], io)).toBe(1);
    const json = JSON.parse(io.stdout()) as { code: unknown[]; extensions: unknown[] };
    expect(json.code.length).toBeGreaterThan(0);
    expect(json.extensions).toEqual([]);
  });
});
