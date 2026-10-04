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
    await main(['scan', 'extensions/endpoint-security/test/fixtures/backend', '--out', join(dir, 'out.sarif')], io);
    const sarif = JSON.parse(readFileSync(join(dir, 'out.sarif'), 'utf8')) as { runs: { tool: { driver: { name: string } }; results: unknown[] }[] };
    expect(sarif.runs[0].tool.driver.name).toBe('jest-security');
    expect(sarif.runs[0].results.length).toBeGreaterThan(5);
  });

  it('runs doctor', async () => {
    const io = captureIo();
    expect(await main(['doctor'], io)).toBe(0);
    expect(io.stdout()).toContain('✔ grammars');
    expect(io.stdout()).toContain('✔ scripts');
  });
});
