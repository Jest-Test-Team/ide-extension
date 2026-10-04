import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../src/security';
import { captureIo, REPO } from './io';

const EXT = join(REPO, 'extensions/endpoint-security/test/fixtures/extensions');

describe('jest-security scan-extension', () => {
  it('discovers, scans and analyses extensions, and writes SARIF', async () => {
    const out = join(mkdtempSync(join(tmpdir(), 'cli-se-')), 'ext.sarif');
    const io = captureIo(REPO);
    expect(await main(['scan-extension', EXT, '--out', out], io)).toBe(1); // suspicious-ext is high
    const text = io.stdout();
    for (const section of ['== Discovered extension folders ==', '== Risk ranking ==', '== Analysis ==', 'What installed extensions can do', 'Recommendations', '== Summary ==']) {
      expect(text).toContain(section);
    }
    expect(text).toMatch(/: 3 extension\(s\)/);
    expect(text).toMatch(/^HIGH /m);
    expect(text).toMatch(/Data access \(credentials, clipboard, keystrokes\): [1-9]/);
    expect(text).toMatch(/Review .* \(high risk/);
    const sarif = JSON.parse(readFileSync(out, 'utf8')) as { runs: { results: { ruleId: string }[] }[] };
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].results.filter((r) => r.ruleId === 'ext/risk')).toHaveLength(3);
  });

  it('supports JSON with the analysis, the alias and --fail-on none', async () => {
    const io = captureIo(REPO);
    expect(await main(['scan-extensions', EXT, '--format', 'json', '--out', '-', '--fail-on', 'none'], io)).toBe(0);
    const json = JSON.parse(io.stdout()) as { folders: string[]; analysis: { total: number; levels: { high: number } }; results: unknown[] };
    expect(json.analysis.total).toBe(3);
    expect(json.analysis.levels.high).toBe(1);
    expect(json.results).toHaveLength(3);
  });

  it('explains when no extensions folder exists', async () => {
    const io = captureIo(REPO);
    expect(await main(['scan-extension', join(tmpdir(), 'definitely-missing-dir')], io)).toBe(2);
    expect(io.stderr()).toContain('no extensions folder found');
  });
});
