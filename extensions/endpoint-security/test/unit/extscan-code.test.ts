import { publicIpv4, RuleEngine } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { shannonEntropy } from '../../src/extscan/codeRules';
import { loadCodeRules, scanExtensionCode, type CodeScanOptions } from '../../src/extscan/codeScan';
import { loadManifestOptions } from '../../src/extscan/data';
import { manifestSignals } from '../../src/extscan/manifest';
import { reportFindings, toExtensionMarkdown, toExtensionSarif } from '../../src/extscan/report';
import { scoreExtension } from '../../src/extscan/score';

const data = join(__dirname, '../../data/extscan');
const engine = new RuleEngine(testHost(), loadCodeRules(data).rules);
const manifestOpts = loadManifestOptions(data);
const OPTS: CodeScanOptions = { includeNodeModules: true, maxFileSizeMB: 10, maxFiles: 100 };

async function scan(name: string, opts = OPTS) {
  const dir = join(__dirname, '../fixtures/extensions', name);
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>;
  const code = await scanExtensionCode(engine, testHost(), dir, pkg, opts);
  const id = `${pkg.publisher as string}.${pkg.name as string}`;
  const manifest = manifestSignals({ id, version: pkg.version as string, path: dir, packageJSON: pkg, builtin: false, source: 'gallery' }, manifestOpts);
  const score = scoreExtension([...manifest, ...code.signals]);
  return { code, score, result: { ext: { id, version: pkg.version as string, path: dir, builtin: false }, risk: score } };
}

/** `signal` → sorted `file:line rule-variant` strings. */
function hits(signals: { id: string; locations: { file: string; finding: { ruleId: string; range: { start: { line: number } } } }[] }[]) {
  const out: Record<string, string[]> = {};
  for (const s of signals) {
    out[s.id] = s.locations.map((l) => `${l.file.split(/[\\/]/).pop()}:${l.finding.range.start.line + 1} ${l.finding.ruleId.split('.')[1] ?? ''}`.trim()).sort();
  }
  return out;
}

describe('extension code scan', () => {
  it('rules load and carry a stable version', () => {
    const a = loadCodeRules(data);
    expect(a.rules.length).toBeGreaterThan(8);
    expect(a.version).toMatch(/^[0-9a-f]{12}$/);
    expect(loadCodeRules(data).version).toBe(a.version);
  });

  it('credential-stealer shaped fixture scores high with the exfiltration combination', async () => {
    const { code, score } = await scan('suspicious-ext');
    expect(code.filesScanned).toBe(2);
    expect(hits(code.signals)).toEqual({
      'ext/process-exec': ['extension.js:3 child-process'],
      'ext/credential-path': ['extension.js:8 files', 'extension.js:9 files'],
      'ext/exfil-endpoint': ['extension.js:10 service'],
      'ext/hardcoded-ip': ['extension.js:11 url'],
      'ext/input-capture': ['extension.js:12 clipboard-keys'],
      'ext/dynamic-code': ['extension.js:15 eval', 'payload.js:7 eval'],
      'ext/obfuscated': ['payload.js:2 obfuscator', 'payload.js:7 packed-payload'],
      'ext/native-binary': ['helper.node:1'],
    });
    expect(score.level).toBe('high');
    expect(score.boosts.map((b) => b.because[0])).toEqual(['ext/credential-path', 'ext/obfuscated', 'ext/activates-on-startup']);
  });

  it('ordinary language-server client stays low', async () => {
    const { code, score } = await scan('benign-lsp');
    expect(hits(code.signals)).toEqual({
      'ext/process-exec': ['extension.js:3 child-process'],
      'ext/dynamic-code': ['extension.js:8 require', 'extension.js:9 eval'],
      'ext/native-binary': ['native.node:1'],
    });
    expect(score).toMatchObject({ level: 'low', score: 3 });
  });

  it('typosquat fixture is flagged by its manifest alone', async () => {
    const { code, score } = await scan('typosquat-ext');
    expect(code.signals).toEqual([]);
    expect(score.signals.map((s) => s.id)).toContain('ext/typosquat');
    expect(score.level).toBe('medium');
  });

  it('respects the file budget and size limit', async () => {
    const budget = await scan('suspicious-ext', { ...OPTS, maxFiles: 1 });
    expect(budget.code.filesScanned).toBe(1);
    expect(budget.code.signals.find((s) => s.id === 'ext/scan-incomplete')?.message).toMatch(/1 file\(s\) beyond the 1-file budget/);
    const size = await scan('suspicious-ext', { ...OPTS, maxFileSizeMB: 0.0001 });
    expect(size.code.filesScanned).toBe(0);
    expect(size.code.signals.map((s) => s.id)).toEqual(['ext/native-binary', 'ext/scan-incomplete']);
  });

  it('public IPv4 validator skips private ranges, OIDs and versions', () => {
    expect(publicIpv4('45.13.22.7')).toBe(true);
    for (const v of ['10.0.0.1', '192.168.1.10', '172.20.1.1', '127.0.0.1', '169.254.169.254', '100.100.100.200', '2.5.4.3', '1.3.6.1', '4.0.1.3', '6.0.0.0', '8.8.8.8', '203.0.113.5', '300.1.1.1']) {
      expect(publicIpv4(v), v).toBe(false);
    }
  });

  it('entropy of random base64 exceeds the payload threshold; text does not', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('the quick brown fox jumps over the lazy dog')).toBeLessThan(4.5);
    expect(shannonEntropy(Buffer.from(Array.from({ length: 600 }, (_, i) => (i * 7919 + 13) % 251)).toString('base64'))).toBeGreaterThan(5.2);
  });

  it('exports findings relative to the extensions folder with one ext/risk result per extension', async () => {
    const { result } = await scan('suspicious-ext');
    const findings = reportFindings([result]);
    expect([...findings.keys()].sort()).toEqual(['suspicious-ext/bin/helper.node', 'suspicious-ext/out/extension.js', 'suspicious-ext/out/payload.js', 'suspicious-ext/package.json']);
    const risk = findings.get('suspicious-ext/package.json')!.find((f) => f.ruleId === 'ext/risk')!;
    expect(risk).toMatchObject({ severity: 'error' });
    expect(risk.message).toMatch(/^helpful-dev\.theme-helper@1\.0\.0: high risk/);
    const sarif = toExtensionSarif([result], loadCodeRules(data).rules, '0.0.0') as { runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string }[] }[] };
    const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((r) => r.id));
    expect(sarif.runs[0].results.every((r) => ruleIds.has(r.ruleId))).toBe(true);
    const md = toExtensionMarkdown([result], loadCodeRules(data).rules);
    expect(md).toMatch(/\| Theme Helper|\| helpful-dev\.theme-helper/);
    expect(md).toContain('## Findings');
    expect(md).not.toContain('ext/risk');
  });
});
