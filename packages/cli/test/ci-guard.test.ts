import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import JSZip from 'jszip';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parsePolicy, evaluatePolicy } from '../src/ci/policy';
import { main } from '../src/security';
import { captureIo } from './io';

const FIXTURES = join(__dirname, '../../../extensions/endpoint-security/test/fixtures/extensions');
const MALWARE = (JSON.parse(readFileSync(join(__dirname, '../../../extensions/endpoint-security/data/extscan/removed-packages.json'), 'utf8')) as { entries: string[][] }).entries.find(
  (e) => e[2] === 'Malware',
)![0];

/** VSIX of a fixture folder (every file under extension/). */
async function vsixOf(folder: string): Promise<Buffer> {
  const zip = new JSZip();
  zip.file('extension.vsixmanifest', '<PackageManifest/>');
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        walk(p);
      } else {
        zip.file(`extension/${relative(folder, p).replace(/\\/g, '/')}`, readFileSync(p));
      }
    }
  };
  walk(folder);
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

/** A fake VS Marketplace: gallery query + VSIX downloads for two fixture extensions. */
class FakeRegistry {
  server!: Server;
  url = '';
  galleryDown = false;
  packages = new Map<string, { publisher: string; name: string; version: string; data: Buffer }>();
  downloads: string[] = [];

  async start() {
    for (const [folder, version] of [
      ['benign-lsp', '2.3.4'],
      ['suspicious-ext', '1.0.0'],
    ]) {
      const pkg = JSON.parse(readFileSync(join(FIXTURES, folder, 'package.json'), 'utf8')) as { publisher: string; name: string };
      this.packages.set(`${pkg.publisher}.${pkg.name}`, { publisher: pkg.publisher, name: pkg.name, version, data: await vsixOf(join(FIXTURES, folder)) });
    }
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        if (req.url?.startsWith('/_apis/public/gallery/extensionquery')) {
          if (this.galleryDown) {
            res.writeHead(503).end();
            return;
          }
          const ids = (JSON.parse(body) as { filters: { criteria: { filterType: number; value: string }[] }[] }).filters[0].criteria.filter((c) => c.filterType === 7).map((c) => c.value);
          const extensions = ids
            .map((id) => this.packages.get(id))
            .filter((p) => !!p)
            .map((p) => ({
              extensionName: p!.name,
              publisher: { publisherName: p!.publisher },
              versions: [
                {
                  version: p!.version,
                  assetUri: `${this.url}/assets/${p!.publisher}.${p!.name}`,
                  properties: [{ key: 'Microsoft.VisualStudio.Services.VsixSha256', value: createHash('sha256').update(p!.data).digest('hex') }],
                },
              ],
            }));
          res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ results: [{ extensions }] }));
          return;
        }
        const m = /^\/assets\/([^/]+)\/Microsoft\.VisualStudio\.Services\.VSIXPackage$/.exec(req.url ?? '');
        const p = m && this.packages.get(m[1]);
        if (p) {
          this.downloads.push(m![1]);
          res.writeHead(200).end(p.data);
          return;
        }
        res.writeHead(404).end();
      });
    });
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }
}

describe('scan-manifest (CI extension guard)', () => {
  const registry = new FakeRegistry();
  const repo = mkdtempSync(join(tmpdir(), 'jest-sec-guard-'));
  const cache = mkdtempSync(join(tmpdir(), 'jest-sec-guard-cache-'));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
  const write = (p: string, text: string) => {
    mkdirSync(dirname(join(repo, p)), { recursive: true });
    writeFileSync(join(repo, p), text);
  };
  let base = '';

  beforeAll(async () => {
    await registry.start();
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    write('.vscode/extensions.json', '{\n  "recommendations": [\n    "example.benign-lsp"\n  ]\n}\n');
    git('add', '.');
    git('commit', '-q', '-m', 'base');
    base = git('rev-parse', 'HEAD');
    write(
      '.vscode/extensions.json',
      ['{', '  // added in this branch', '  "recommendations": [', '    "example.benign-lsp",', '    "helpful-dev.theme-helper",', `    "${MALWARE}",`, '    "ms-pythom.python"', '  ]', '}', ''].join('\n'),
    );
    git('commit', '-q', '-am', 'head');
  });
  afterAll(() => {
    registry.server.close();
    rmSync(repo, { recursive: true, force: true });
    rmSync(cache, { recursive: true, force: true });
  });

  const run = async (...args: string[]) => {
    const io = captureIo(repo);
    const code = await main(['scan-manifest', '--registry-url', registry.url, '--cache-dir', cache, '--no-online', '--no-annotations', ...args], io);
    return { code, out: io.stdout(), err: io.stderr() };
  };

  it('scans only what the branch adds and blocks malware, look-alikes and risky code', async () => {
    const { code, out } = await run('--base', base, '--format', 'json', '--out', '-');
    const json = JSON.parse(out) as { exitCode: number; changes: { id: string; status: string }[]; items: { id: string; status: string; level: string; failing: boolean; signals: { id: string }[]; package?: { verified: boolean } }[] };
    expect(code).toBe(1);
    expect(json.changes.map((c) => `${c.status}:${c.id}`)).toEqual([`added:helpful-dev.theme-helper`, `added:${MALWARE}`, 'added:ms-pythom.python', 'unchanged:example.benign-lsp']);
    const byId = Object.fromEntries(json.items.map((i) => [i.id, i]));
    expect(Object.keys(byId)).not.toContain('example.benign-lsp');
    // Downloaded, hash-verified and scanned with the full scanner.
    expect(byId['helpful-dev.theme-helper']).toMatchObject({ status: 'scanned', level: 'high', failing: true, package: { verified: true } });
    expect(byId['helpful-dev.theme-helper'].signals.map((s) => s.id)).toEqual(expect.arrayContaining(['ext/exfil-endpoint', 'ext/obfuscated']));
    // Taken down: judged by id — the known-bad list forces high.
    expect(byId[MALWARE]).toMatchObject({ status: 'id-only', level: 'high', failing: true });
    expect(byId[MALWARE].signals.map((s) => s.id)).toContain('ext/known-bad');
    // Look-alike that is not published: flagged, but medium does not fail at the default level.
    expect(byId['ms-pythom.python']).toMatchObject({ status: 'id-only', level: 'medium', failing: false });
    expect(byId['ms-pythom.python'].signals.map((s) => s.id)).toEqual(expect.arrayContaining(['ext/typosquat', 'ext/not-on-marketplace']));
    expect(registry.downloads).toEqual(['helpful-dev.theme-helper']);
  });

  it('SARIF points every result at the manifest line that adds the extension', async () => {
    const { code } = await run('--base', base, '--out', 'guard.sarif');
    expect(code).toBe(1);
    const sarif = JSON.parse(readFileSync(join(repo, 'guard.sarif'), 'utf8')) as {
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; level: string; message: { text: string }; locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[] }[] }[];
    };
    const results = sarif.runs[0].results;
    const risk = results.filter((r) => r.ruleId === 'ext/risk').map((r) => `${r.locations[0].physicalLocation.artifactLocation.uri}:${r.locations[0].physicalLocation.region.startLine}:${r.level}`);
    expect(risk).toEqual(['.vscode/extensions.json:5:error', '.vscode/extensions.json:6:error', '.vscode/extensions.json:7:warning']);
    expect(results.find((r) => r.ruleId === 'ext/exfil-endpoint')?.message.text).toMatch(/in out\/extension\.js:10/);
    const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((r) => r.id));
    expect(results.every((r) => ruleIds.has(r.ruleId))).toBe(true);
  });

  it('writes the job summary / PR comment markdown and GitHub annotations', async () => {
    const summary = join(repo, 'summary.md');
    const { out } = await run('--base', base, '--format', 'text', '--summary', summary, '--annotations');
    const md = readFileSync(summary, 'utf8');
    expect(md.startsWith('<!-- jest-security-extension-guard -->')).toBe(true);
    expect(md).toContain('❌ **2 extension(s) blocked**');
    expect(md).toMatch(/\| 🔴 \| \[`helpful-dev\.theme-helper`\]\(https:\/\/marketplace\.visualstudio\.com\/items\?itemName=helpful-dev\.theme-helper\) \| 1\.0\.0 \| added · `\.vscode\/extensions\.json:5` \| high/);
    expect(md).toContain('<details><summary><b>ms-pythom.python</b>');
    expect(out).toContain('::error file=.vscode/extensions.json,line=5,title=helpful-dev.theme-helper%3A high risk');
    expect(out).toContain('::warning file=.vscode/extensions.json,line=7');
    expect(out).toContain('Result: blocked');
  });

  it('nothing changed → nothing scanned, exit 0', async () => {
    const { code, out } = await run('--base', 'HEAD', '--format', 'text');
    expect(code).toBe(0);
    expect(out).toContain('nothing to scan');
  });

  it('policy file: blocked publisher fails an otherwise low-risk extension; cache is reused', async () => {
    write('.github/jest-security.yml', 'fail-on: high\nblocked:\n  - example.*\n');
    try {
      const before = registry.downloads.length;
      const { code, out } = await run('--format', 'json', '--out', '-');
      const items = (JSON.parse(out) as { items: { id: string; level: string; failing: boolean; violations: { rule: string }[] }[] }).items;
      expect(code).toBe(1);
      expect(items.find((i) => i.id === 'example.benign-lsp')).toMatchObject({ level: 'low', failing: true, violations: [{ rule: 'policy/blocked' }] });
      expect(registry.downloads.slice(before)).toEqual(['example.benign-lsp']); // theme-helper came from the cache
    } finally {
      rmSync(join(repo, '.github'), { recursive: true });
    }
  });

  it('registry outage → exit 2 (incomplete), but known-bad ids still fail', async () => {
    registry.galleryDown = true;
    try {
      const { code, out } = await run('--base', base, '--format', 'json', '--out', '-', '--fail-on', 'none');
      const items = (JSON.parse(out) as { items: { id: string; status: string; level: string }[] }).items;
      expect(code).toBe(2);
      expect(items.every((i) => i.status === 'unscanned')).toBe(true);
      expect(items.find((i) => i.id === MALWARE)?.level).toBe('high');
      expect((await run('--base', base, '--format', 'json', '--out', '-')).code).toBe(1);
    } finally {
      registry.galleryDown = false;
    }
  });

  it('rejects bad options', async () => {
    expect((await run('--registry', 'npm')).code).toBe(2);
    expect((await run('--policy', 'missing.yml')).err).toMatch(/policy file not found/);
    expect((await run('--base', 'no-such-ref')).err).toMatch(/fetch-depth: 0/);
  });
});

describe('policy file', () => {
  it('parses and validates', () => {
    expect(parsePolicy('fail-on: medium\nallowlist: [Foo.Bar@1.0.0]\nallowed-publishers: [ms-python]\nrequire-verified-publisher: true\n')).toMatchObject({
      failOn: 'medium',
      allowlist: ['foo.bar@1.0.0'],
      allowedPublishers: ['ms-python'],
      requireVerifiedPublisher: true,
    });
    expect(() => parsePolicy('fail_on: high')).toThrow(/unknown key\(s\) fail_on/);
    expect(() => parsePolicy('fail-on: low')).toThrow(/high, medium or none/);
    expect(() => parsePolicy('blocked: evil.ext')).toThrow(/list of strings/);
  });

  it('evaluates blocked ids / publishers, allowed publishers and verification', () => {
    const p = parsePolicy('blocked: [evil.*, bad.one]\nallowed-publishers: [good, evil]\nrequire-verified-publisher: true\n');
    expect(evaluatePolicy('Evil.Thing', p, true).map((v) => v.rule)).toEqual(['policy/blocked']);
    expect(evaluatePolicy('other.thing', p, false).map((v) => v.rule)).toEqual(['policy/publisher-not-allowed', 'policy/unverified-publisher']);
    expect(evaluatePolicy('good.thing', p, undefined)[0].message).toMatch(/could not be confirmed/);
    expect(evaluatePolicy('good.thing', p, true)).toEqual([]);
  });
});
