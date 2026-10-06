import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import JSZip from 'jszip';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractVsix, fetchPackage, pickGalleryVersion, resolvePackages, type ResolvedPackage } from '../src/ci/fetch';

const FIXTURE = join(__dirname, '../../../extensions/endpoint-security/test/fixtures/extensions/benign-lsp');

/** A VSIX built from the benign-lsp fixture, plus optional extra (hostile) entries. */
async function vsix(extra: (zip: JSZip) => void = () => {}): Promise<Buffer> {
  const zip = new JSZip();
  zip.file('extension.vsixmanifest', '<PackageManifest/>');
  zip.file('extension/package.json', readFileSync(join(FIXTURE, 'package.json')));
  zip.file('extension/out/extension.js', readFileSync(join(FIXTURE, 'out/extension.js')));
  extra(zip);
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', platform: 'UNIX' });
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const tmp = () => mkdtempSync(join(tmpdir(), 'jest-sec-fetch-'));

describe('VSIX extraction', () => {
  it('extracts only extension/ and finds package.json', async () => {
    const dest = join(tmp(), 'x');
    const res = await extractVsix(await vsix(), dest);
    expect(res.files).toBe(2);
    expect(readdirSync(dest).sort()).toEqual(['out', 'package.json']);
  });

  it('rejects zip-slip and absolute paths (yauzl validation or our own guard)', async () => {
    const UNSAFE = /unsafe path|invalid relative path|absolute path/;
    const slip = await vsix((z) => z.file('extension/../../evil.js', 'x'));
    const dest = join(tmp(), 'x');
    await expect(extractVsix(slip, dest)).rejects.toThrow(UNSAFE);
    expect(existsSync(join(dest, '..', '..', 'evil.js'))).toBe(false);
    const abs = await vsix((z) => z.file('/etc/evil', 'x'));
    await expect(extractVsix(abs, join(tmp(), 'x'))).rejects.toThrow(UNSAFE);
  });

  it('skips symlinks', async () => {
    const dest = join(tmp(), 'x');
    await extractVsix(await vsix((z) => z.file('extension/link', '/etc/passwd', { unixPermissions: 0o120777 })), dest);
    expect(existsSync(join(dest, 'link'))).toBe(false);
  });

  it('enforces entry and size limits', async () => {
    const data = await vsix((z) => z.file('extension/big.js', 'a'.repeat(5000)));
    await expect(extractVsix(data, join(tmp(), 'x'), { maxEntries: 2, maxBytes: 1e9 })).rejects.toThrow(/more than 2 entries/);
    await expect(extractVsix(data, join(tmp(), 'y'), { maxEntries: 100, maxBytes: 4000 })).rejects.toThrow(/extracted size exceeds/);
  });

  it('requires an extension package.json', async () => {
    const zip = new JSZip();
    zip.file('extension/readme.md', 'hi');
    await expect(extractVsix(await zip.generateAsync({ type: 'nodebuffer' }), join(tmp(), 'x'))).rejects.toThrow(/no extension\/package.json/);
  });
});

describe('download, verify and cache', () => {
  let server: Server;
  let base = '';
  let good: Buffer;
  let hits = 0;
  beforeAll(async () => {
    good = await vsix();
    server = createServer((req, res) => {
      hits++;
      if (req.url === '/good.vsix') {
        res.writeHead(200, { 'Content-Type': 'application/vsix' }).end(good);
      } else {
        res.writeHead(404).end();
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => server.close());

  const pkg = (over: Partial<ResolvedPackage> = {}): ResolvedPackage => ({
    id: 'example.benign-lsp',
    version: '2.3.4',
    targetPlatform: 'universal',
    url: `${base}/good.vsix`,
    registry: 'marketplace',
    preRelease: false,
    ...over,
  });

  it('downloads, checks the published hash, extracts, then serves from cache', async () => {
    const cache = tmp();
    const first = await fetchPackage(pkg({ sha256: sha(good) }), cache);
    expect(first).toMatchObject({ cached: false, verified: true, sha256: sha(good) });
    expect(JSON.parse(readFileSync(join(first.dir, 'package.json'), 'utf8')).name).toBe('benign-lsp');
    const before = hits;
    const second = await fetchPackage(pkg({ sha256: sha(good) }), cache);
    expect(second).toMatchObject({ cached: true, verified: true, dir: first.dir });
    expect(hits).toBe(before);
    rmSync(cache, { recursive: true, force: true });
  });

  it('refuses a hash mismatch and leaves no cache entry', async () => {
    const cache = tmp();
    await expect(fetchPackage(pkg({ sha256: '0'.repeat(64) }), cache)).rejects.toThrow(/SHA-256 mismatch/);
    expect(readdirSync(cache)).toEqual([]);
  });

  it('enforces the download size cap and reports HTTP errors', async () => {
    await expect(fetchPackage(pkg(), tmp(), { maxBytes: 100 })).rejects.toThrow(/limit/);
    await expect(fetchPackage(pkg({ url: `${base}/missing.vsix` }), tmp())).rejects.toThrow(/HTTP 404/);
  });

  it('unpublished hash: still extracted, verified undefined', async () => {
    expect((await fetchPackage(pkg(), tmp())).verified).toBeUndefined();
  });
});

describe('resolving versions', () => {
  const v = (version: string, targetPlatform?: string, pre = false) => ({
    version,
    targetPlatform,
    assetUri: `https://cdn.example/${version}/${targetPlatform ?? 'u'}`,
    properties: [
      ...(pre ? [{ key: 'Microsoft.VisualStudio.Code.PreRelease', value: 'true' }] : []),
      { key: 'Microsoft.VisualStudio.Services.VsixSha256', value: `sha-${version}-${targetPlatform ?? 'u'}` },
    ],
  });

  it('picks the newest stable build for the platform, universal first', () => {
    const versions = [v('2.0.0', 'darwin-arm64'), v('2.0.0', 'linux-x64'), v('1.9.0-pre', undefined, true), v('1.8.0')];
    expect(pickGalleryVersion(versions, 'linux-x64')).toMatchObject({ version: '2.0.0', targetPlatform: 'linux-x64' });
    expect(pickGalleryVersion(versions, 'win32-x64')).toMatchObject({ version: '1.8.0' });
    expect(pickGalleryVersion(versions, 'linux-x64', '1.9.0-pre')).toMatchObject({ version: '1.9.0-pre' });
    expect(pickGalleryVersion([v('3.0.0', 'linux-x64'), v('3.0.0')], 'linux-x64')?.targetPlatform).toBeUndefined();
  });

  it('resolves through the gallery (latest, pre-release fallback, not found)', async () => {
    const bodies: { flags: number; ids: string[] }[] = [];
    const gallery = (async (_url: string, init: { body: string }) => {
      const body = JSON.parse(init.body) as { flags: number; filters: { criteria: { filterType: number; value: string }[] }[] };
      const ids = body.filters[0].criteria.filter((c) => c.filterType === 7).map((c) => c.value);
      bodies.push({ flags: body.flags, ids });
      const all = body.flags === 403;
      const exts = [
        { extensionName: 'stable', publisher: { publisherName: 'Pub' }, versions: [v('1.2.3')] },
        { extensionName: 'preonly', publisher: { publisherName: 'pub' }, versions: all ? [v('2.0.0', undefined, true), v('1.0.0')] : [v('2.0.0', undefined, true)] },
      ].filter((e) => ids.includes(`pub.${e.extensionName}`));
      return new Response(JSON.stringify({ results: [{ extensions: exts }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const res = await resolvePackages([{ id: 'Pub.Stable' }, { id: 'pub.preonly' }, { id: 'gone.away' }, { id: 'pub.preonly', version: '2.0.0' }], { fetch: gallery });
    expect(res.get('pub.preonly@2.0.0')).toMatchObject({ status: 'found', pkg: { version: '2.0.0', preRelease: true } });
    expect(res.get('pub.stable')).toMatchObject({ status: 'found', pkg: { version: '1.2.3', sha256: 'sha-1.2.3-u', url: 'https://cdn.example/1.2.3/u/Microsoft.VisualStudio.Services.VSIXPackage' } });
    expect(res.get('pub.preonly')).toMatchObject({ status: 'found', pkg: { version: '1.0.0', preRelease: false } });
    expect(res.get('gone.away')).toMatchObject({ status: 'not-found' });
    expect(bodies.map((b) => b.flags)).toEqual([915, 403]);
  });

  it('turns registry outages into per-extension errors', async () => {
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    expect((await resolvePackages([{ id: 'a.b' }], { fetch: down })).get('a.b')).toEqual({ status: 'error', reason: 'Marketplace query failed: HTTP 503' });
  });

  it('resolves through Open VSX, following the platform build', async () => {
    const calls: string[] = [];
    const ovsx = (async (url: string) => {
      calls.push(url.replace('https://open-vsx.org', ''));
      if (url.endsWith('/api/pub/native')) {
        return new Response(JSON.stringify({ version: '1.0.0', targetPlatform: 'darwin-arm64', files: { download: 'x' } }));
      }
      if (url.endsWith('/api/pub/native/linux-x64/latest')) {
        return new Response(JSON.stringify({ version: '1.0.0', targetPlatform: 'linux-x64', files: { download: 'https://dl/native.vsix', sha256: 'https://dl/native.sha256' } }));
      }
      if (url === 'https://dl/native.sha256') {
        return new Response('ABCDEF  native.vsix\n');
      }
      return new Response('', { status: 404 });
    }) as unknown as typeof fetch;
    const res = await resolvePackages([{ id: 'pub.native' }, { id: 'pub.none' }], { registry: 'open-vsx', fetch: ovsx });
    expect(res.get('pub.native')).toMatchObject({ status: 'found', pkg: { targetPlatform: 'linux-x64', url: 'https://dl/native.vsix', sha256: 'abcdef', registry: 'open-vsx' } });
    expect(res.get('pub.none')).toMatchObject({ status: 'not-found', reason: 'not on Open VSX' });
  });
});
