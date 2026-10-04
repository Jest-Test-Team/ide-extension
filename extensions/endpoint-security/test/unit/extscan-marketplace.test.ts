import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { GALLERY_URL, galleryQuery, lookupMarketplace, marketplaceSignals, parseGalleryResponse } from '../../src/extscan/marketplace';
import { scoreExtension } from '../../src/extscan/score';

const recorded = JSON.parse(readFileSync(join(__dirname, '../fixtures/marketplace/response.json'), 'utf8')) as unknown;
const IDS = ['ms-python.python', 'WakaTime.vscode-wakatime', 'nobody-here.does-not-exist'];
const ids = (s: { id: string }[]) => s.map((x) => x.id);

describe('Marketplace lookup (recorded response, no network)', () => {
  it('builds a name query restricted to VS Code', () => {
    expect(galleryQuery(['a.b'])).toEqual({
      filters: [{ criteria: [{ filterType: 7, value: 'a.b' }, { filterType: 8, value: 'Microsoft.VisualStudio.Code' }], pageNumber: 1, pageSize: 1 }],
      flags: 914,
    });
  });

  it('parses publisher verification, installs and missing extensions (case-insensitive ids)', () => {
    const infos = parseGalleryResponse(recorded, IDS);
    expect(infos.get('ms-python.python')).toMatchObject({ found: true, verified: true, publisherDisplayName: 'Microsoft' });
    expect(infos.get('ms-python.python')!.installs).toBeGreaterThan(1e8);
    expect(infos.get('wakatime.vscode-wakatime')).toMatchObject({ found: true, verified: true });
    expect(infos.get('nobody-here.does-not-exist')).toEqual({ id: 'nobody-here.does-not-exist', found: false });
  });

  it('turns lookups into signals', () => {
    const now = Date.parse('2026-10-04T00:00:00Z');
    expect(ids(marketplaceSignals({ id: 'a.b', found: false }, now))).toEqual(['ext/not-on-marketplace']);
    expect(ids(marketplaceSignals({ id: 'a.b', found: true, verified: true, installs: 5e6, lastUpdated: '2026-01-01T00:00:00Z' }, now))).toEqual(['ext/verified-publisher']);
    expect(ids(marketplaceSignals({ id: 'a.b', found: true, verified: false, installs: 12, lastUpdated: '2023-01-01T00:00:00Z' }, now))).toEqual([
      'ext/unverified-publisher',
      'ext/low-installs',
      'ext/stale',
    ]);
    // Not being listed is a signal on its own, but stays low without anything else.
    expect(scoreExtension(marketplaceSignals({ id: 'a.b', found: false }, now)).score).toBe(3);
  });

  it('batches requests through the injected fetch', async () => {
    const calls: { url: string; body: { filters: { criteria: { value: string }[] }[] } }[] = [];
    const fakeFetch = (async (url: string, init: { body: string }) => {
      calls.push({ url, body: JSON.parse(init.body) });
      return new Response(JSON.stringify(recorded), { status: 200 });
    }) as unknown as typeof fetch;
    const many = [...IDS, ...Array.from({ length: 60 }, (_, i) => `pub.ext${i}`)];
    const infos = await lookupMarketplace(many, { fetch: fakeFetch });
    expect(calls).toHaveLength(2);
    expect(calls.every((c) => c.url === GALLERY_URL)).toBe(true);
    expect(calls[0].body.filters[0].criteria).toHaveLength(51);
    expect(infos.size).toBe(many.length);
    expect(infos.get('pub.ext59')).toMatchObject({ found: false });
  });

  it('surfaces HTTP errors', async () => {
    const failing = (async () => new Response('busy', { status: 503 })) as unknown as typeof fetch;
    await expect(lookupMarketplace(['a.b'], { fetch: failing })).rejects.toThrow(/HTTP 503/);
  });
});
