import { signal, type Signal } from './signals';

export const GALLERY_URL = 'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery';
const BATCH = 50;
/** IncludeFiles | IncludeVersionProperties | IncludeAssetUri | IncludeStatistics | IncludeLatestVersionOnly. */
const FLAGS = 914;
const LOW_INSTALLS = 1000;
const STALE_MS = 2 * 365 * 24 * 3600 * 1000;

export interface GalleryInfo {
  id: string;
  found: boolean;
  verified?: boolean;
  installs?: number;
  lastUpdated?: string;
  publisherDisplayName?: string;
}

interface GalleryExtension {
  extensionName: string;
  lastUpdated?: string;
  publisher: { publisherName: string; displayName?: string; flags?: string; isDomainVerified?: boolean };
  statistics?: { statisticName: string; value: number }[];
}

/** Request body for one batch: `filterType 7` = extension name, `8` = target (VS Code). */
export function galleryQuery(ids: readonly string[]): object {
  return {
    filters: [
      {
        criteria: [...ids.map((value) => ({ filterType: 7, value })), { filterType: 8, value: 'Microsoft.VisualStudio.Code' }],
        pageNumber: 1,
        pageSize: ids.length,
      },
    ],
    flags: FLAGS,
  };
}

export function parseGalleryResponse(json: unknown, ids: readonly string[]): Map<string, GalleryInfo> {
  const out = new Map<string, GalleryInfo>(ids.map((id) => [id.toLowerCase(), { id: id.toLowerCase(), found: false }]));
  const exts = ((json as { results?: { extensions?: GalleryExtension[] }[] })?.results?.[0]?.extensions ?? []) as GalleryExtension[];
  for (const e of exts) {
    const id = `${e.publisher.publisherName}.${e.extensionName}`.toLowerCase();
    if (!out.has(id)) {
      continue;
    }
    out.set(id, {
      id,
      found: true,
      verified: e.publisher.isDomainVerified === true || /\bverified\b/.test(e.publisher.flags ?? ''),
      installs: e.statistics?.find((s) => s.statisticName === 'install')?.value,
      lastUpdated: e.lastUpdated,
      publisherDisplayName: e.publisher.displayName,
    });
  }
  return out;
}

export function marketplaceSignals(info: GalleryInfo, now = Date.now()): Signal[] {
  if (!info.found) {
    return [signal('ext/not-on-marketplace', `\`${info.id}\` is not listed on the VS Marketplace (sideloaded, renamed or taken down).`)];
  }
  const out: Signal[] = [];
  const who = info.publisherDisplayName ? `Publisher ${info.publisherDisplayName}` : 'The publisher';
  if (info.verified) {
    out.push(signal('ext/verified-publisher', `${who} has a verified domain on the Marketplace.`));
  } else {
    out.push(signal('ext/unverified-publisher', `${who} has no verified domain on the Marketplace.`));
  }
  if (info.installs !== undefined && info.installs < LOW_INSTALLS) {
    out.push(signal('ext/low-installs', `Only ${Math.round(info.installs)} Marketplace installs.`));
  }
  if (info.lastUpdated && now - Date.parse(info.lastUpdated) > STALE_MS) {
    out.push(signal('ext/stale', `Last Marketplace update ${info.lastUpdated.slice(0, 10)}.`));
  }
  return out;
}

/**
 * Looks extensions up on the VS Marketplace in batches. Sends the given extension identifiers to
 * Microsoft, so callers must only use it when the user opted in.
 */
export async function lookupMarketplace(
  ids: readonly string[],
  opts: { fetch?: typeof fetch; signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<Map<string, GalleryInfo>> {
  const doFetch = opts.fetch ?? fetch;
  const out = new Map<string, GalleryInfo>();
  for (let i = 0; i < ids.length; i += BATCH) {
    const batch = ids.slice(i, i + BATCH);
    const timeout = AbortSignal.timeout(opts.timeoutMs ?? 15000);
    const res = await doFetch(GALLERY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json;api-version=3.0-preview.1' },
      body: JSON.stringify(galleryQuery(batch)),
      signal: opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout,
    });
    if (!res.ok) {
      throw new Error(`Marketplace query failed: HTTP ${res.status}`);
    }
    parseGalleryResponse(await res.json(), batch).forEach((v, k) => out.set(k, v));
  }
  return out;
}
