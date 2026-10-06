import { createHash } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, normalize, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import yauzl from 'yauzl';

export type Registry = 'marketplace' | 'open-vsx';

export const MARKETPLACE = 'https://marketplace.visualstudio.com';
export const OPEN_VSX = 'https://open-vsx.org';
/** Same cap as the Go analyzer's VSIX comparison. */
export const MAX_VSIX_BYTES = 400 * 1024 * 1024;
export const MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024;
export const MAX_ENTRIES = 100_000;

export interface PackageRef {
  id: string;
  /** Pinned version; latest stable when absent. */
  version?: string;
}

/** Result key: `id` for the latest version, `id@version` for a pinned one. */
export const refKey = (r: PackageRef) => (r.version ? `${r.id.toLowerCase()}@${r.version}` : r.id.toLowerCase());

export interface ResolvedPackage {
  id: string;
  version: string;
  /** `universal` or a VS Code target such as `linux-x64`. */
  targetPlatform: string;
  url: string;
  /** Published SHA-256 of the VSIX, when the registry provides one. */
  sha256?: string;
  registry: Registry;
  preRelease: boolean;
}

export type Resolution = { status: 'found'; pkg: ResolvedPackage } | { status: 'not-found'; reason: string } | { status: 'error'; reason: string };

export interface FetchOptions {
  registry?: Registry;
  /** Platform-specific packages: which build to scan (default linux-x64, what CI runners use). */
  targetPlatform?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  marketplaceUrl?: string;
  openVsxUrl?: string;
}

// ---------------------------------------------------------------- Marketplace

interface GalleryVersion {
  version: string;
  targetPlatform?: string;
  assetUri?: string;
  properties?: { key: string; value: string }[];
}
interface GalleryExt {
  extensionName: string;
  publisher: { publisherName: string };
  versions?: GalleryVersion[];
}

/** IncludeVersions | IncludeFiles | IncludeVersionProperties | IncludeAssetUri | IncludeStatistics (+ IncludeLatestVersionOnly). */
const FLAGS_ALL_VERSIONS = 403;
const FLAGS_LATEST = 915;
const prop = (v: GalleryVersion, key: string) => v.properties?.find((p) => p.key === key)?.value;
const isPre = (v: GalleryVersion) => prop(v, 'Microsoft.VisualStudio.Code.PreRelease') === 'true';
const platformOf = (v: GalleryVersion) => v.targetPlatform ?? 'universal';

/** Picks the build to scan: the newest stable version (or the pinned one), universal or the requested platform. */
export function pickGalleryVersion(versions: readonly GalleryVersion[], target: string, pinned?: string): GalleryVersion | undefined {
  const fits = (v: GalleryVersion) => platformOf(v) === 'universal' || platformOf(v) === target;
  const candidates = versions.filter((v) => fits(v) && (pinned ? v.version === pinned : !isPre(v)));
  // The gallery lists newest first; universal wins over a platform build of the same version.
  return candidates.sort((a, b) => (a.version === b.version ? (platformOf(a) === 'universal' ? -1 : 1) : 0))[0];
}

async function galleryQuery(ids: string[], flags: number, opts: FetchOptions): Promise<Map<string, GalleryExt>> {
  const doFetch = opts.fetch ?? fetch;
  const res = await doFetch(`${opts.marketplaceUrl ?? MARKETPLACE}/_apis/public/gallery/extensionquery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json;api-version=3.0-preview.1' },
    body: JSON.stringify({
      filters: [{ criteria: [...ids.map((value) => ({ filterType: 7, value })), { filterType: 8, value: 'Microsoft.VisualStudio.Code' }], pageNumber: 1, pageSize: ids.length }],
      flags,
    }),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
  });
  if (!res.ok) {
    throw new Error(`Marketplace query failed: HTTP ${res.status}`);
  }
  const json = (await res.json()) as { results?: { extensions?: GalleryExt[] }[] };
  const out = new Map<string, GalleryExt>();
  for (const e of json.results?.[0]?.extensions ?? []) {
    out.set(`${e.publisher.publisherName}.${e.extensionName}`.toLowerCase(), e);
  }
  return out;
}

function fromGallery(ref: PackageRef, v: GalleryVersion, opts: FetchOptions): ResolvedPackage {
  const [pub, name] = ref.id.split('.');
  const platform = platformOf(v);
  const url = v.assetUri
    ? `${v.assetUri}/Microsoft.VisualStudio.Services.VSIXPackage`
    : `${opts.marketplaceUrl ?? MARKETPLACE}/_apis/public/gallery/publishers/${encodeURIComponent(pub)}/vsextensions/${encodeURIComponent(name)}/${encodeURIComponent(v.version)}/vspackage${platform === 'universal' ? '' : `?targetPlatform=${platform}`}`;
  return { id: ref.id, version: v.version, targetPlatform: platform, url, sha256: prop(v, 'Microsoft.VisualStudio.Services.VsixSha256'), registry: 'marketplace', preRelease: isPre(v) };
}

async function resolveMarketplace(refs: readonly PackageRef[], opts: FetchOptions): Promise<Map<string, Resolution>> {
  const target = opts.targetPlatform ?? 'linux-x64';
  const out = new Map<string, Resolution>();
  const latest = new Map<string, GalleryExt>();
  const ids = [...new Set(refs.map((r) => r.id))];
  for (let i = 0; i < ids.length; i += 50) {
    (await galleryQuery(ids.slice(i, i + 50), FLAGS_LATEST, opts)).forEach((v, k) => latest.set(k, v));
  }
  for (const ref of refs) {
    const ext = latest.get(ref.id);
    if (!ext) {
      out.set(refKey(ref), { status: 'not-found', reason: 'not on the VS Marketplace (never published, renamed or taken down)' });
      continue;
    }
    let v = pickGalleryVersion(ext.versions ?? [], target, ref.version);
    if (!v) {
      // Pinned older version, or the latest is a pre-release: look through every version.
      const all = (await galleryQuery([ref.id], FLAGS_ALL_VERSIONS, opts)).get(ref.id);
      v = pickGalleryVersion(all?.versions ?? [], target, ref.version) ?? (ref.version ? undefined : (all?.versions ?? []).find((x) => platformOf(x) === 'universal' || platformOf(x) === target));
    }
    out.set(
      refKey(ref),
      v
        ? { status: 'found', pkg: fromGallery(ref, v, opts) }
        : { status: 'not-found', reason: ref.version ? `version ${ref.version} is not published for ${target}` : `no package for ${target}` },
    );
  }
  return out;
}

// ---------------------------------------------------------------- Open VSX

interface OpenVsxExt {
  version: string;
  targetPlatform?: string;
  preRelease?: boolean;
  files?: { download?: string; sha256?: string };
}

async function resolveOpenVsx(refs: readonly PackageRef[], opts: FetchOptions): Promise<Map<string, Resolution>> {
  const doFetch = opts.fetch ?? fetch;
  const base = opts.openVsxUrl ?? OPEN_VSX;
  const target = opts.targetPlatform ?? 'linux-x64';
  const get = async (path: string): Promise<OpenVsxExt | undefined> => {
    const res = await doFetch(`${base}/api/${path}`, { signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000) });
    if (res.status === 404) {
      return undefined;
    }
    if (!res.ok) {
      throw new Error(`Open VSX: HTTP ${res.status}`);
    }
    return (await res.json()) as OpenVsxExt;
  };
  const out = new Map<string, Resolution>();
  for (const ref of refs) {
    const [pub, name] = ref.id.split('.').map(encodeURIComponent);
    const suffix = ref.version ? `/${encodeURIComponent(ref.version)}` : '';
    try {
      let ext = await get(`${pub}/${name}${suffix}`);
      if (ext && ext.targetPlatform && ext.targetPlatform !== 'universal' && ext.targetPlatform !== target) {
        ext = await get(`${pub}/${name}/${target}${suffix || '/latest'}`);
      }
      if (!ext?.files?.download) {
        out.set(refKey(ref), { status: 'not-found', reason: ext ? `no package for ${target}` : 'not on Open VSX' });
        continue;
      }
      let sha256: string | undefined;
      if (ext.files.sha256) {
        const res = await doFetch(ext.files.sha256, { signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000) });
        sha256 = res.ok ? (await res.text()).trim().split(/\s+/)[0].toLowerCase() : undefined;
      }
      out.set(refKey(ref), {
        status: 'found',
        pkg: { id: ref.id, version: ext.version, targetPlatform: ext.targetPlatform ?? 'universal', url: ext.files.download, sha256, registry: 'open-vsx', preRelease: !!ext.preRelease },
      });
    } catch (err) {
      out.set(refKey(ref), { status: 'error', reason: (err as Error).message });
    }
  }
  return out;
}

/** Resolves extension ids (and pinned versions) to downloadable VSIX packages, keyed by {@link refKey}. */
export async function resolvePackages(refs: readonly PackageRef[], opts: FetchOptions = {}): Promise<Map<string, Resolution>> {
  const unique = [...new Map(refs.map((r) => [refKey(r), { ...r, id: r.id.toLowerCase() }])).values()];
  if (!unique.length) {
    return new Map();
  }
  try {
    return opts.registry === 'open-vsx' ? await resolveOpenVsx(unique, opts) : await resolveMarketplace(unique, opts);
  } catch (err) {
    return new Map(unique.map((r) => [refKey(r), { status: 'error', reason: (err as Error).message } as Resolution]));
  }
}

// ---------------------------------------------------------------- download + extract

export interface FetchedPackage {
  pkg: ResolvedPackage;
  /** Extracted extension folder (the VSIX's `extension/` directory). */
  dir: string;
  sha256: string;
  /** Published hash matched (true), was not published (undefined). A mismatch throws. */
  verified?: boolean;
  cached: boolean;
}

export function defaultCacheDir(): string {
  return join(process.env.RUNNER_TEMP || tmpdir(), 'jest-security-vsix');
}

const safeName = (s: string) => s.replace(/[^\w.@-]/g, '_');

/** Downloads with a byte cap, returning the body and its SHA-256. */
async function download(url: string, maxBytes: number, opts: FetchOptions): Promise<{ data: Buffer; sha256: string }> {
  const doFetch = opts.fetch ?? fetch;
  const res = await doFetch(url, { signal: AbortSignal.timeout(opts.timeoutMs ?? 5 * 60_000) });
  if (!res.ok || !res.body) {
    throw new Error(`download failed: HTTP ${res.status}`);
  }
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > maxBytes) {
    throw new Error(`package is ${Math.round(declared / 1024 / 1024)} MB, above the ${Math.round(maxBytes / 1024 / 1024)} MB limit`);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  const hash = createHash('sha256');
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
    total += chunk.byteLength;
    if (total > maxBytes) {
      throw new Error(`package exceeds the ${Math.round(maxBytes / 1024 / 1024)} MB limit`);
    }
    hash.update(chunk);
    chunks.push(Buffer.from(chunk));
  }
  return { data: Buffer.concat(chunks), sha256: hash.digest('hex') };
}

/**
 * Extracts the `extension/` folder of a VSIX into `dest`. Defensive: rejects absolute paths and
 * `..` (zip slip), skips symlinks and anything outside `extension/`, and caps entry count and
 * total size. Nothing is executed.
 */
export async function extractVsix(data: Buffer, dest: string, limits = { maxEntries: MAX_ENTRIES, maxBytes: MAX_EXTRACTED_BYTES }): Promise<{ files: number; bytes: number }> {
  const zip = await new Promise<yauzl.ZipFile>((resolve, reject) =>
    yauzl.fromBuffer(data, { lazyEntries: true, validateEntrySizes: true, strictFileNames: false }, (err, z) => (err ? reject(err) : resolve(z))),
  );
  let files = 0;
  let bytes = 0;
  let entries = 0;
  try {
    await new Promise<void>((resolve, reject) => {
      zip.on('error', reject);
      zip.on('end', resolve);
      zip.on('entry', (entry: yauzl.Entry) => {
        void (async () => {
          if (++entries > limits.maxEntries) {
            throw new Error(`more than ${limits.maxEntries} entries`);
          }
          const name = entry.fileName.replace(/\\/g, '/');
          if (name.startsWith('/') || /^[a-z]:/i.test(name) || name.split('/').includes('..')) {
            throw new Error(`unsafe path in package: ${name}`);
          }
          // Unix mode in the high 16 bits of the external attributes; 0o120000 = symlink.
          const isLink = ((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000;
          if (!name.startsWith('extension/') || name.endsWith('/') || isLink) {
            zip.readEntry();
            return;
          }
          bytes += entry.uncompressedSize;
          if (bytes > limits.maxBytes) {
            throw new Error(`extracted size exceeds ${Math.round(limits.maxBytes / 1024 / 1024)} MB`);
          }
          const target = normalize(join(dest, name.slice('extension/'.length)));
          if (!target.startsWith(normalize(dest) + sep) || isAbsolute(name)) {
            throw new Error(`unsafe path in package: ${name}`);
          }
          mkdirSync(dirname(target), { recursive: true });
          await pipeline(await zip.openReadStreamPromise(entry), createWriteStream(target, { mode: 0o644 }));
          files++;
          zip.readEntry();
        })().catch(reject);
      });
      zip.readEntry();
    });
  } finally {
    zip.close();
  }
  if (!existsSync(join(dest, 'package.json'))) {
    throw new Error('not a VS Code extension package (no extension/package.json)');
  }
  return { files, bytes };
}

/** Downloads (or reuses from `cacheDir`), verifies and extracts one package. */
export async function fetchPackage(pkg: ResolvedPackage, cacheDir = defaultCacheDir(), opts: FetchOptions & { maxBytes?: number } = {}): Promise<FetchedPackage> {
  const key = safeName(`${pkg.registry === 'open-vsx' ? 'ovsx-' : ''}${pkg.id}@${pkg.version}@${pkg.targetPlatform}`);
  const dir = join(cacheDir, key);
  const done = join(dir, '.jest-security.json');
  if (existsSync(done)) {
    const meta = JSON.parse(readFileSync(done, 'utf8')) as { sha256: string; verified?: boolean };
    return { pkg, dir: join(dir, 'extension'), sha256: meta.sha256, verified: meta.verified, cached: true };
  }
  const { data, sha256 } = await download(pkg.url, opts.maxBytes ?? MAX_VSIX_BYTES, opts);
  if (pkg.sha256 && pkg.sha256.toLowerCase() !== sha256) {
    throw new Error(`SHA-256 mismatch: registry publishes ${pkg.sha256}, downloaded ${sha256}`);
  }
  // Extract into a temporary folder and rename, so an interrupted run never leaves a half cache entry.
  const tmp = `${dir}.partial-${process.pid}`;
  rmSync(tmp, { recursive: true, force: true });
  try {
    await extractVsix(data, join(tmp, 'extension'));
    const verified = pkg.sha256 ? true : undefined;
    writeFileSync(join(tmp, '.jest-security.json'), JSON.stringify({ id: pkg.id, version: pkg.version, targetPlatform: pkg.targetPlatform, url: pkg.url, sha256, verified }));
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dirname(dir), { recursive: true });
    renameSync(tmp, dir);
    return { pkg, dir: join(dir, 'extension'), sha256, verified, cached: false };
  } catch (err) {
    rmSync(tmp, { recursive: true, force: true });
    throw err;
  }
}
