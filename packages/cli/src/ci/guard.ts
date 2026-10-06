import type { Rule } from '@ide-ext/core';
import { loadManifestOptions } from '../../../../extensions/endpoint-security/src/extscan/data';
import { manifestSignals, type ExtInfo } from '../../../../extensions/endpoint-security/src/extscan/manifest';
import type { ExtResult } from '../../../../extensions/endpoint-security/src/extscan/scanner';
import { isAllowlisted, scoreExtension } from '../../../../extensions/endpoint-security/src/extscan/score';
import { signal, type RiskLevel, type Signal } from '../../../../extensions/endpoint-security/src/extscan/signals';
import type { EngineId } from '../analyzers/protocol';
import { scanExtensions, type ScanCoverage } from '../endpoint';
import { assetDir } from '../lib/assets';
import { diffManifests, readManifestsAtRef, toScan, type ManifestChange } from './diff';
import { defaultCacheDir, fetchPackage, refKey, resolvePackages, type FetchedPackage, type FetchOptions, type Registry, type Resolution } from './fetch';
import { readManifests } from './manifests';
import { evaluatePolicy, type FailOn, type Policy, type Violation } from './policy';

export interface GuardOptions {
  /** Repository root. */
  root: string;
  /** Manifest files / folders (repository-relative); empty = auto-discover. */
  manifests: string[];
  /** Git ref to compare with; only added / version-changed extensions are scanned. */
  base?: string;
  /** Also scan unchanged extensions when a base is given. */
  all?: boolean;
  registry: Registry;
  targetPlatform: string;
  cacheDir?: string;
  policy: Policy;
  failOn: FailOn;
  allowlist: string[];
  trusted: string[];
  includeNodeModules: boolean;
  maxFiles: number;
  /** Marketplace reputation lookups (verified publisher, installs). */
  reputation: boolean;
  analyzers: EngineId[];
  analyzerTimeoutMs: number;
  fetch?: FetchOptions;
  onProgress?: (msg: string) => void;
}

/** One extension a change introduces (or, with --all / no base, every listed one). */
export interface GuardItem {
  change: ManifestChange;
  /** scanned = package downloaded and scanned; id-only = not downloadable, judged by id; unscanned = registry / download error. */
  status: 'scanned' | 'id-only' | 'unscanned';
  resolution?: Resolution;
  fetched?: FetchedPackage;
  /** Why the package could not be scanned. */
  reason?: string;
  result?: ExtResult;
  violations: Violation[];
  /** Blocks the change: risk at or above fail-on, or a policy violation. */
  failing: boolean;
}

export interface GuardReport {
  files: string[];
  base?: string;
  changes: ManifestChange[];
  items: GuardItem[];
  codeRules: Rule[];
  coverage?: ScanCoverage;
  failOn: FailOn;
  registry: Registry;
  targetPlatform: string;
  exitCode: 0 | 1 | 2;
}

const RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

export const atOrAbove = (level: RiskLevel, failOn: FailOn) => failOn !== 'none' && RANK[level] >= RANK[failOn];

/** A result for an extension that could not be downloaded: manifest-free signals from its id. */
function idOnlyResult(change: ManifestChange, registry: Registry, notFound: boolean, opts: GuardOptions, manifestOpts: ReturnType<typeof loadManifestOptions>): ExtResult {
  const [publisher, ...rest] = change.id.split('.');
  const ext: ExtInfo = {
    id: change.id,
    version: change.version ?? 'latest',
    path: `${registry}:${change.id}`,
    packageJSON: { publisher, name: rest.join('.') },
    builtin: false,
  };
  // Typosquat, known-bad list and publisher checks only need the id.
  const signals: Signal[] = manifestSignals(ext, manifestOpts).filter((s) => ['ext/typosquat', 'ext/known-bad', 'ext/unknown-publisher', 'ext/trusted-publisher'].includes(s.id));
  if (notFound) {
    signals.push(
      signal('ext/not-on-marketplace', registry === 'open-vsx' ? `\`${change.id}\` is not published on Open VSX.` : `\`${change.id}\` is not listed on the VS Marketplace (never published, renamed or taken down).`),
    );
  }
  return { ext: { id: ext.id, version: ext.version, path: ext.path, builtin: false }, risk: scoreExtension(signals, { allowlisted: isAllowlisted(change.id, ext.version, opts.allowlist) }) };
}

export async function runGuard(opts: GuardOptions): Promise<GuardReport> {
  const head = readManifests(opts.root, opts.manifests);
  const baseEntries = opts.base ? await readManifestsAtRef(opts.root, opts.base, head.files, !opts.manifests.length) : undefined;
  const changes = diffManifests(baseEntries, head.entries);
  const selected = opts.all ? changes.filter((c) => c.status !== 'removed') : toScan(changes);
  const items: GuardItem[] = selected.map((change) => ({ change, status: 'unscanned', violations: [], failing: false }));
  const manifestOpts = loadManifestOptions(assetDir('extscan'), opts.trusted);

  // 1. Resolve and download.
  const resolutions = await resolvePackages(
    items.map((i) => ({ id: i.change.id, version: i.change.version })),
    { ...opts.fetch, registry: opts.registry, targetPlatform: opts.targetPlatform },
  );
  for (const item of items) {
    const res = resolutions.get(refKey({ id: item.change.id, version: item.change.version }));
    item.resolution = res;
    if (res?.status === 'found') {
      opts.onProgress?.(`downloading ${res.pkg.id}@${res.pkg.version}`);
      try {
        item.fetched = await fetchPackage(res.pkg, opts.cacheDir ?? defaultCacheDir(), opts.fetch);
        item.status = 'scanned';
      } catch (err) {
        item.reason = (err as Error).message;
      }
    } else if (res?.status === 'not-found') {
      item.status = 'id-only';
      item.reason = res.reason;
    } else {
      item.reason = res?.status === 'error' ? res.reason : 'not resolved';
    }
  }

  // 2. Scan the downloaded packages with the full scanner.
  const fetched = items.filter((i) => i.fetched);
  let codeRules: Rule[] = [];
  let coverage: ScanCoverage | undefined;
  if (fetched.length) {
    const scan = await scanExtensions(
      fetched.map((i) => i.fetched!.dir),
      {
        allowlist: opts.allowlist,
        trusted: opts.trusted,
        includeNodeModules: opts.includeNodeModules,
        maxFiles: opts.maxFiles,
        online: opts.reputation,
        analyzers: opts.analyzers,
        analyzerTimeoutMs: opts.analyzerTimeoutMs,
        onProgress: (id) => opts.onProgress?.(`scanning ${id}`),
      },
    );
    codeRules = scan.codeRules;
    coverage = scan.coverage;
    for (const item of fetched) {
      item.result = scan.results.find((r) => r.ext.path === item.fetched!.dir);
      if (!item.result) {
        item.status = 'unscanned';
        item.reason = 'the package has no readable package.json';
      }
    }
  }
  for (const item of items.filter((i) => !i.result)) {
    // Not downloadable: still judged by id (known-bad list, look-alikes work offline). Registry or
    // download errors keep the item "unscanned", which fails the run with exit code 2.
    item.result = idOnlyResult(item.change, opts.registry, item.status === 'id-only', opts, manifestOpts);
  }

  // 3. Policy and verdict.
  for (const item of items) {
    const signals = item.result?.risk.signals ?? [];
    const verified = signals.some((s) => s.id === 'ext/verified-publisher') ? true : signals.some((s) => s.id === 'ext/unverified-publisher') ? false : undefined;
    item.violations = evaluatePolicy(item.change.id, opts.policy, verified);
    item.failing = item.violations.length > 0 || (!!item.result && atOrAbove(item.result.risk.level, opts.failOn));
  }
  const failing = items.some((i) => i.failing);
  const errors = items.some((i) => i.status === 'unscanned');
  return {
    files: head.files,
    base: opts.base,
    changes,
    items,
    codeRules,
    coverage,
    failOn: opts.failOn,
    registry: opts.registry,
    targetPlatform: opts.targetPlatform,
    exitCode: failing ? 1 : errors ? 2 : 0,
  };
}
