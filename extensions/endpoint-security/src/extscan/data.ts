import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { indexSnapshot, type RemovedSnapshot } from './knownBad';
import type { ManifestOptions } from './manifest';

interface PopularFile {
  trustedPublishers: string[];
  popular: string[];
}

/**
 * Loads the bundled scanner data (`data/extscan` → `dist/extscan`). A downloaded known-bad list in
 * `updatedRemovedPath` replaces the bundled snapshot when it exists and is newer.
 */
export function loadManifestOptions(dataDir: string, extraTrusted: readonly string[] = [], updatedRemovedPath?: string): ManifestOptions & { knownBadFetched: string } {
  const popular = JSON.parse(readFileSync(join(dataDir, 'popular-extensions.json'), 'utf8')) as PopularFile;
  let removed = JSON.parse(readFileSync(join(dataDir, 'removed-packages.json'), 'utf8')) as RemovedSnapshot;
  if (updatedRemovedPath && existsSync(updatedRemovedPath)) {
    try {
      const updated = JSON.parse(readFileSync(updatedRemovedPath, 'utf8')) as RemovedSnapshot;
      if (Array.isArray(updated.entries) && updated.fetched > removed.fetched) {
        removed = updated;
      }
    } catch {
      // Corrupt download: keep the bundled snapshot.
    }
  }
  return {
    trustedPublishers: new Set([...popular.trustedPublishers, ...extraTrusted].map((p) => p.toLowerCase())),
    popular: [...new Set(popular.popular.map((p) => p.toLowerCase()))],
    knownBad: indexSnapshot(removed),
    knownBadFetched: removed.fetched,
  };
}
