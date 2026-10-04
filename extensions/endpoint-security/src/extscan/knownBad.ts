import type { RiskLevel } from './signals';

export interface RemovedEntry {
  id: string;
  /** Removal date as published (MM/DD/YYYY). */
  date: string;
  type: string;
}

export interface RemovedSnapshot {
  source: string;
  fetched: string;
  entries: [id: string, date: string, type: string][];
}

export const REMOVED_PACKAGES_URL = 'https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md';

/** Parses the `| Extension Identifier | Removal Date | Type |` table of RemovedPackages.md. */
export function parseRemovedPackages(markdown: string): RemovedEntry[] {
  const out: RemovedEntry[] = [];
  for (const line of markdown.split(/\r?\n/)) {
    const cells = line.split('|').map((c) => c.trim());
    // A table row splits into ['', id, date, type(, '')] — the trailing pipe is optional.
    if (cells.length < 4 || !/^[\w-]+\.[\w.-]+$/.test(cells[1]) || !/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(cells[2])) {
      continue;
    }
    out.push({ id: cells[1].toLowerCase(), date: cells[2], type: cells[3] });
  }
  return out;
}

export function toSnapshot(entries: RemovedEntry[], fetched = new Date().toISOString()): RemovedSnapshot {
  return { source: REMOVED_PACKAGES_URL, fetched, entries: entries.map((e) => [e.id, e.date, e.type]) };
}

export function indexSnapshot(snapshot: RemovedSnapshot): Map<string, RemovedEntry> {
  const map = new Map<string, RemovedEntry>();
  for (const [id, date, type] of snapshot.entries) {
    map.set(id.toLowerCase(), { id: id.toLowerCase(), date, type });
  }
  return map;
}

export interface RemovalVerdict {
  /** Weight added to the score (0 for benign removal reasons). */
  weight: number;
  force?: RiskLevel;
}

/** How much a removal reason counts: malware forces high, impersonation-like reasons weigh heavily. */
export function removalVerdict(type: string): RemovalVerdict {
  const t = type.toLowerCase();
  if (/malware|malicious/.test(t)) {
    return { weight: 10, force: 'high' };
  }
  if (/impersonation|untrustworthy|expired domain|typo/.test(t)) {
    return { weight: 6 };
  }
  // Spam, Deprecated, Owner Request, Publisher requested, ...: informational.
  return { weight: 0 };
}
