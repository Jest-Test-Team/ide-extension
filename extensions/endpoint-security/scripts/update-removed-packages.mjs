// Refreshes data/extscan/removed-packages.json from microsoft/vsmarketplace RemovedPackages.md.
// Usage (from extensions/endpoint-security): node scripts/update-removed-packages.mjs
// Kept in sync with parseRemovedPackages() in src/extscan/knownBad.ts.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const URL = 'https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md';
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'extscan', 'removed-packages.json');

const res = await fetch(URL);
if (!res.ok) {
  throw new Error(`GET ${URL}: ${res.status}`);
}
const entries = [];
for (const line of (await res.text()).split(/\r?\n/)) {
  const cells = line.split('|').map((c) => c.trim());
  if (cells.length < 4 || !/^[\w-]+\.[\w.-]+$/.test(cells[1]) || !/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(cells[2])) {
    continue;
  }
  entries.push([cells[1].toLowerCase(), cells[2], cells[3]]);
}
if (entries.length < 100) {
  throw new Error(`only ${entries.length} entries parsed; the table format may have changed`);
}
writeFileSync(out, JSON.stringify({ source: URL, fetched: new Date().toISOString(), entries }) + '\n');
console.log(`wrote ${entries.length} entries to ${out}`);
