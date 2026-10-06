import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isManifestPath, parseManifest, type ManifestEntry } from './manifests';

const exec = promisify(execFile);

export type ChangeStatus = 'added' | 'changed' | 'removed' | 'unchanged';

/** One extension's status between the base and the head of a change. */
export interface ManifestChange {
  id: string;
  status: ChangeStatus;
  /** Pinned version at head (or at base for removed extensions). */
  version?: string;
  baseVersion?: string;
  /** Where the head references it (base references for removed ones). */
  entries: ManifestEntry[];
}

/** References that put an extension on the team's list (not unwanted / dev container removals). */
const wanted = (e: ManifestEntry) => e.kind !== 'unwanted' && !e.remove;

function group(entries: readonly ManifestEntry[]): Map<string, ManifestEntry[]> {
  const m = new Map<string, ManifestEntry[]>();
  for (const e of entries.filter(wanted)) {
    m.set(e.id, [...(m.get(e.id) ?? []), e]);
  }
  return m;
}

const pinned = (es: readonly ManifestEntry[]) => es.find((e) => e.version)?.version;

/**
 * Compares the extension lists of two revisions. `base` undefined means "no baseline": every
 * extension at head counts as added (full scan on push / schedule).
 */
export function diffManifests(base: readonly ManifestEntry[] | undefined, head: readonly ManifestEntry[]): ManifestChange[] {
  const h = group(head);
  const b = group(base ?? []);
  const out: ManifestChange[] = [];
  for (const [id, entries] of h) {
    const version = pinned(entries);
    if (!base || !b.has(id)) {
      out.push({ id, status: 'added', version, entries });
      continue;
    }
    const baseVersion = pinned(b.get(id)!);
    out.push({ id, status: version !== baseVersion ? 'changed' : 'unchanged', version, baseVersion, entries });
  }
  for (const [id, entries] of b) {
    if (!h.has(id)) {
      out.push({ id, status: 'removed', version: pinned(entries), entries });
    }
  }
  const order: Record<ChangeStatus, number> = { added: 0, changed: 1, removed: 2, unchanged: 3 };
  // Within a status, follow the files: reports then read in the same order as the manifest.
  const at = (c: ManifestChange) => c.entries[0];
  return out.sort((x, y) => order[x.status] - order[y.status] || at(x).file.localeCompare(at(y).file) || at(x).line - at(y).line || x.id.localeCompare(y.id));
}

/** Extensions a change introduces or re-versions: what gets scanned and can fail the check. */
export const toScan = (changes: readonly ManifestChange[]) => changes.filter((c) => c.status === 'added' || c.status === 'changed');

async function git(cwd: string, args: string[]): Promise<string> {
  return (await exec('git', args, { cwd, maxBuffer: 64 * 1024 * 1024 })).stdout;
}

/** Verifies `ref` resolves to a commit; throws a readable error otherwise (e.g. shallow clone). */
export async function resolveRef(cwd: string, ref: string): Promise<string> {
  try {
    return (await git(cwd, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`])).trim();
  } catch {
    throw new Error(`git ref "${ref}" not found — fetch it first (e.g. actions/checkout with fetch-depth: 0, or git fetch origin ${ref})`);
  }
}

/**
 * Manifest entries at `ref`: the given files plus any auto-detected manifest that existed there,
 * so a deleted dev container still shows its extensions as removed. Missing files count as empty.
 */
export async function readManifestsAtRef(cwd: string, ref: string, files: readonly string[], autoDetect: boolean): Promise<ManifestEntry[]> {
  const commit = await resolveRef(cwd, ref);
  const paths = new Set(files);
  if (autoDetect) {
    (await git(cwd, ['ls-tree', '-r', '--name-only', commit]))
      .split('\n')
      .filter((p) => p && isManifestPath(p) && !/(^|\/)(node_modules|\.git|dist|out)\//.test(p))
      .forEach((p) => paths.add(p));
  }
  const out: ManifestEntry[] = [];
  for (const p of [...paths].sort()) {
    let text: string;
    try {
      text = await git(cwd, ['show', `${commit}:${p}`]);
    } catch {
      continue; // not present at the base
    }
    try {
      out.push(...parseManifest(p, text));
    } catch {
      // An unparsable base file contributes nothing; the head file is what gets validated.
    }
  }
  return out;
}
