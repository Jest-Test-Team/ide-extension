import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, relative } from 'node:path';

/** Where a team's extension list can live in a repository. */
export type ManifestKind = 'recommendation' | 'unwanted' | 'devcontainer' | 'workspace' | 'profile' | 'list';

/** One extension reference in a committed file. */
export interface ManifestEntry {
  /** Lower-case `publisher.name`. */
  id: string;
  /** Pinned version (`id@1.2.3`, profile entries, `--show-versions` lists). */
  version?: string;
  /** Repository-relative path, forward slashes. */
  file: string;
  /** 1-based line of the reference. */
  line: number;
  kind: ManifestKind;
  /** Dev container `-publisher.name`: removes an extension a feature would add. */
  remove?: boolean;
}

const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][\w.-]*$/i;

/** Strips `//` and `/* *\/` comments and trailing commas (JSONC), keeping offsets and line numbers. */
export function stripJsonc(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') {
        j += text[j] === '\\' ? 2 : 1;
      }
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      const stop = end < 0 ? text.length : end;
      out += ' '.repeat(stop - i);
      i = stop;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return dropTrailingCommas(out);
}

/** Replaces commas followed only by whitespace and `}` / `]` with a space, skipping strings. */
function dropTrailingCommas(text: string): string {
  const chars = [...text];
  let inString = false;
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (inString) {
      if (c === '\\') {
        i++;
      } else if (c === '"') {
        inString = false;
      }
    } else if (c === '"') {
      inString = true;
    } else if (c === ',') {
      let j = i + 1;
      while (j < chars.length && /\s/.test(chars[j])) {
        j++;
      }
      if (chars[j] === '}' || chars[j] === ']') {
        chars[i] = ' ';
      }
    }
  }
  return chars.join('');
}

/** Finds the line of each quoted value in order of appearance, so repeated ids get distinct lines. */
class LineFinder {
  private cursor = 0;
  constructor(private readonly text: string) {}
  lineOf(raw: string): number {
    let at = this.text.indexOf(JSON.stringify(raw), this.cursor);
    if (at < 0) {
      at = this.text.indexOf(raw, this.cursor);
    }
    if (at < 0) {
      return 1;
    }
    this.cursor = at + raw.length;
    return this.text.slice(0, at).split('\n').length;
  }
}

/** `publisher.name`, `publisher.name@1.2.3`, `-publisher.name` → parts; undefined when not an id. */
function splitRef(raw: string): { id: string; version?: string; remove: boolean } | undefined {
  const t = raw.trim();
  const remove = t.startsWith('-');
  const [id, version] = (remove ? t.slice(1) : t).split('@');
  if (!ID.test(id)) {
    return undefined;
  }
  return { id: id.toLowerCase(), version: version || undefined, remove };
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function fromList(raws: string[], file: string, kind: ManifestKind, lines: LineFinder): ManifestEntry[] {
  const out: ManifestEntry[] = [];
  for (const raw of raws) {
    const ref = splitRef(raw);
    if (ref) {
      out.push({ id: ref.id, version: ref.version, file, line: lines.lineOf(raw), kind, ...(ref.remove ? { remove: true } : {}) });
    }
  }
  return out;
}

/**
 * Parses one committed file. The format follows from the content: an object with
 * `recommendations`, a dev container (`customizations.vscode.extensions`), a workspace
 * (`extensions.recommendations`), a VS Code profile `extensions.json` (array), or a plain list
 * (`code --list-extensions --show-versions`).
 */
export function parseManifest(file: string, text: string): ManifestEntry[] {
  const lines = new LineFinder(text);
  const trimmed = text.trimStart();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    const raws = text
      .split(/\r?\n/)
      .map((l) => l.replace(/#.*/, '').trim())
      .filter(Boolean);
    return fromList(raws, file, 'list', lines);
  }
  let json: unknown;
  try {
    json = JSON.parse(stripJsonc(text));
  } catch (err) {
    throw new Error(`${file}: not valid JSON (${(err as Error).message})`);
  }
  if (Array.isArray(json)) {
    // VS Code profile extensions.json: [{ identifier: { id }, version }]
    const out: ManifestEntry[] = [];
    for (const e of json as { identifier?: { id?: unknown }; version?: unknown }[]) {
      const raw = e?.identifier?.id;
      if (typeof raw === 'string' && ID.test(raw)) {
        out.push({ id: raw.toLowerCase(), version: typeof e.version === 'string' ? e.version : undefined, file, line: lines.lineOf(raw), kind: 'profile' });
      }
    }
    return out;
  }
  const obj = (json ?? {}) as Record<string, unknown>;
  const out: ManifestEntry[] = [];
  out.push(...fromList(strings(obj.recommendations), file, 'recommendation', lines));
  out.push(...fromList(strings(obj.unwantedRecommendations), file, 'unwanted', lines));
  const ws = obj.extensions as Record<string, unknown> | undefined;
  if (ws && !Array.isArray(ws)) {
    out.push(...fromList(strings(ws.recommendations), file, 'workspace', lines));
    out.push(...fromList(strings(ws.unwantedRecommendations), file, 'unwanted', lines));
  }
  const dc = ((obj.customizations as Record<string, unknown> | undefined)?.vscode as Record<string, unknown> | undefined)?.extensions;
  // Older dev container files list extensions at the top level.
  out.push(...fromList([...strings(dc), ...strings(Array.isArray(ws) ? ws : undefined)], file, 'devcontainer', lines));
  return out.sort((a, b) => a.line - b.line);
}

/** Files found automatically: workspace recommendations, dev containers, `.code-workspace` files. */
export function isManifestPath(rel: string): boolean {
  const p = rel.replace(/\\/g, '/');
  const name = basename(p);
  return /(^|\/)\.vscode\/extensions\.json$/.test(p) || name === 'devcontainer.json' || name === '.devcontainer.json' || name.endsWith('.code-workspace');
}

const SKIP = new Set(['node_modules', '.git', 'dist', 'out', 'build', 'target', '.vscode-test', 'vendor']);

/** Walks `root` for manifest files (repository-relative, sorted). */
export function discoverManifests(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) {
          walk(p);
        }
      } else if (e.isFile() && isManifestPath(relative(root, p))) {
        out.push(relative(root, p).replace(/\\/g, '/'));
      }
    }
  };
  walk(root);
  return out.sort();
}

/** Reads and parses manifests from disk; `paths` may be files or folders (searched). */
export function readManifests(root: string, paths?: readonly string[]): { files: string[]; entries: ManifestEntry[] } {
  const files = new Set<string>();
  for (const p of paths?.length ? paths : ['.']) {
    const abs = join(root, p);
    if (statSync(abs).isDirectory()) {
      discoverManifests(abs).forEach((f) => files.add(relative(root, join(abs, f)).replace(/\\/g, '/')));
    } else {
      files.add(relative(root, abs).replace(/\\/g, '/'));
    }
  }
  const sorted = [...files].sort();
  return { files: sorted, entries: sorted.flatMap((f) => parseManifest(f, readFileSync(join(root, f), 'utf8'))) };
}
