import { LineIndex, type Range } from './text';

export interface TagOccurrence {
  uri: string;
  /** Tag name without `@`, e.g. `sca` or `sca-ref`. */
  tag: string;
  id: string;
  description?: string;
  /** Range of the id inside the tag, so go-to-definition lands on it. */
  range: Range;
  line: number;
}

/**
 * Finds comment tags such as `@sca(aes-sbox, "table lookup indexed by key byte")` and
 * `@sca-ref(aes-sbox)`. Tag names are matched exactly; ids allow `[\w.:-]`.
 */
export function scanTags(uri: string, text: string, tagNames: readonly string[]): TagOccurrence[] {
  if (tagNames.length === 0) {
    return [];
  }
  const names = [...tagNames].sort((a, b) => b.length - a.length).map(escapeRe).join('|');
  const re = new RegExp(`@(${names})\\(\\s*([\\w.:-]+)\\s*(?:,\\s*"((?:[^"\\\\]|\\\\.)*)")?\\s*\\)`, 'g');
  const lines = new LineIndex(text);
  const out: TagOccurrence[] = [];
  for (const m of text.matchAll(re)) {
    const idStart = (m.index ?? 0) + m[0].indexOf(m[2], m[1].length + 2);
    const range = lines.rangeOf(idStart, idStart + m[2].length);
    out.push({ uri, tag: m[1], id: m[2], description: m[3], range, line: range.start.line });
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** In-memory index of tag occurrences across documents. */
export class TagIndex {
  private readonly byUri = new Map<string, TagOccurrence[]>();

  constructor(readonly tagNames: readonly string[]) {}

  update(uri: string, text: string): TagOccurrence[] {
    const tags = scanTags(uri, text, this.tagNames);
    if (tags.length) {
      this.byUri.set(uri, tags);
    } else {
      this.byUri.delete(uri);
    }
    return tags;
  }

  remove(uri: string): void {
    this.byUri.delete(uri);
  }

  all(): TagOccurrence[] {
    return [...this.byUri.values()].flat();
  }

  inDocument(uri: string): TagOccurrence[] {
    return this.byUri.get(uri) ?? [];
  }

  find(id: string, tag?: string): TagOccurrence[] {
    return this.all().filter((t) => t.id === id && (!tag || t.tag === tag));
  }

  /** The occurrence whose id range contains the position, if any. */
  at(uri: string, line: number, character: number): TagOccurrence | undefined {
    return this.inDocument(uri).find(
      (t) => t.range.start.line === line && t.range.start.character <= character && character <= t.range.end.character,
    );
  }
}
