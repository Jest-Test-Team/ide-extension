/** Zero-based line/character position, character counted in UTF-16 code units (same as VS Code). */
export interface Position {
  line: number;
  character: number;
}

export interface Range {
  start: Position;
  end: Position;
}

/** Maps UTF-16 offsets to positions for a fixed text. Build once per document version. */
export class LineIndex {
  private readonly lineStarts: number[] = [0];

  constructor(readonly text: string) {
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) {
        this.lineStarts.push(i + 1);
      }
    }
  }

  get lineCount(): number {
    return this.lineStarts.length;
  }

  positionAt(offset: number): Position {
    const clamped = Math.max(0, Math.min(offset, this.text.length));
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid] <= clamped) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return { line: lo, character: clamped - this.lineStarts[lo] };
  }

  offsetAt(pos: Position): number {
    const line = Math.max(0, Math.min(pos.line, this.lineStarts.length - 1));
    return Math.min(this.lineStarts[line] + pos.character, this.text.length);
  }

  rangeOf(startOffset: number, endOffset: number): Range {
    return { start: this.positionAt(startOffset), end: this.positionAt(endOffset) };
  }

  lineText(line: number): string {
    const start = this.lineStarts[line] ?? this.text.length;
    const next = this.lineStarts[line + 1];
    return this.text.slice(start, next === undefined ? undefined : next - 1).replace(/\r$/, '');
  }
}

/** Replaces `{{name}}` placeholders; unknown names are left untouched. */
export function renderTemplate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (whole, key: string) => vars[key] ?? whole);
}
