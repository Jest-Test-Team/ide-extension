/** Finds the innermost unclosed `name(` before the cursor and the active argument index. */
export function enclosingCall(text: string): { name: string; arg: number } | undefined {
  let depth = 0;
  let arg = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === ')' || ch === ']' || ch === '}') {
      depth++;
    } else if (ch === '(' || ch === '[' || ch === '{') {
      if (depth === 0) {
        if (ch !== '(') {
          return undefined;
        }
        const m = /([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(text.slice(0, i));
        return m ? { name: m[1], arg } : undefined;
      }
      depth--;
    } else if (ch === ',' && depth === 0) {
      arg++;
    } else if (ch === ';' && depth === 0) {
      return undefined;
    }
  }
  return undefined;
}
