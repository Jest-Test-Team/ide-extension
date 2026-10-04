/** Optimal-string-alignment (restricted Damerau–Levenshtein) distance; stops early above `max`. */
export function editDistance(a: string, b: string, max = Infinity): number {
  if (Math.abs(a.length - b.length) > max) {
    return max + 1;
  }
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let d = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d = Math.min(d, prev2[j - 2] + 1);
      }
      cur.push(d);
      rowMin = Math.min(rowMin, d);
    }
    if (rowMin > max) {
      return max + 1;
    }
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length];
}

/** Folds look-alike characters and separators so `rn`/`m`, `0`/`o`, `1`/`l`/`i`, `_`/`-` compare equal. */
export function foldHomoglyphs(id: string): string {
  return id
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/[1i|]/g, 'l')
    .replace(/5/g, 's')
    .replace(/[_\s]/g, '-')
    .replace(/-+/g, '-');
}

export interface TyposquatMatch {
  target: string;
  reason: 'edit-distance' | 'homoglyph';
  distance: number;
}

/**
 * Finds a popular extension `id` imitates. Identifiers from the same publisher as the target never
 * match: Marketplace publisher names are unique, so a same-publisher sibling is not impersonation.
 */
export function findTyposquat(id: string, popular: Iterable<string>): TyposquatMatch | undefined {
  const lower = id.toLowerCase();
  const publisher = lower.split('.')[0];
  const folded = foldHomoglyphs(lower);
  let best: TyposquatMatch | undefined;
  for (const target of popular) {
    if (target === lower || target.split('.')[0] === publisher) {
      continue;
    }
    if (foldHomoglyphs(target) === folded) {
      return { target, reason: 'homoglyph', distance: editDistance(lower, target) };
    }
    // Short identifiers are naturally close to each other; allow one edit below 10 characters.
    const max = target.length < 10 ? 1 : 2;
    const d = editDistance(lower, target, max);
    if (d <= max && (!best || d < best.distance)) {
      best = { target, reason: 'edit-distance', distance: d };
    }
  }
  return best;
}
