import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SIGNALS } from '../../src/extscan/signals';
import { VECTOR_DEFS } from '../../src/extscan/vectors.generated';
import { CATEGORY_TITLES } from '../../src/extscan/vectorTypes';

const ROOT = join(__dirname, '..', '..');

describe('vector registry', () => {
  it('is regenerated from vectors.yaml', async () => {
    const { generate } = (await import(join(ROOT, 'scripts', 'gen-vectors.mjs'))) as { generate: (y: string) => string };
    const expected = generate(readFileSync(join(ROOT, 'data', 'extscan', 'vectors.yaml'), 'utf8'));
    expect(readFileSync(join(ROOT, 'src', 'extscan', 'vectors.generated.ts'), 'utf8')).toBe(expected);
  });

  it('has at least 100 vectors covering every category', () => {
    expect(VECTOR_DEFS.length).toBeGreaterThanOrEqual(100);
    const cats = new Set(VECTOR_DEFS.map((v) => v.category));
    for (const c of Object.keys(CATEGORY_TITLES)) {
      expect(cats.has(c), c).toBe(true);
    }
  });

  it('keeps the original signal ids and weights', () => {
    const original: Record<string, number> = {
      'ext/activates-on-startup': 2, 'ext/activates-after-startup': 1, 'ext/untrusted-workspace': 1, 'ext/many-dependencies': 1,
      'ext/unknown-publisher': 0, 'ext/trusted-publisher': -2, 'ext/typosquat': 4, 'ext/sideloaded': 1, 'ext/known-bad': 6,
      'ext/process-exec': 1, 'ext/dynamic-code': 1, 'ext/hardcoded-ip': 2, 'ext/exfil-endpoint': 3, 'ext/credential-path': 3,
      'ext/input-capture': 2, 'ext/native-binary': 1, 'ext/obfuscated': 3, 'ext/scan-incomplete': 0, 'ext/not-on-marketplace': 3,
      'ext/unverified-publisher': 1, 'ext/low-installs': 1, 'ext/stale': 0, 'ext/verified-publisher': -1,
    };
    for (const [id, w] of Object.entries(original)) {
      expect(SIGNALS[id]?.weight, id).toBe(w);
    }
  });

  it('gives every risk-raising vector a description and a reference or rationale', () => {
    for (const v of VECTOR_DEFS) {
      expect(v.description.length, v.id).toBeGreaterThan(20);
      expect(v.engines.length, v.id).toBeGreaterThan(0);
    }
    const highWithoutRef = VECTOR_DEFS.filter((v) => v.weight >= 4 && !v.attack.length && !v.cwe.length && !v.doc.length).map((v) => v.id);
    expect(highWithoutRef).toEqual([]);
  });
});
