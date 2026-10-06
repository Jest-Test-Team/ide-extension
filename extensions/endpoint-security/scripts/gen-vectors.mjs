// Generates src/extscan/vectors.generated.ts from data/extscan/vectors.yaml (the vector registry).
// Usage: node scripts/gen-vectors.mjs [--check]   (--check exits 1 if the generated file is stale)
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'data', 'extscan', 'vectors.yaml');
const out = join(root, 'src', 'extscan', 'vectors.generated.ts');

const CATEGORIES = ['manifest', 'process', 'data', 'network', 'obfuscation', 'native', 'supply-chain', 'webview', 'vscode-api', 'scripts', 'reputation', 'model', 'meta', 'runtime'];
const ENGINES = ['ts', 'rs', 'go', 'py', 'jl', 'rt'];
const SEVERITIES = ['error', 'warning', 'info', 'hint'];
const DOCS = ['activation', 'trust', 'ext-security', 'removed'];

export function generate(yamlText) {
  const doc = parse(yamlText);
  if (doc.version !== 1 || !Array.isArray(doc.vectors)) {
    throw new Error('vectors.yaml: expected version 1 and a vectors list');
  }
  const seen = new Set();
  const vectors = doc.vectors.map((v, i) => {
    const where = `vectors[${i}] (${v.id})`;
    if (!/^(ext|runtime)\/[a-z0-9-]+$/.test(v.id ?? '')) {throw new Error(`${where}: bad id`);}
    if (seen.has(v.id)) {throw new Error(`${where}: duplicate id`);}
    seen.add(v.id);
    if (!CATEGORIES.includes(v.category)) {throw new Error(`${where}: unknown category ${v.category}`);}
    if (!Array.isArray(v.engines) || !v.engines.length || v.engines.some((e) => !ENGINES.includes(e))) {throw new Error(`${where}: bad engines`);}
    if (!Number.isInteger(v.weight)) {throw new Error(`${where}: weight must be an integer`);}
    if (!SEVERITIES.includes(v.severity)) {throw new Error(`${where}: bad severity`);}
    if (typeof v.title !== 'string' || typeof v.description !== 'string') {throw new Error(`${where}: title and description are required`);}
    const refs = v.refs ?? {};
    for (const d of refs.doc ?? []) {if (!DOCS.includes(d)) {throw new Error(`${where}: unknown doc ref ${d}`);}}
    return {
      id: v.id,
      category: v.category,
      engines: v.engines,
      weight: v.weight,
      severity: v.severity,
      online: v.online === true,
      title: v.title,
      description: v.description,
      attack: (refs.attack ?? []).map(String),
      cwe: (refs.cwe ?? []).map(String),
      doc: refs.doc ?? [],
    };
  });
  return [
    '// Generated from data/extscan/vectors.yaml by scripts/gen-vectors.mjs. Do not edit; run `npm run gen:vectors`.',
    "import type { VectorDef } from './vectorTypes';",
    '',
    `export const VECTOR_DEFS: readonly VectorDef[] = ${JSON.stringify(vectors, null, 2)};`,
    '',
  ].join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = generate(readFileSync(src, 'utf8'));
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('vectors.generated.ts is out of date; run npm run gen:vectors');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
}
