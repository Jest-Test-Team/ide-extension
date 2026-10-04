// Bundles the jest-* CLIs into dist/ with the runtime data they need (grammars, rule packs, scripts).
import * as esbuild from 'esbuild';
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');
const pkg = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));
const dist = join(here, 'dist');
const bins = ['jest-endpoint', 'jest-hw', 'jest-julia', 'jest-security'].filter((b) => existsSync(join(here, 'src', 'bin', `${b}.ts`)));

rmSync(dist, { recursive: true, force: true });
await esbuild.build({
  entryPoints: Object.fromEntries(bins.map((b) => [b, join(here, 'src', 'bin', `${b}.ts`)])),
  outdir: dist,
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  minify: process.argv.includes('--production'),
  logLevel: 'info',
  define: { 'import.meta.url': '__import_meta_url', __CLI_VERSION__: JSON.stringify(pkg.version) },
  banner: { js: "#!/usr/bin/env node\nconst __import_meta_url = require('url').pathToFileURL(__filename).href;" },
});
for (const b of bins) {
  chmodSync(join(dist, `${b}.js`), 0o755);
}

const nm = join(repo, 'node_modules');
mkdirSync(join(dist, 'grammars'), { recursive: true });
cpSync(join(nm, 'web-tree-sitter', 'tree-sitter.wasm'), join(dist, 'grammars', 'tree-sitter.wasm'));
for (const [mod, files] of Object.entries({
  'tree-sitter-c': ['tree-sitter-c.wasm'],
  'tree-sitter-cpp': ['tree-sitter-cpp.wasm'],
  'tree-sitter-rust': ['tree-sitter-rust.wasm'],
  'tree-sitter-go': ['tree-sitter-go.wasm'],
  'tree-sitter-typescript': ['tree-sitter-typescript.wasm', 'tree-sitter-tsx.wasm'],
  'tree-sitter-python': ['tree-sitter-python.wasm'],
  'tree-sitter-julia': ['tree-sitter-julia.wasm'],
})) {
  for (const f of files) {
    cpSync(join(nm, mod, f), join(dist, 'grammars', f));
  }
}
const data = {
  rules: 'extensions/endpoint-security/data/rules',
  ptree: 'extensions/endpoint-security/data/ptree',
  extscan: 'extensions/endpoint-security/data/extscan',
  scripts: 'extensions/julia-profiler/scripts',
};
for (const [to, from] of Object.entries(data)) {
  cpSync(join(repo, from), join(dist, to), { recursive: true });
}
