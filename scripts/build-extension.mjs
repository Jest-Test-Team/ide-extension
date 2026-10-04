// Shared esbuild driver for every extension in this monorepo.
// Usage (from an extension folder): node ../../scripts/build-extension.mjs [--watch] [--production]
import * as esbuild from 'esbuild';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const cwd = process.cwd();
const watch = process.argv.includes('--watch');
const production = process.argv.includes('--production');
const pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8'));
const cfg = pkg['x-build'] ?? {};

/** Node-side bundles: the extension host entry plus any worker / agent entries. */
const nodeEntries = { extension: 'src/extension.ts', ...(cfg.nodeEntries ?? {}) };
/** Browser-side bundles loaded inside webviews. */
const webEntries = cfg.webEntries ?? {};

const common = {
  bundle: true,
  minify: production,
  sourcemap: !production,
  sourcesContent: false,
  logLevel: 'info',
};

/**
 * Locates an installed package by walking up node_modules folders. Unlike require.resolve this
 * works for packages whose "exports" map hides package.json.
 */
function findPackageDir(name) {
  for (let dir = cwd; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', name);
    if (existsSync(join(candidate, 'package.json'))) {
      return candidate;
    }
    if (dirname(dir) === dir) {
      throw new Error(`build: package not installed: ${name}`);
    }
  }
}

/** Copies runtime assets (tree-sitter wasm grammars, static media) into dist/. */
function copyAssets() {
  mkdirSync(join(cwd, 'dist'), { recursive: true });
  for (const spec of cfg.copy ?? []) {
    // spec: "pkg:<module>/<path>" resolves inside node_modules, otherwise relative to the extension.
    let from;
    if (spec.from.startsWith('pkg:')) {
      const [mod, ...rest] = spec.from.slice(4).split('/');
      const scoped = mod.startsWith('@') ? `${mod}/${rest.shift()}` : mod;
      from = join(findPackageDir(scoped), ...rest);
    } else {
      from = resolve(cwd, spec.from);
    }
    if (!existsSync(from)) {
      throw new Error(`build: asset not found: ${spec.from} (${from})`);
    }
    cpSync(from, join(cwd, 'dist', spec.to), { recursive: true });
  }
}

// Start from a clean dist/ so stale bundles or source maps never end up in a .vsix.
rmSync(join(cwd, 'dist'), { recursive: true, force: true });

const contexts = await Promise.all([
  esbuild.context({
    ...common,
    entryPoints: nodeEntries,
    outdir: 'dist',
    format: 'cjs',
    platform: 'node',
    target: 'node20',
    external: ['vscode'],
    // ESM dependencies (e.g. web-tree-sitter) call createRequire(import.meta.url), which is empty
    // in a CJS bundle; point it at the bundle file instead.
    define: { 'import.meta.url': '__import_meta_url', __CLI_VERSION__: JSON.stringify(pkg.version) },
    banner: { js: "const __import_meta_url = require('url').pathToFileURL(__filename).href;" },
  }),
  ...(Object.keys(webEntries).length
    ? [
        esbuild.context({
          ...common,
          entryPoints: webEntries,
          outdir: 'dist/web',
          format: 'iife',
          platform: 'browser',
          target: 'es2022',
        }),
      ]
    : []),
]);

copyAssets();
if (watch) {
  await Promise.all(contexts.map((c) => c.watch()));
} else {
  await Promise.all(contexts.map((c) => c.rebuild()));
  await Promise.all(contexts.map((c) => c.dispose()));
}
