import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { GRAMMAR_FILES } from '@ide-ext/core';

/** Runtime data the CLIs need; each lives in a folder of that name next to (or above) the bundle. */
export type AssetKind = 'grammars' | 'rules' | 'ptree' | 'extscan' | 'scripts' | 'runtime';

// When running from source (tests, ts-node) the data still lives in the extension folders.
const REPO = resolve(__dirname, '..', '..', '..', '..');
const SOURCE: Record<Exclude<AssetKind, 'grammars'>, string> = {
  rules: join(REPO, 'extensions/endpoint-security/data/rules'),
  ptree: join(REPO, 'extensions/endpoint-security/data/ptree'),
  extscan: join(REPO, 'extensions/endpoint-security/data/extscan'),
  scripts: join(REPO, 'extensions/julia-profiler/scripts'),
  runtime: join(REPO, 'packages/cli/runtime'),
};

const PROBE: Record<AssetKind, string> = {
  grammars: 'tree-sitter.wasm',
  rules: 'pci-dss-4.0.1.yaml',
  ptree: 'default-rules.yaml',
  extscan: 'popular-extensions.json',
  scripts: 'collect.jl',
  runtime: 'audit-agent.cjs',
};

export function assetDir(kind: AssetKind): string {
  const roots = [process.env.JEST_ASSETS, __dirname, dirname(__dirname)].filter((x): x is string => !!x);
  for (const root of roots) {
    if (existsSync(join(root, kind, PROBE[kind]))) {
      return join(root, kind);
    }
  }
  if (kind === 'grammars') {
    return devGrammars();
  }
  if (existsSync(join(SOURCE[kind], PROBE[kind]))) {
    return SOURCE[kind];
  }
  throw new Error(`cannot find the "${kind}" data folder; set JEST_ASSETS to the directory that contains it`);
}

/** Source checkout: assemble the grammar folder from node_modules (as the extension build does). */
function devGrammars(): string {
  const dir = join(tmpdir(), 'jest-cli-dev-grammars');
  mkdirSync(dir, { recursive: true });
  const nm = join(REPO, 'node_modules');
  const files: Record<string, string> = { 'tree-sitter.wasm': join(nm, 'web-tree-sitter', 'tree-sitter.wasm') };
  for (const [id, file] of Object.entries(GRAMMAR_FILES)) {
    files[file] = join(nm, id === 'tsx' ? 'tree-sitter-typescript' : `tree-sitter-${id}`, file);
  }
  for (const [file, from] of Object.entries(files)) {
    if (!existsSync(join(dir, file))) {
      if (!existsSync(from)) {
        throw new Error(`grammar ${file} not found; run npm install or set JEST_ASSETS`);
      }
      copyFileSync(from, join(dir, file));
    }
  }
  return dir;
}
