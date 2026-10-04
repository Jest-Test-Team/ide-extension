import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { GRAMMAR_FILES, TreeSitterHost } from '../src/parsing/treeSitter';

/** Mirrors the `dist/grammars` layout from node_modules so tests can load real grammars. */
export function grammarDir(): string {
  const dir = join(tmpdir(), 'ide-ext-test-grammars');
  mkdirSync(dir, { recursive: true });
  const root = resolve(__dirname, '../../..', 'node_modules');
  const sources: Record<string, string> = { 'tree-sitter.wasm': join(root, 'web-tree-sitter', 'tree-sitter.wasm') };
  for (const [id, file] of Object.entries(GRAMMAR_FILES)) {
    const pkg = id === 'tsx' ? 'tree-sitter-typescript' : `tree-sitter-${id}`;
    sources[file] = join(root, pkg, file);
  }
  for (const [file, from] of Object.entries(sources)) {
    const to = join(dir, file);
    if (!existsSync(to)) {
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(from, to);
    }
  }
  return dir;
}

let host: TreeSitterHost | undefined;
export function testHost(): TreeSitterHost {
  host ??= new TreeSitterHost(grammarDir());
  return host;
}
