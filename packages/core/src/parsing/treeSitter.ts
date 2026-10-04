import { join } from 'node:path';
import { Language, Parser, Query, type Tree } from 'web-tree-sitter';

/** Grammar wasm file names, keyed by grammar id. Extensions copy these into `dist/grammars`. */
export const GRAMMAR_FILES = {
  c: 'tree-sitter-c.wasm',
  cpp: 'tree-sitter-cpp.wasm',
  rust: 'tree-sitter-rust.wasm',
  go: 'tree-sitter-go.wasm',
  typescript: 'tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-tsx.wasm',
  python: 'tree-sitter-python.wasm',
  julia: 'tree-sitter-julia.wasm',
} as const;

export type GrammarId = keyof typeof GRAMMAR_FILES;

/** VS Code languageId -> grammar. `javascript` reuses the TypeScript grammar, which is a superset. */
const LANGUAGE_TO_GRAMMAR: Record<string, GrammarId> = {
  c: 'c',
  cpp: 'cpp',
  'cuda-cpp': 'cpp',
  objc: 'c',
  rust: 'rust',
  go: 'go',
  typescript: 'typescript',
  javascript: 'typescript',
  typescriptreact: 'tsx',
  javascriptreact: 'tsx',
  python: 'python',
  julia: 'julia',
};

export function grammarForLanguage(languageId: string): GrammarId | undefined {
  return LANGUAGE_TO_GRAMMAR[languageId];
}

/**
 * Lazily loads tree-sitter grammars from a directory containing `tree-sitter.wasm` plus the
 * grammar wasm files, and caches parse trees per (key, version).
 */
export class TreeSitterHost {
  private static initPromise: Promise<void> | undefined;
  private readonly languages = new Map<GrammarId, Promise<Language>>();
  private readonly queries = new Map<string, Query>();
  private readonly trees = new Map<string, { version: number; text: string; tree: Tree }>();

  constructor(private readonly wasmDir: string) {}

  private init(): Promise<void> {
    TreeSitterHost.initPromise ??= Parser.init({
      locateFile: (file: string) => join(this.wasmDir, file),
    });
    return TreeSitterHost.initPromise;
  }

  async language(grammar: GrammarId): Promise<Language> {
    let lang = this.languages.get(grammar);
    if (!lang) {
      lang = this.init().then(() => Language.load(join(this.wasmDir, GRAMMAR_FILES[grammar])));
      this.languages.set(grammar, lang);
    }
    return lang;
  }

  /** Compiles (and caches) a query. Throws with the grammar id in the message on syntax errors. */
  async query(grammar: GrammarId, source: string): Promise<Query> {
    const key = `${grammar}\u0000${source}`;
    let q = this.queries.get(key);
    if (!q) {
      const lang = await this.language(grammar);
      try {
        q = new Query(lang, source);
      } catch (err) {
        throw new Error(`Invalid ${grammar} query: ${(err as Error).message}\n${source}`);
      }
      this.queries.set(key, q);
    }
    return q;
  }

  /**
   * Parses `text`. When `cacheKey` is given, a tree for the same key, version and text is reused and
   * the previous tree for that key is freed. Comparing text guards against callers (such as
   * workspace scans of files on disk) that cannot supply a meaningful version.
   */
  async parse(grammar: GrammarId, text: string, cacheKey?: string, version = 0): Promise<Tree> {
    if (cacheKey) {
      const hit = this.trees.get(cacheKey);
      if (hit && hit.version === version && hit.text === text) {
        return hit.tree;
      }
      hit?.tree.delete();
    }
    const language = await this.language(grammar); // also completes Parser.init()
    const parser = new Parser();
    try {
      parser.setLanguage(language);
      const tree = parser.parse(text);
      if (!tree) {
        throw new Error(`tree-sitter failed to parse ${cacheKey ?? 'document'}`);
      }
      if (cacheKey) {
        this.trees.set(cacheKey, { version, text, tree });
      }
      return tree;
    } finally {
      parser.delete();
    }
  }

  forget(cacheKey: string): void {
    this.trees.get(cacheKey)?.tree.delete();
    this.trees.delete(cacheKey);
  }

  dispose(): void {
    for (const { tree } of this.trees.values()) {
      tree.delete();
    }
    this.trees.clear();
    for (const q of this.queries.values()) {
      q.delete();
    }
    this.queries.clear();
  }
}
