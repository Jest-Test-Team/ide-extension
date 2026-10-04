/** Best-effort VS Code language id for files scanned from disk without opening them. */
const BY_EXTENSION: Record<string, string> = {
  c: 'c',
  h: 'c',
  cc: 'cpp',
  cpp: 'cpp',
  cxx: 'cpp',
  hpp: 'cpp',
  hh: 'cpp',
  hxx: 'cpp',
  ino: 'cpp',
  rs: 'rust',
  go: 'go',
  ts: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'typescriptreact',
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'javascriptreact',
  py: 'python',
  jl: 'julia',
  yaml: 'yaml',
  yml: 'yaml',
  json: 'json',
  toml: 'toml',
  md: 'markdown',
};

export function languageIdForPath(path: string): string {
  const name = path.replace(/\\/g, '/').split('/').pop() ?? '';
  if (/^sdkconfig(\.|$)/.test(name)) {
    return 'properties';
  }
  const ext = name.includes('.') ? name.split('.').pop()!.toLowerCase() : '';
  return BY_EXTENSION[ext] ?? 'plaintext';
}

/** Line comment prefix used when inserting suppression directives. */
export function lineCommentFor(languageId: string): string {
  switch (languageId) {
    case 'python':
    case 'julia':
    case 'yaml':
    case 'properties':
    case 'shellscript':
    case 'toml':
      return '#';
    default:
      return '//';
  }
}
