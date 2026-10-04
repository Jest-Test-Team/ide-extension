#!/usr/bin/env bash
# Scaffolds an extension folder equivalent to `yo code` (TypeScript + esbuild) wired into this monorepo.
set -euo pipefail
name="$1"
dir="extensions/$name"
mkdir -p "$dir/src" "$dir/test/unit" "$dir/test/integration" "$dir/test/fixtures" "$dir/media"
cat > "$dir/tsconfig.json" <<JSON
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "types": ["node", "vscode", "mocha"] },
  "include": ["src", "test"]
}
JSON
cat > "$dir/.vscodeignore" <<IGN
**
!dist/**
!media/**
!package.json
!README.md
!CHANGELOG.md
!LICENSE
!icon.png
dist/**/*.map
IGN
cat > "$dir/.vscode-test.mjs" <<JS
import { defineConfig } from '@vscode/test-cli';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  workspaceFolder: './test/fixtures',
  // The default user-data-dir inside the repo yields an IPC socket path longer than macOS allows.
  launchArgs: ['--user-data-dir', join(tmpdir(), 'vsct-$name'), '--disable-extensions'],
  mocha: { timeout: 60000 },
});
JS
cat > "$dir/CHANGELOG.md" <<MD
# Changelog

## 0.1.0

- Initial release.
MD
cp LICENSE "$dir/LICENSE"
