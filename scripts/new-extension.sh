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
  "include": ["src", "test"],
  "exclude": ["test/fixtures"]
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
import { extensionTestConfig } from '../../scripts/vscode-test-config.mjs';

export default await extensionTestConfig('$name');
JS
cat > "$dir/CHANGELOG.md" <<MD
# Changelog

## 0.1.0

- Initial release.
MD
cp LICENSE "$dir/LICENSE"
