# ide-extension

Three VS Code extensions for security and systems engineering, plus an extension pack:

| Extension | Folder | What it does |
|---|---|---|
| **Endpoint Security & Compliance Toolkit** | [`extensions/endpoint-security`](extensions/endpoint-security/README.md) | WFP / ETW / Endpoint Security API hover + validation, PCI DSS 4.0.1 & CCSP D2 compliance scan with SARIF export, process-tree detection simulation |
| **Julia Invalidation & Compiler Profiler** | [`extensions/julia-profiler`](extensions/julia-profiler/README.md) | SnoopCompile.jl invalidation tree & inference flame graph, invalidation linter, benchmark judge vs. git baseline |
| **Embedded Hardware Security Workbench** | [`extensions/hw-security`](extensions/hw-security/README.md) | ESP32/ESPHome security linter, NIST SP 800-90B entropy & restart tests, PUF metrics, ChipWhisperer side-channel tags |
| Security & Systems Engineering Pack | `extensions/security-pack` | Installs all three |

Shared code lives in [`packages/core`](packages/core): a web-tree-sitter host, the declarative rule engine (tree-sitter queries, regex/absent rules and code rules — every rule cites its sources), diagnostics with quick fixes and suppressions, SARIF/Markdown reports, and webview helpers. Each extension bundles it with esbuild.

## Development

```bash
npm install
npm run build              # bundle every extension (dist/)
npm run typecheck && npm run lint
npm test                   # vitest unit + webview DOM tests
npm run test:integration   # @vscode/test-cli in a downloaded VS Code (xvfb-run on Linux)
npm run package            # vsix/*.vsix
```

Press **F5** in VS Code and choose *Run Endpoint Security*, *Run Julia Profiler* or *Run HW Security* to open an Extension Development Host. The host opens on that extension's `test/fixtures`.

## install 
```bash
code --install-extension vsix/endpoint-security-0.1.0.vsix
code --install-extension vsix/julia-profiler-0.1.0.vsix
code --install-extension vsix/hw-security-0.1.0.vsix
code --install-extension vsix/security-pack-0.1.0.vsix   # optional
```

### Tests that need external tools

| Env var | Enables |
|---|---|
| `JULIA_PROFILER_TEST_JULIA=/path/to/julia` | integration tests that run SnoopCompile and BenchmarkTools for real |
| `NIST_EA_NON_IID=/path/to/ea_non_iid` | regenerates `extensions/hw-security/test/fixtures/entropy/nist-reference.json` |
| `NIST_EA_RESTART=/path/to/ea_restart` | regenerates the restart-test reference |

The committed NIST reference values come from [usnistgov/SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment). The TypeScript estimators must match them to 1e-9.

## Releasing

1. Create the Marketplace publisher `jest-test-team` at <https://marketplace.visualstudio.com/manage>, or change `publisher` in each `extensions/*/package.json` and the pack's `extensionPack` ids.
2. In Azure DevOps, create a Personal Access Token: organisation **All accessible organizations**, scope **Marketplace → Manage**.
3. Add it as the repository secret `VSCE_PAT`. Optionally add `OVSX_PAT` for Open VSX.
4. Bump versions and changelogs, then tag the release: `git tag v0.1.0 && git push --tags`. [`release.yml`](.github/workflows/release.yml) tests, packages and publishes the extensions in dependency order, and attaches the `.vsix` files to a GitHub release.

To publish manually instead, run `npx vsce login jest-test-team`, then `npm run package`, then `npx vsce publish --packagePath vsix/<file>.vsix`.
