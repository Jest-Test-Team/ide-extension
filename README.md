# ide-extension

Monorepo for three VS Code extensions focused on security and systems engineering:

| Extension | Folder | Summary |
|---|---|---|
| Endpoint Security & Compliance Toolkit | `extensions/endpoint-security` | WFP / ETW / Endpoint Security API validation, PCI DSS 4.0.1 & CCSP D2 compliance scan, process-tree simulation |
| Julia Invalidation & Compiler Profiler | `extensions/julia-profiler` | SnoopCompile.jl invalidation / inference visualisation, refactoring linter, benchmark judge |
| Embedded Hardware Security Workbench | `extensions/hw-security` | ESP32 firmware linter, NIST SP 800-90B entropy & PUF metrics, ChipWhisperer side-channel tags |

Shared logic lives in `packages/core` and is bundled into each extension with esbuild.

## Development

```bash
npm install
npm run build        # bundle every extension
npm test             # unit tests (vitest)
npm run package      # produce .vsix files
```

Open the repo in VS Code and press **F5**, then pick an extension's launch configuration to start an Extension Development Host.
