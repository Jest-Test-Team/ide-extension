# Security & Systems Engineering Pack

Installs the Endpoint Security & Compliance Toolkit, the Julia Invalidation & Compiler Profiler and the Embedded Hardware Security Workbench together.

## Install

Requires VS Code 1.90.0 or newer (compatible with `engines.vscode` `^1.90.0`).

Once published on the Visual Studio Marketplace, this extension will be installable with `code --install-extension jest-test-team.security-pack` or by searching for `Security & Systems Engineering Pack` in the VS Code Extensions view. Until then, the currently available path is to build from source and use **Install from VSIX…** in VS Code (see the repo root README for the developer path).
Once published on the Visual Studio Marketplace, installing the Pack would also install endpoint-security, julia-profiler, and hw-security. Currently, install manually from VSIX files: install those three extensions first, then the Pack (see the repo root README for the developer build path).


## Command line

**Security Pack: Install 'jest-security' Command in PATH** adds one command for all three tools:

```bash
jest-security scan                          # full audit: code + installed extensions → report + security.sarif
jest-security scan-extension                # installed extensions only: discover, scan, analyse → report + security.sarif
jest-security lint src firmware --format md
jest-security endpoint simulate attack.ptree.yaml
jest-security hw entropy trng.bin --bits 8
jest-security julia report profile.json
jest-security doctor                        # check data files, julia and git
```

The same tools are on npm as `@jest-test-team/security-cli`, which provides `jest-security`, `jest-endpoint`, `jest-hw` and `jest-julia`.
