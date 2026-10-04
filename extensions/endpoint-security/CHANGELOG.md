# Changelog

## 0.3.3

- CLI: `jest-endpoint extensions` adds a signal benchmark across all scanned extensions; `jest-security scan` includes the installed-extension risk scan.

## 0.3.2

- Fix: the installed command (`~/.local/bin/…`) is no longer repointed by development hosts or by the same extension in another editor while the existing target still exists; updates within the same editor are still picked up automatically.

## 0.3.1

- Fix: `ide-ext-ignore` / `ide-ext-ignore-next-line` suppressions now work for rule ids containing `/` (all built-in rules), including those inserted by the *Suppress* quick fix.
- New `ide-ext-ignore-file <rule-id>` directive; CLI `--ignore <glob>` and `.jestignore` support.
- `pci/pan-literal` no longer reports test card numbers in unit-test files (`*.test.*`, `*_test.go`, `__tests__/`).

## 0.3.0

- Command-line tool `jest-endpoint`: the extension's features in a terminal or CI (text / JSON / SARIF / Markdown output, CI-friendly exit codes). Bundled in the extension — **Install '…' Command in PATH** — and published as `@jest-test-team/security-cli` on npm.

## 0.2.0

- **Installed extension risk scan:** a new *Installed Extensions* view (shield icon) that scores every installed extension low / medium / high and lists the reasons.
  - Signals come from the manifest (startup activation, untrusted workspaces, look-alike identifiers, VSIX installs), from a code scan of the bundled JavaScript (process execution, dynamic code, literal IPs, exfiltration endpoints, credential paths, clipboard / keystroke capture, obfuscation, native binaries), and from Microsoft's list of removed extensions.
  - Code scanning runs in a worker thread with a per-version cache.
  - Combination-based scoring. You can allowlist extensions, optionally pinned to a version.
  - SARIF / Markdown export.
  - Read-only: nothing is uninstalled or modified.
- Opt-in Marketplace reputation lookup (publisher verification, installs, last update) and an opt-in weekly refresh of the removed-extensions list. Both are off by default.

## 0.1.0

- WFP / ETW / Endpoint Security API database with hover, signature help and completion (C, C++, Objective-C, Rust).
- Lifecycle and misuse diagnostics for engine sessions, ETW sessions/consumers, ES clients and kernel callouts.
- PCI DSS 4.0.1 and CCSP Domain 2 compliance scanning for Go and TypeScript/JavaScript, with SARIF / Markdown export.
- Process-tree scenario simulation (`*.ptree.yaml`) with an ATT&CK-mapped detection library and a data-only local/remote agent.
