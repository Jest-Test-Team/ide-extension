# Changelog

## 0.2.1

- Fix: `ide-ext-ignore` / `ide-ext-ignore-next-line` suppressions now work for rule ids containing `/` (all built-in rules), including those inserted by the *Suppress* quick fix.
- New `ide-ext-ignore-file <rule-id>` directive; CLI `--ignore <glob>` and `.jestignore` support.

## 0.2.0

- Command-line tool `jest-hw` (alias `jest-embedded`: the extension's features in a terminal or CI (text / JSON / SARIF / Markdown output, CI-friendly exit codes). Bundled in the extension — **Install '…' Command in PATH** — and published as `@jest-test-team/security-cli` on npm.

## 0.1.0

- ESP32 / ESP-IDF / ESPHome firmware security linter, including sdkconfig root-of-trust checks.
- NIST SP 800-90B non-IID entropy assessment (validated against NIST ea_non_iid) and restart test.
- PUF quality metrics with an ECC block-failure model.
- ChipWhisperer side-channel tags with cross-language navigation and leak-candidate hints.
