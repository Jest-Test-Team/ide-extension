# Changelog

## 0.2.3

- `jest-security scan` is now a full audit: code findings plus the installed-extension risk scan (ranking, reasons with file:line, signal benchmark), printed as a report and written to one SARIF file with two runs.

## 0.2.2

- Fix: the installed command (`~/.local/bin/…`) is no longer repointed by development hosts or by the same extension in another editor while the existing target still exists; updates within the same editor are still picked up automatically.

## 0.2.1

- Fix: `ide-ext-ignore` / `ide-ext-ignore-next-line` suppressions now work for rule ids containing `/` (all built-in rules), including those inserted by the *Suppress* quick fix.
- New `ide-ext-ignore-file <rule-id>` directive; CLI `--ignore <glob>` and `.jestignore` support.

## 0.2.0

- Command-line tool `jest-security`: the extension's features in a terminal or CI (text / JSON / SARIF / Markdown output, CI-friendly exit codes). Bundled in the extension — **Install '…' Command in PATH** — and published as `@jest-test-team/security-cli` on npm.

## 0.1.0

- Initial release.
