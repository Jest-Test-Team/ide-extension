# Changelog

## 0.2.1

- Fix: `ide-ext-ignore` / `ide-ext-ignore-next-line` suppressions now work for rule ids containing `/` (all built-in rules), including those inserted by the *Suppress* quick fix.
- New `ide-ext-ignore-file <rule-id>` directive; CLI `--ignore <glob>` and `.jestignore` support.
- Bundled Julia scripts are lint-clean (`const` globals).

## 0.2.0

- Command-line tool `jest-julia`: the extension's features in a terminal or CI (text / JSON / SARIF / Markdown output, CI-friendly exit codes). Bundled in the extension — **Install '…' Command in PATH** — and published as `@jest-test-team/security-cli` on npm.

## 0.1.0

- SnoopCompile-based invalidation and inference profiling in a private tool environment.
- Invalidations tree view, inference flame graph and inference-trigger report.
- Invalidation-oriented linter with quick fixes and diagnostics backed by the recorded profile.
- Benchmark comparison against a git baseline, plus an AirspeedVelocity.jl workflow generator.
