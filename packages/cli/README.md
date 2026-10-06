# @jest-test-team/security-cli

Command-line versions of the Jest-Test-Team VS Code extensions. Use them for CI, servers and scripts.

| Command | Extension |
|---|---|
| `jest-endpoint` | Endpoint Security & Compliance Toolkit |
| `jest-hw` (alias `jest-embedded`) | Embedded Hardware Security Workbench |
| `jest-julia` | Julia Invalidation & Compiler Profiler |
| `jest-security` | Security & Systems Engineering Pack: every rule set at once, plus `endpoint` / `hw` / `julia` sub-tools |

## Install

```bash
npm i -g @jest-test-team/security-cli   # Node.js 20+
```

Each VS Code extension also bundles its own command; run **Install '<tool>' Command in PATH** from the Command Palette. That copy needs no Node.js: it runs on the editor's runtime when `node` isn't on PATH.

## Output and exit codes

- Lint-style commands print an eslint-like report, or use `--format json|sarif|md` and `--out <file>`.
- SARIF uploads directly to GitHub code scanning.
- `0`: clean or passed.
- `1`: findings at or above `--fail-on` (default `error`), a failed test (`restart`, `simulate --expect`) or a threshold (`entropy --min`, `analyze --max-invalidated`, `bench` regressions).
- `2`: usage or runtime error.
- Colour is used only on a terminal; `NO_COLOR` disables it.

## GitHub Actions example

```yaml
- run: npm i -g @jest-test-team/security-cli
- run: jest-security scan . --no-extensions --out security.sarif --fail-on none   # CI runners have no editor extensions
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security.sarif
```

## Extension guard: block risky extensions in pull requests

`jest-security scan-manifest` checks the extension lists committed to a repository:
- `.vscode/extensions.json` recommendations
- dev container `customizations.vscode.extensions`
- `*.code-workspace` files
- a committed VS Code profile `extensions.json`, or `code --list-extensions --show-versions` output, when you name the file

For each extension a change **adds or re-versions**, it:
1. downloads the package from the VS Marketplace (or Open VSX);
2. checks the registry's published SHA-256;
3. unpacks it defensively (nothing runs);
4. scans it with the same engine as `scan-extension`.

Extensions that can no longer be downloaded are still judged by their identifier: Microsoft's list of removed extensions, look-alike names, and "not on the registry". This catches an extension that was already taken down for malware.

### GitHub Action

```yaml
# .github/workflows/extension-guard.yml — full example: docs/ci/extension-guard.yml
on:
  pull_request:
    paths: ['**/.vscode/extensions.json', '**/devcontainer.json', '**/.devcontainer.json', '**/*.code-workspace']
permissions:
  contents: read
  pull-requests: write     # summary comment
  security-events: write   # SARIF upload
jobs:
  extensions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Jest-Test-Team/ide-extension@v1
```

On a pull request the action:
- compares the branch with its base and scans only added or version-changed extensions;
- writes a risk table to the job summary and keeps one PR comment up to date;
- annotates the manifest line that adds a risky extension;
- uploads SARIF to code scanning (private repositories need GitHub Advanced Security; without it the step is skipped);
- **fails the check** when an extension reaches `fail-on` (default `high`) or breaks the policy.

Add a weekly `schedule` run with `base: none` as well: an extension approved months ago can be listed as malware today.

Inputs:

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | policy, else `high` | Risk level that fails the check (`high`, `medium`, `none`) |
| `policy` | `.github/jest-security.yml` | Policy file (see below) |
| `manifests` | auto-discover | Files or folders, separated by spaces or new lines |
| `base` | PR base / previous push | `none` scans everything |
| `scan-all` | `false` | Also scan unchanged extensions |
| `registry`, `registry-url` | `marketplace` | `open-vsx`, or a private mirror |
| `target-platform` | `linux-x64` | Which build of platform-specific extensions to scan |
| `comment`, `sarif` | `true` | PR comment, code scanning upload |
| `fail-on-incomplete` | `true` | Fail when a package could not be downloaded |
| `version` | pinned | CLI version (`source` builds it from the action checkout) |

Outputs: `exit-code`, `scanned`, `high`, `medium`, `sarif-file`, `summary-file`.

### Policy file

```yaml
# .github/jest-security.yml
fail-on: high                     # or medium / none
allowlist:                        # reasons are still listed, but not scored
  - ms-python.python
  - acme.internal-tools@2.4.1     # this version only; an update is scored again
blocked:
  - some-publisher.*              # a whole publisher
  - bad.extension
allowed-publishers: []            # when set, only these publishers may be added
require-verified-publisher: false # require a Marketplace-verified domain
trusted-publishers: [acme]        # count as well known in the scoring
```

Unknown keys are errors, so a typo cannot quietly weaken the policy.

### Other CI systems

```bash
npx --yes --package=@jest-test-team/security-cli jest-security scan-manifest \
  --base "$TARGET_BRANCH_SHA" --out extensions.sarif --summary summary.md
# exit 0 = pass, 1 = blocked, 2 = some extensions could not be scanned (or wrong usage)
```

In GitLab CI use `$CI_MERGE_REQUEST_DIFF_BASE_SHA`; in Azure Pipelines use `origin/$(System.PullRequest.TargetBranch)`. The base revision needs to be fetched, but only that one commit: `git fetch --depth=1 origin <sha>`.

### Privacy and limits

- The registry is contacted to resolve and download packages, and for publisher reputation (`--no-online` turns reputation off). Only extension identifiers are sent, which the repository lists publicly to its readers anyway.
- `.vscode/extensions.json` has no versions, so CI scans the version a teammate would install **today**. Pin versions in dev containers (`publisher.name@1.2.3`) to gate exact builds.
- The scan is heuristic. It reports risk signals and their reasons; it is not a verdict.

## Reference

This section is generated from `--help`.

### jest-endpoint

```text
jest-endpoint 0.1.4 — Endpoint Security & Compliance Toolkit

Usage: jest-endpoint <command> [options]

Commands:
  lint        Validate WFP/ETW/Endpoint Security API usage (C, C++, Rust) and scan Go/TS/JS for PCI DSS 4.0.1 and CCSP D2 issues
  compliance  PCI DSS 4.0.1 / CCSP Domain 2 compliance scan (shortcut for lint --only compliance)
  simulate    Replay a *.ptree.yaml process-tree scenario against detection rules (data only, nothing is executed)
  api         Show the signature, semantics and docs of a WFP / ETW / Endpoint Security function or constant
  agent       Run the process-tree simulation agent (JSON-RPC over stdio, or HTTP with --http)
  extensions  Risk-scan installed VS Code / Cursor / VSCodium extensions on disk (heuristic, read-only)

Run "jest-endpoint <command> --help" for command options.

Exit codes: 0 = clean, 1 = findings at/above --fail-on (or failed expectation), 2 = usage or runtime error.
```

<details><summary><code>jest-endpoint lint</code></summary>

```text
Usage: jest-endpoint lint [paths…] [options]

Validate WFP/ETW/Endpoint Security API usage (C, C++, Rust) and scan Go/TS/JS for PCI DSS 4.0.1 and CCSP D2 issues

Options:
      --only <api|compliance|all>               Rule group to run (default: all)
  -f, --format <text|json|sarif|md>             Output format (default: text)
  -o, --out <file>                              Write the report to a file instead of stdout
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help                                    Show this help

Examples:
  jest-endpoint lint src/
  jest-endpoint lint --only api agent/ --format json
  jest-endpoint lint . --fail-on warning
```

</details>

<details><summary><code>jest-endpoint compliance</code></summary>

```text
Usage: jest-endpoint compliance [paths…] [options]

PCI DSS 4.0.1 / CCSP Domain 2 compliance scan (shortcut for lint --only compliance)

Options:
  -f, --format <text|json|sarif|md>             Output format (default: text)
  -o, --out <file>                              Write the report to a file instead of stdout
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help                                    Show this help

Examples:
  jest-endpoint compliance services/ --format sarif --out compliance.sarif
  jest-endpoint compliance . --format md --out report.md
```

</details>

<details><summary><code>jest-endpoint simulate</code></summary>

```text
Usage: jest-endpoint simulate <scenario.ptree.yaml> [options]

Replay a *.ptree.yaml process-tree scenario against detection rules (data only, nothing is executed)

Options:
      --rules <rules.yaml>  Additional rules file (repeatable)
      --default-rules       Include the built-in ATT&CK-mapped rules (use --no-default-rules to disable)
      --expect <rule-id>    Exit 1 unless this rule fires (detection regression tests) (repeatable)
      --json                Print the full result as JSON
  -o, --out <file>          Write the report to a file instead of stdout
  -h, --help                Show this help

Examples:
  jest-endpoint simulate scenarios/ransom.ptree.yaml
  jest-endpoint simulate s.ptree.yaml --rules team.yaml --expect mass-file-encryption
```

</details>

<details><summary><code>jest-endpoint api</code></summary>

```text
Usage: jest-endpoint api <name> [options]

Show the signature, semantics and docs of a WFP / ETW / Endpoint Security function or constant

Options:
      --list  List every known function and constant
  -h, --help  Show this help

Examples:
  jest-endpoint api FwpmEngineOpen0
  jest-endpoint api es_ --list
```

</details>

<details><summary><code>jest-endpoint agent</code></summary>

```text
Usage: jest-endpoint agent [options]

Run the process-tree simulation agent (JSON-RPC over stdio, or HTTP with --http)

Options:
      --http <port>  Serve JSON-RPC over HTTP POST on this port
      --host <addr>  Bind address for --http (use 0.0.0.0 inside a sandbox VM) (default: 127.0.0.1)
  -h, --help         Show this help

Examples:
  jest-endpoint agent --http 8765
  jest-endpoint agent --http 8765 --host 0.0.0.0
```

</details>

<details><summary><code>jest-endpoint extensions</code></summary>

```text
Usage: jest-endpoint extensions [extensions folders or single extension folders…] [options]

Risk-scan installed VS Code / Cursor / VSCodium extensions on disk (heuristic, read-only)

Options:
  -f, --format <text|json|sarif|md>           Output format (default: text)
  -o, --out <file>                            Write the report to a file instead of stdout
      --allowlist <publisher.name[@version]>  Trust these extensions (repeatable)
      --trusted-publisher <publisher>         Treat this publisher as known (repeatable)
      --node-modules                          Also scan bundled node_modules (--no-node-modules to skip)
      --max-files <number>                    Maximum JavaScript files scanned per extension (default: 2000)
      --fail-on <high|medium|none>            Exit 1 when an extension reaches this level (default: high)
      --details                               List the reasons for every extension, including low risk (automatic for ≤ 3 extensions)
  -h, --help                                  Show this help

Examples:
  jest-endpoint extensions
  jest-endpoint extensions ~/.vscode/extensions/ash-blade.postgresql-hacker-helper-1.18.0   # one extension
  jest-endpoint extensions ~/.cursor/extensions --format sarif --out ext.sarif
  jest-endpoint extensions --allowlist ms-python.python --fail-on medium
```

</details>

### jest-hw

```text
jest-hw 0.1.4 — Embedded Hardware Security Workbench (alias: jest-embedded)

Usage: jest-hw <command> [options]

Commands:
  lint     Lint ESP32 / ESP-IDF C/C++, sdkconfig and ESPHome YAML for firmware security issues
  entropy  NIST SP 800-90B non-IID min-entropy assessment of noise-source samples (.bin: one sample per byte; text: integers)
  restart  SP 800-90B 3.1.4 restart test: validate an entropy claim H_I from restart data (rows × cols, row-major)
  puf      PUF quality metrics from a CSV of responses (device,read,response — 0/1 or hex) with an ECC requirement
  sca      List ChipWhisperer side-channel points: @sca(id, "…") tags in firmware and @sca-ref(id) in analysis scripts

Run "jest-hw <command> --help" for command options.

Exit codes: 0 = clean / passed, 1 = findings, failed test or threshold, 2 = usage or runtime error.
```

<details><summary><code>jest-hw lint</code></summary>

```text
Usage: jest-hw lint [paths…] [options]

Lint ESP32 / ESP-IDF C/C++, sdkconfig and ESPHome YAML for firmware security issues

Options:
  -f, --format <text|json|sarif|md>             Output format (default: text)
  -o, --out <file>                              Write the report to a file instead of stdout
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help                                    Show this help

Examples:
  jest-hw lint firmware/
  jest-hw lint . --format sarif --out hw.sarif
  jest-hw lint sdkconfig --fail-on warning
```

</details>

<details><summary><code>jest-hw entropy</code></summary>

```text
Usage: jest-hw entropy <samples> [options]

NIST SP 800-90B non-IID min-entropy assessment of noise-source samples (.bin: one sample per byte; text: integers)

Options:
  -b, --bits <number>  Bits per sample, 1–8 (0 = infer from the data) (default: 0)
      --all-bits       Use the whole bitstring instead of the first 1,000,000 bits
      --min <bits>     Exit 1 if the assessed min-entropy per sample is below this value
      --json           Print the result as JSON
  -o, --out <file>     Write the report to a file instead of stdout
  -h, --help           Show this help

Examples:
  jest-hw entropy trng.bin --bits 8
  jest-hw entropy raw.bin -b 4 --min 3.2 --json
```

</details>

<details><summary><code>jest-hw restart</code></summary>

```text
Usage: jest-hw restart <restart.bin> [options]

SP 800-90B 3.1.4 restart test: validate an entropy claim H_I from restart data (rows × cols, row-major)

Options:
      --hi <number>      Initial entropy estimate H_I to validate (bits/sample)
  -b, --bits <number>    Bits per sample (0 = infer) (default: 0)
      --rows <number>    Restarts (= samples per restart; the matrix is square) (default: 1000)
      --rounds <number>  Monte-Carlo rounds for the sanity-check cutoff (NIST: 5,000,000) (default: 200000)
      --json             Print the result as JSON
  -o, --out <file>       Write the report to a file instead of stdout
  -h, --help             Show this help

Examples:
  jest-hw restart restarts.bin --hi 6.5 --bits 8
```

</details>

<details><summary><code>jest-hw puf</code></summary>

```text
Usage: jest-hw puf <responses.csv> [options]

PUF quality metrics from a CSV of responses (device,read,response — 0/1 or hex) with an ECC requirement

Options:
      --ecc-bits <number>       ECC block length n (default: 255)
      --target <number>         Target key-reconstruction failure rate per block (default: 0.000001)
      --min-reliability <0..1>  Exit 1 if reliability is below this
      --json                    Print the result as JSON
  -o, --out <file>              Write the report to a file instead of stdout
  -h, --help                    Show this help

Examples:
  jest-hw puf sram.csv
  jest-hw puf sram.csv --ecc-bits 127 --target 1e-9 --json
```

</details>

<details><summary><code>jest-hw sca</code></summary>

```text
Usage: jest-hw sca [paths…] [options]

List ChipWhisperer side-channel points: @sca(id, "…") tags in firmware and @sca-ref(id) in analysis scripts

Options:
      --json           Print the result as JSON
  -o, --out <file>     Write the report to a file instead of stdout
      --ignore <glob>  Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file    Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help           Show this help

Examples:
  jest-hw sca firmware/ analysis/
  jest-hw sca . --json
```

</details>

### jest-julia

```text
jest-julia 0.1.4 — Julia Invalidation & Compiler Profiler

Usage: jest-julia <command> [options]

Commands:
  lint     Lint Julia code for invalidation / inference problems (abstract fields, non-const globals, piracy…)
  analyze  Record invalidations (@snoop_invalidations) and inference (@snoop_inference) with SnoopCompile.jl
  report   Summarise a profile JSON written by `jest-julia analyze` or the VS Code extension
  bench    Run benchmark/benchmarks.jl on a git baseline (temporary worktree) and the working tree, then judge
  init     Create snoop/workload.jl, benchmark/benchmarks.jl or a GitHub Actions benchmark workflow

Run "jest-julia <command> --help" for command options.

Julia is located via --julia, $JULIA, PATH or ~/.juliaup. SnoopCompile / BenchmarkTools are installed into a private cache environment; your Project.toml is not modified.
```

<details><summary><code>jest-julia lint</code></summary>

```text
Usage: jest-julia lint [paths…] [options]

Lint Julia code for invalidation / inference problems (abstract fields, non-const globals, piracy…)

Options:
      --profile <profile.json>                  Also report methods / call sites recorded in a SnoopCompile profile (from `jest-julia analyze`)
      --threshold <number>                      Recorded invalidations at or above this count are warnings (default: 10)
  -f, --format <text|json|sarif|md>             Output format (default: text)
  -o, --out <file>                              Write the report to a file instead of stdout
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help                                    Show this help

Examples:
  jest-julia lint src/
  jest-julia lint . --profile julia-profile.json --format sarif --out julia.sarif
```

</details>

<details><summary><code>jest-julia analyze</code></summary>

```text
Usage: jest-julia analyze [project dir] [options]

Record invalidations (@snoop_invalidations) and inference (@snoop_inference) with SnoopCompile.jl

Options:
      --workload <file.jl>        Workload run under @snoop_inference (default: snoop/workload.jl if present)
      --julia <path>              Julia executable
  -o, --out <file>                Where to write the profile JSON (default: julia-profile.json)
      --timeout <minutes>         Abort after this many minutes (default: 30)
      --max-invalidated <number>  Exit 1 if more MethodInstances are invalidated
  -h, --help                      Show this help

Examples:
  jest-julia analyze
  jest-julia analyze MyPkg --workload snoop/workload.jl --out profile.json
  jest-julia analyze --max-invalidated 0   # CI gate
```

</details>

<details><summary><code>jest-julia report</code></summary>

```text
Usage: jest-julia report <profile.json> [options]

Summarise a profile JSON written by `jest-julia analyze` or the VS Code extension

Options:
      --top <number>  Rows per section (default: 10)
      --json          Print the parsed profile as JSON
  -o, --out <file>    Write the report to a file instead of stdout
  -h, --help          Show this help
```

</details>

<details><summary><code>jest-julia bench</code></summary>

```text
Usage: jest-julia bench [project dir] [options]

Run benchmark/benchmarks.jl on a git baseline (temporary worktree) and the working tree, then judge

Options:
      --baseline <ref|none>  Git ref to compare against (default: HEAD)
      --seconds <number>     BenchmarkTools time budget per benchmark (default: 1)
      --tolerance <number>   Median-time change treated as noise (default: 0.05)
      --julia <path>         Julia executable
      --json                 Print judgements as JSON
  -o, --out <file>           Write the report to a file instead of stdout
  -h, --help                 Show this help

Examples:
  jest-julia bench
  jest-julia bench --baseline main --tolerance 0.1
  jest-julia bench --baseline none
```

</details>

<details><summary><code>jest-julia init</code></summary>

```text
Usage: jest-julia init <workload|bench|workflow> [project dir] [options]

Create snoop/workload.jl, benchmark/benchmarks.jl or a GitHub Actions benchmark workflow

Options:
      --force  Overwrite an existing file
  -h, --help   Show this help
```

</details>

### jest-security

```text
jest-security 0.2.0 — Security & Systems Engineering Pack — all tools in one command

Usage: jest-security <command> [options]

Commands:
  endpoint         Endpoint Security & Compliance Toolkit (same as jest-endpoint …)
  hw               Embedded Hardware Security Workbench (same as jest-hw …)
  julia            Julia Invalidation & Compiler Profiler (same as jest-julia …)
  lint             Run every code linter (endpoint API + compliance, ESP32 / ESPHome, Julia) over the given paths (use scan for a full audit incl. installed extensions)
  scan             Full security audit: lint the code AND risk-scan installed VS Code / Cursor extensions; prints a report and writes one SARIF file (default security.sarif)
  scan-extension   Find every installed extension (VS Code, Insiders, VSCodium, Cursor, Windsurf, remote), scan and analyse them; report in the terminal and security.sarif
  scan-extensions  Alias of scan-extension
  scan-manifest    CI gate: scan extensions a repository recommends (.vscode/extensions.json, dev containers, workspaces) by downloading them; fail on risk or policy
  analyzers        Show the optional deep-inspection analyzers (Rust, Go, Python, Julia), or install one: analyzers install rs|go|py|jl
  doctor           Check the installation: versions, bundled data, and external tools (julia, git)

Run "jest-security <command> --help" for command options.

Examples:
  jest-security scan                      # full audit: code + installed extensions → report + security.sarif
  jest-security scan-extension            # installed extensions only: discover, scan, analyse → report + security.sarif
  jest-security scan-manifest --base origin/main   # CI: scan extensions this branch adds to the repo's extension lists
  jest-security endpoint simulate attack.ptree.yaml
  jest-security hw entropy trng.bin --bits 8
  jest-security julia report profile.json
```

<details><summary><code>jest-security lint</code></summary>

```text
Usage: jest-security lint [paths…] [options]

Run every code linter (endpoint API + compliance, ESP32 / ESPHome, Julia) over the given paths (use scan for a full audit incl. installed extensions)

Options:
  -f, --format <text|json|sarif|md>             Output format (default: text)
  -o, --out <file>                              Write the report to a file instead of stdout
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
  -h, --help                                    Show this help

Examples:
  jest-security lint .
  jest-security lint src firmware --format md --out findings.md
```

</details>

<details><summary><code>jest-security scan</code></summary>

```text
Usage: jest-security scan [paths…] [options]

Full security audit: lint the code AND risk-scan installed VS Code / Cursor extensions; prints a report and writes one SARIF file (default security.sarif)

Options:
  -f, --format <text|json|sarif|md>             Format of the --out file (the terminal always gets the readable report) (default: sarif)
  -o, --out <file>                              Report file (use --out - to print the file format to stdout instead) (default: security.sarif)
      --fail-on <error|warning|info|hint|none>  Exit with code 1 when a finding has at least this severity (default: error)
      --disable <rule-id>                       Turn a rule off (repeatable)
      --rule-pack <file.yaml>                   Add a YAML/JSON rule pack (repeatable)
  -q, --quiet                                   Report errors only
      --ignore <glob>                           Skip matching files/folders (gitignore-style; also read from .jestignore) (repeatable)
      --ignore-file                             Read .jestignore in the working directory (--no-ignore-file to skip)
      --extensions                              Include the installed-extension risk scan (--no-extensions to skip)
      --extension-dir <dir>                     Extensions folder to scan (default: VS Code, Insiders, VSCodium, Cursor, Windsurf, remote) (repeatable)
      --allowlist <publisher.name[@version]>    Trusted extensions (repeatable)
      --extension-fail-on <high|medium|none>    Exit 1 when an installed extension reaches this risk level (default: high)
  -h, --help                                    Show this help

Examples:
  jest-security scan                          # code in . + installed extensions → report + security.sarif
  jest-security scan src firmware --no-extensions
  jest-security scan --format md --out audit.md
  jest-security scan --extension-dir ~/.cursor/extensions --extension-fail-on medium
```

</details>

<details><summary><code>jest-security scan-extension</code></summary>

```text
Usage: jest-security scan-extension [extensions folders or single extension folders…] [options]

Find every installed extension (VS Code, Insiders, VSCodium, Cursor, Windsurf, remote), scan and analyse them; report in the terminal and security.sarif

Options:
  -f, --format <sarif|md|json|text>           Format of the --out file (the terminal always gets the readable report) (default: sarif)
  -o, --out <file>                            Report file (--out - prints the file format to stdout instead) (default: security.sarif)
      --details                               List the reasons for every extension, including low risk
      --allowlist <publisher.name[@version]>  Trust these extensions (repeatable)
      --trusted-publisher <publisher>         Treat this publisher as known (repeatable)
      --node-modules                          Also scan bundled node_modules (--no-node-modules for a faster scan)
      --max-files <number>                    Maximum JavaScript files scanned per extension (default: 2000)
      --fail-on <high|medium|none>            Exit 1 when an extension reaches this risk level (default: high)
  -h, --help                                  Show this help

Examples:
  jest-security scan-extension                       # every editor → report + security.sarif
  jest-security scan-extension --details --format md --out extensions.md
  jest-security scan-extension ~/.vscode/extensions/ash-blade.postgresql-hacker-helper-1.18.0
```

</details>

<details><summary><code>jest-security scan-manifest</code></summary>

```text
Usage: jest-security scan-manifest [manifest files or folders…] [options]

CI gate: scan extensions a repository recommends (.vscode/extensions.json, dev containers, workspaces) by downloading them; fail on risk or policy

Options:
      --base <git-ref>                        Compare with this revision; only added or version-changed extensions are scanned (e.g. origin/main)
      --all                                   With --base, also scan unchanged extensions
      --registry <marketplace|open-vsx>       Where to download packages from (default: marketplace)
      --registry-url <url>                    Registry base URL, for a private Marketplace / Open VSX mirror (default https://marketplace.visualstudio.com or https://open-vsx.org)
      --target-platform <platform>            Build to scan for platform-specific extensions (default: linux-x64)
      --cache-dir <dir>                       Download cache (default $RUNNER_TEMP/jest-security-vsix or the temp folder)
      --policy <file>                         Policy file (default .github/jest-security.yml when it exists)
      --fail-on <high|medium|none>            Exit 1 when a new or changed extension reaches this level (default: policy, else high)
  -f, --format <sarif|md|json|text>           Format of the --out file (the terminal always gets the readable report) (default: sarif)
  -o, --out <file>                            Report file (--out - prints the file format to stdout instead) (default: security.sarif)
      --summary <file>                        Append the Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)
      --annotations                           Print GitHub annotations on the manifest lines (default: on inside GitHub Actions)
      --allowlist <publisher.name[@version]>  Trust these extensions (added to the policy allowlist) (repeatable)
      --trusted-publisher <publisher>         Treat this publisher as known (repeatable)
      --node-modules                          Also scan bundled node_modules
      --max-files <number>                    Maximum JavaScript files scanned per extension (default: 2000)
      --deep                                  Also run the installed Rust / Go / Python / Julia analyzers (deep inspection)
      --analyzers <rs|go|py|jl>               Run only these analyzers (implies --deep) (repeatable)
      --online                                Marketplace reputation lookups (verified publisher, installs); the registry is contacted for downloads anyway
      --analyzer-timeout <seconds>            Per-analyzer time limit (default: 600)
  -h, --help                                  Show this help

Examples:
  jest-security scan-manifest                               # every extension the repo recommends
  jest-security scan-manifest --base origin/main            # only what this branch adds or re-versions
  jest-security scan-manifest .devcontainer --fail-on medium
  jest-security scan-manifest --base "$BASE_SHA" --summary "$GITHUB_STEP_SUMMARY" --out ext.sarif
  jest-security scan-manifest team-extensions.txt --registry open-vsx
```

</details>

<details><summary><code>jest-security doctor</code></summary>

```text
Usage: jest-security doctor [options]

Check the installation: versions, bundled data, and external tools (julia, git)

Options:
  -h, --help  Show this help
```

</details>

## Data and privacy

- Every command reads files only.
- `simulate` replays event data and never executes anything.
- `extensions` reads installed extensions from disk and makes no network calls.
- `scan-manifest` is the exception: it downloads the extensions a repository lists from the registry (VS Marketplace or Open VSX), sending only their identifiers. Packages are unpacked into a cache and read; nothing in them is executed.
- `jest-julia analyze` and `bench` run your Julia project with SnoopCompile or BenchmarkTools. They install into a private cache environment (`~/.cache/jest-julia`), so your `Project.toml` is never modified.
