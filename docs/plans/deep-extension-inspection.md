# Plan: Deep, polyglot inspection of installed extensions (≥ 110 vectors)

## Context
`jest-security scan-extension` today is shallow. It has 23 signals:
- 9 regex / tree-sitter code rules over `.js/.cjs/.mjs` only, with no data flow;
- manifest checks;
- a native-binary *presence* flag.

The benchmark output proves the point: it is mostly "runs processes / evaluates code", which nearly every extension does.

The user wants a deep inspection of each extension, with at least ~100 vectors and a more meaningful benchmark. Decisions taken with the user:
- **Polyglot runtime:** Go, Rust, Julia and Python analyzers are used at scan time when installed.
- **Network:** online checks are opt-in and off by default.

The scan must still work with nothing extra installed, and must say exactly which vectors ran.

## Architecture
```
jest-security scan-extension [--deep] [--online] [--analyzers rs,go,py,jl]
        │
        ▼
TypeScript orchestrator (packages/cli + extensions/endpoint-security/src/extscan)
  ├─ discovery (existing disk.ts / inventory.ts)
  ├─ vector registry   data/extscan/vectors.yaml      ← single source of truth (id, category, weight, severity, engine, ATT&CK/CWE refs)
  ├─ TS core engine    always on: manifest, tree-sitter JS rules, webview/API rules, Markdown/JSON assets
  ├─ analyzer host     spawns available analyzers, JSON protocol v1, timeouts, read-only
  │    ├─ jest-ext-rs  (Rust)   JS AST + cross-file data flow (oxc), obfuscation/entropy, binaries (goblin), YARA-X, hashes
  │    ├─ jest-ext-go  (Go)     supply chain: bundled npm deps, OSV (offline snapshot + online), install scripts, VSIX integrity, domain inventory
  │    ├─ jest-ext-py  (Python) Python files shipped in extensions (ast), deobfuscation/unpacking, ML anomaly model
  │    └─ jest-ext-jl  (Julia)  benchmark: population + baseline percentiles, robust z-scores, calibrated weights
  ├─ scoring           category scores 0–100 + existing combination rules (score.ts) with calibrated weights
  └─ report            terminal deep report, SARIF (taxonomy = vector registry), Markdown/JSON, VS Code Installed Extensions view
```

**Analyzer protocol v1** (`packages/cli/src/analyzers/protocol.ts`):
- **Invocation:** `<analyzer> analyze` reads one JSON request on stdin and writes NDJSON on stdout.
- **Request:** `{protocol:1, extensions:[{id, version, path, manifest}], vectors:[ids], options:{online, maxFileMB, maxFiles}}`.
- **Response messages:**
  - `{type:"signal", ext, vector, message, locations:[{file,line,col}], evidence?, confidence}`;
  - `{type:"metric", ext, name, value}`, e.g. entropy, dep count, percentile;
  - `{type:"progress"}`;
  - `{type:"done", ran:[vectorIds], skipped:[{id,reason}]}`.
- **Discovery:** `$JEST_ANALYZERS_DIR`, then `~/.cache/jest-security/analyzers` (installed by `jest-security analyzers install`, checksum-verified GitHub release assets for Rust/Go; `pip install` / Julia project for Py/JL), then `PATH`.
- **Safety:** analyzers never execute or `require` extension code. They get a per-analyzer timeout and are killed on cancel.

Every report ends with a **coverage table** listing the vectors that ran, those skipped and why, and which engines were available. `jest-security doctor` lists the analyzers and their versions.

## Vector catalog (110; engine in brackets, ⓝ = online opt-in)
A full registry with weights and refs lives in `data/extscan/vectors.yaml`. The 23 existing signals are migrated into it; existing ids keep working.

**A. Manifest & metadata — 22 [TS]**
- activation `*`, `onStartupFinished`, `onUri` / uriHandler, broad `workspaceContains`
- untrusted-workspace support without restricted configs, virtual workspaces
- `extensionKind` workspace + process exec
- terminal profile / task / debugger adapter executables, authentication provider
- keybindings overriding copy/paste/save, `configurationDefaults` weakening security (`security.workspace.trust.*`, `http.proxy*`, `terminal.integrated.env.*`, `extensions.autoUpdate`)
- unknown `extensionDependencies` / `extensionPack`, missing / mismatched repository, missing license
- displayName / brand impersonation, publisher ≠ brand, abnormal version jump, `scripts.postinstall`/`vscode:prepublish` remnants, remote `jsonValidation` URLs, walkthrough remote media, obfuscated / unusual entry file names

**B. Process & system — 18 [TS rules + RS data flow]**
- `shell:true`, `bash -c` / `powershell -enc` / `cmd /c`, `curl|sh`, download → write → chmod → exec chain [RS]
- persistence writes: LaunchAgents, crontab, shell rc files, Startup folder, `reg add …\Run`, `schtasks`, `launchctl`, `systemctl`
- `sudo` / `osascript … administrator privileges`, `osascript keystroke`, `screencapture`, `tccutil`, `security add-trusted-cert`
- killing other processes, writing into other extensions' folders, editing VS Code `settings.json` / `keybindings.json` from disk

**C. Data access — 16 [TS rules + RS taint]**
- `~/.ssh`, `.aws`, `.npmrc`, `.git-credentials`, `.netrc`, kubeconfig, docker `config.json`, gcloud / azure tokens
- browser `Login Data` / `Cookies` / `Local State`, keychain / DPAPI, crypto wallets
- shell history, bulk `.env` reading, `process.env` dumps
- `authentication.getSession` with broad scopes at activation, workspace-wide `findFiles('**/*')` + read

**D. Network & exfiltration — 14 [TS + RS + GO]**
- raw `net` / `dgram` sockets, DNS exfil (dynamic subdomains), webhook / paste / tunnel services (Discord, Telegram, Slack, ngrok, pastebin, webhook.site, transfer.sh)
- `.onion`, mining pools (`stratum+tcp`), IP-lookup services, cleartext `http`/`ws` endpoints, TLS verification disabled
- executable downloads (`.exe` / `.sh` / `.ps1` URLs), encoded URL construction [RS]
- full domain inventory with first-party vs third-party classification [GO], reputation lookup ⓝ [GO]

**E. Obfuscation & evasion — 12 [RS; TS subset]**
- javascript-obfuscator / packer (`eval(function(p,a,c,k,e,d)`), high-entropy literals (Shannon), long base64/hex blobs
- `fromCharCode` chains, decode → `eval`, embedded encrypted payload (`createDecipheriv` + `eval`), base64 WebAssembly instantiate
- anti-debug loops, sandbox / CI / VM detection, time bombs (date-gated code), self-modifying writes to own files

**F. Native binaries & WASM — 10 [RS]**
- format / arch, unsigned or ad-hoc-signed Mach-O (`codesign -dv` when on macOS), Authenticode presence
- dangerous imports (ptrace, `CGEventTapCreate`, `SetWindowsHookEx`, `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`, keychain / AX APIs)
- URLs / IPs in strings, UPX / packed sections, high-entropy sections, WASM imports (WASI fs/sockets)
- YARA-X rule pack hits (curated open rules for stealers / miners / RATs)

**G. Supply chain — 12 [GO; ⓝ for live data]**
- bundled npm packages with OSV vulnerabilities (offline snapshot, live ⓝ), OSV `MAL-` malicious packages
- dependency typosquats, packages with install scripts, protestware list, git / tarball-URL dependencies, deprecated packages, dependency count / depth outliers, missing lockfile
- **VSIX tamper check ⓝ:** download the published VSIX for id@version, diff file hashes against the installed copy
- Marketplace vs Open VSX mismatch ⓝ

**H. Webviews & UI — 8 [TS + RS]**
- `enableScripts` without CSP, CSP with `unsafe-eval` / `unsafe-inline` / remote origins, remote `<script src>`, `localResourceRoots` too broad
- `enableCommandUris`, `MarkdownString.isTrusted` with command links, message handlers that `executeCommand` / spawn with webview data [RS taint]

**I. VS Code API abuse — 10 [TS + RS taint]**
- `createTerminal` + hidden `sendText`, `workbench.action.terminal.sendSequence`, `getConfiguration().update` on security keys
- programmatic install / uninstall of other extensions, `env.openExternal` at activation
- `onDidChangeTextDocument` / `'*'` providers → network (code exfiltration), clipboard → network, secrets of other extensions, global storage used as a payload cache

**J. Python / Julia / scripts shipped inside extensions — 6 [PY, JL, TS]**
- `.py` files: `subprocess` / `os.system` / `eval` / `exec` / `pickle.loads`, network to IPs, credential paths (Python `ast`) [PY]
- `.jl`: `run(`…`)`, `download` + `include` [JL]
- shell / PowerShell / batch scripts with download-exec [TS]

**K. Reputation & provenance — 8 [GO/TS; mostly ⓝ]**
- verified publisher, install count / rating outliers, last update age, repository exists and contains the version tag
- publisher domain verification, VirusTotal hash lookup (user API key) ⓝ, known-bad list freshness, sideload source

**L. Behavioural model & benchmark — 4 [PY, JL]**
- ML anomaly score (Python model trained offline on the baseline corpus plus labelled malicious samples) [PY]
- category percentile vs. baseline of popular extensions; robust z-score outliers within the user's own set; calibrated overall score [JL]

## Benchmark redesign
- **Category scores** (0–100) for A–K per extension, an overall risk built from calibrated weights, and the existing combination rules ("credential access + exfil endpoint", etc.).
- **Baseline:**
  - Offline corpus tooling (`tools/corpus/`, Python) downloads the top ~500 Marketplace extensions plus public malicious samples (dev-time only) and runs the full scan.
  - Julia (`tools/benchmark/`) fits per-vector frequencies, category distributions and logistic weights, and writes `data/extscan/baseline.json` and `weights.json`. Both are versioned and shipped.
- **Runtime:**
  - The Julia analyzer, when present, computes percentiles vs baseline and the user's population, plus outliers.
  - Without it, TypeScript computes simple percentiles from `baseline.json`.
- **Report** per extension: "code-execution signals higher than 93 % of popular extensions", plus the top vectors with evidence.

## Report changes
- **Terminal (`--deep`):**
  - per-extension scorecard (category bars), evidence snippets at file:line, data-flow paths (source → sink chains from Rust taint);
  - the benchmark;
  - a coverage table.
- **SARIF:** `taxonomies` = vector registry; `codeFlows` for taint paths; `properties.category` / `confidence`; one run per engine.
- **VS Code:** the Installed Extensions view shows category scores and coverage.

## Delivery (commit + push after each phase)
1. **Registry + protocol:**
   - `vectors.yaml`, migrate existing signals, analyzer host, coverage reporting;
   - `doctor` / `analyzers install`, `--deep` / `--online` / `--analyzers` flags.
2. **TS core vectors:** A, plus TS subsets of B–E, H, I, J-scripts (~65 vectors with no installs). Synthetic fixture per vector.
3. **Rust analyzer** `analyzers/rust` (cargo workspace): oxc parsing + cross-file taint, obfuscation / entropy, goblin binaries, YARA-X; release builds for darwin-arm64/x64, linux-x64/arm64, win-x64.
4. **Go analyzer** `analyzers/go`: npm dependency graph, OSV offline snapshot + live API, install scripts, typosquats, VSIX tamper check, domain inventory.
5. **Python analyzer** `analyzers/python` (`jest-ext-py`): `.py` AST checks, deobfuscation helpers, ML anomaly model (scikit-learn, model file versioned); plus the corpus tooling.
6. **Julia analyzer** `analyzers/julia` (`JestExtBenchmark.jl`): baseline fit, percentiles, calibration; `baseline.json` / `weights.json` produced and shipped.
7. **Reports + docs:** scorecards, codeFlows, VS Code view, README EN / 繁體中文, CI matrix building and testing every analyzer.

## Critical files
- `extensions/endpoint-security/src/extscan/`: `signals.ts` → registry loader, `score.ts` (category scores, calibrated weights), `codeScan.ts` (walk all file types, not only JS), `report.ts` (taxonomy, codeFlows), `data/extscan/*.yaml|json`.
- `packages/cli/src/endpoint.ts` (`scanExtensions`), `security.ts` (`scan-extension`), `extAnalysis.ts` (categories → registry); new `packages/cli/src/analyzers/`.
- New: `analyzers/{rust,go,python,julia}/`, `tools/corpus/`, `tools/benchmark/`.
- **Reused:** `RuleEngine` and tree-sitter host (`packages/core`), `readExtensionsDir` (`extscan/disk.ts`), `manifestSignals`, `scoreExtension` combinations, `toSarif`, `run()` / `cacheDir()` from `packages/cli/src/lib/proc.ts`, and the cache-environment pattern from `jest-julia` for Julia / Python setup.

## Verification
- **Per vector:** a synthetic positive and a benign negative fixture (`test/fixtures/extscan/vectors/<id>/`), asserted by the engine that owns it. A registry test checks that every vector has fixtures, refs and an owning engine, and that the total is ≥ 100.
- **Per analyzer:**
  - `cargo test`, `go test ./...`, `pytest`, `julia --project -e 'using Pkg; Pkg.test()'`;
  - a protocol conformance test (golden NDJSON) shared by all four.
- **Degradation:** the CLI runs with no analyzers, then each alone, then all. Results are a superset as engines are added, and coverage lists exactly what ran.
- **Real-world checks:**
  - **Speed:** `jest-security scan-extension --deep` on this machine's 21 extensions takes < 90 s with all analyzers, < 30 s TS-only.
  - **False positives:** ≤ 5 % of the baseline corpus is rated high.
  - **Known malicious samples:** all rated high.
- **Online:** with `--online`, mocked HTTP tests for OSV / Marketplace / VirusTotal; nothing contacts the network without the flag (asserted by a network-blocking test).
