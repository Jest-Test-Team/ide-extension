# Julia Invalidation & Compiler Profiler

Find and fix the causes of Julia compile latency — method invalidations and runtime-dispatch inference — without leaving VS Code.

## Features

### Invalidation & inference analysis
**Julia Profiler: Analyze Invalidations & Inference** runs [SnoopCompile.jl](https://github.com/timholy/SnoopCompile.jl) on the project containing the active file:

- `@snoop_invalidations` while loading the package → **Invalidations** view in the activity bar: each invalidating method with the number of compiled `MethodInstance`s it invalidated, expandable down to the invalidated callers. Click any node to jump to its source.
- `@snoop_inference` while running a workload script (`snoop/workload.jl` by default; **Create Inference Workload Script** scaffolds it) → **flame graph report**: zoomable inference flame graph, top methods by self inference time and the call sites whose runtime dispatch triggered fresh inference.

SnoopCompile is installed into a private environment in the extension's storage and stacked onto `LOAD_PATH`, so your `Project.toml`/`Manifest.toml` are never modified. The last profile is kept per workspace; **Open Profile JSON…** loads a saved one.

### Refactoring linter
Static checks (tree-sitter) for code patterns that commonly cause invalidations or poor inference:

| Rule | What it flags | Quick fix |
|---|---|---|
| `julia/abstract-field` | struct fields typed `::Real`, `::AbstractVector`, `Vector{Any}`, or untyped | turn the field into a type parameter |
| `julia/nonconst-global` | non-`const` globals read inside functions | add `const` |
| `julia/untyped-container` | `[]`, `Any[]`, `Dict()` | — |
| `julia/global-in-function` | `global x = …` inside functions | — |
| `julia/base-method-extension` | type piracy, and Base/Core methods extended with abstract/untyped arguments | — |

When a profile is loaded, **runtime-backed diagnostics** mark the exact methods that invalidated code (`julia/runtime-invalidation`) and the call sites that triggered inference (`julia/runtime-inference-trigger`). Every diagnostic links to the relevant Julia manual or SnoopCompile documentation, and can be suppressed with `# ide-ext-ignore-next-line <rule-id>`.

**Insert PrecompileTools Workload** adds a `@setup_workload`/`@compile_workload` block to cache compiled code in the package image.

### Benchmark comparison
**Run Benchmarks & Compare…** runs your PkgBenchmark-style `benchmark/benchmarks.jl` (`const SUITE = BenchmarkGroup()`) on a baseline git ref — checked out in a temporary worktree — and on the working tree, then judges median times like `BenchmarkTools.judge` (default tolerance 5 %). **Create GitHub Actions Benchmark Workflow** adds an [AirspeedVelocity.jl](https://github.com/MilesCranmer/AirspeedVelocity.jl) workflow that comments the same comparison on pull requests.

## Requirements

- Julia ≥ 1.10 (tested with 1.13). The binary is taken from `juliaProfiler.executablePath`, then `julia.executablePath` (Julia extension), then `PATH`, then `~/.juliaup/bin/julia`.
- Internet access the first time, to install SnoopCompile / BenchmarkTools into the private tool environments.
- `git` for baseline comparisons.

## Settings

| Setting | Default | |
|---|---|---|
| `juliaProfiler.executablePath` | `""` | Julia binary |
| `juliaProfiler.workloadScript` | `""` | workload for `@snoop_inference` (relative to the project) |
| `juliaProfiler.timeoutMinutes` | `30` | abort long analyses |
| `juliaProfiler.lint.enable` / `lint.disabledRules` | `true` / `[]` | linter control |
| `juliaProfiler.invalidationThreshold` | `10` | recorded invalidations at or above this are warnings |
| `juliaProfiler.benchmark.seconds` / `benchmark.timeTolerance` | `1` / `0.05` | benchmark budget and judge tolerance |

## Command line

The same features are available as `jest-julia`, for terminals and CI pipelines:
- **Install from VS Code:** **Julia Profiler: Install 'jest-julia' Command in PATH**. It needs no Node.js.
- **Install from npm:** `npm i -g @jest-test-team/security-cli`.

```bash
jest-julia lint src/
jest-julia analyze --out profile.json --max-invalidated 0
jest-julia report profile.json
jest-julia lint src/ --profile profile.json     # add recorded invalidations / triggers
jest-julia bench --baseline main               # exit 1 on regressions
jest-julia init bench
```

- Reports: `--format text|json|sarif|md`.
- Exit codes: `1` on findings or a failed check, so the commands work as CI gates.
- Options: see `jest-julia <command> --help`.

## Sources

- [Julia manual — Performance Tips](https://docs.julialang.org/en/v1/manual/performance-tips/)
- [Julia compiler / devdocs](https://docs.julialang.org/en/v1/devdocs/eval/)
- [SnoopCompile.jl documentation](https://timholy.github.io/SnoopCompile.jl/stable/)
- [BenchmarkTools.jl manual](https://juliaci.github.io/BenchmarkTools.jl/stable/manual/)
