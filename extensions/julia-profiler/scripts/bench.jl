# Runs a PkgBenchmark-style suite (`benchmark/benchmarks.jl` defining `SUITE::BenchmarkGroup`)
# and writes per-benchmark estimates as JSON for the VS Code extension.
#
# Usage:
#   julia --startup-file=no --project=<package dir> bench.jl <benchmarks.jl> <out.json> <tool env dir> [seconds]
#
# BenchmarkTools is installed into <tool env dir> and stacked onto LOAD_PATH; the package's own
# environment is not modified. If benchmark/Project.toml exists it is stacked as well.

const FILE = abspath(ARGS[1])
const OUT = ARGS[2]
const TOOL_ENV = ARGS[3]
const SECONDS = length(ARGS) >= 4 ? parse(Float64, ARGS[4]) : 1.0

import Pkg
let user = Base.active_project()
    Pkg.activate(TOOL_ENV; io = devnull)
    if !haskey(Pkg.project().dependencies, "BenchmarkTools")
        println(stderr, "[bench] installing BenchmarkTools into $TOOL_ENV")
        Pkg.add("BenchmarkTools"; io = stderr)
    end
    user === nothing ? Pkg.activate(; io = devnull) : Pkg.activate(user; io = devnull)
end
push!(LOAD_PATH, TOOL_ENV)
let benchenv = joinpath(dirname(FILE), "Project.toml")
    isfile(benchenv) && push!(LOAD_PATH, dirname(FILE))
end

using BenchmarkTools

Base.include(Main, FILE)
isdefined(Main, :SUITE) || error("$FILE must define `const SUITE = BenchmarkGroup()`")
const suite = getfield(Main, :SUITE)

println(stderr, "[bench] tuning")
tune!(suite)
println(stderr, "[bench] running")
results = run(suite; verbose = false, seconds = SECONDS)

esc(s) = replace(string(s), "\\" => "\\\\", "\"" => "\\\"", "\n" => "\\n")
open(OUT, "w") do io
    print(io, "{\"version\":1,\"julia\":\"", VERSION, "\",\"benchmarks\":[")
    for (i, (keys, trial)) in enumerate(BenchmarkTools.leaves(results))
        i > 1 && print(io, ',')
        med = median(trial)
        print(io, "{\"name\":\"", esc(join(string.(keys), " / ")), "\"",
              ",\"median_ns\":", time(med),
              ",\"min_ns\":", time(minimum(trial)),
              ",\"mean_ns\":", time(mean(trial)),
              ",\"memory\":", memory(med),
              ",\"allocs\":", allocs(med),
              ",\"samples\":", length(trial.times), "}")
    end
    print(io, "]}")
end
println(stderr, "[bench] wrote $OUT")
