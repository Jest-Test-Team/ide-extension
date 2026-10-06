using Test
using JSON
using JestExtBenchmark: exec_hits_text, robust_z, population_outliers, analyze

@testset "julia-exec" begin
    lines(src) = [h.line for h in exec_hits_text(src)]
    @test lines("x = 1\nrun(`curl -s https://x.example`)") == [2]
    @test lines("p = download(url)\ninclude(p)") == [2]
    @test lines("eval(Meta.parse(s))") == [1]
    @test lines("include(\"helpers.jl\")\nprintln(`echo hi`)") == Int[]
    @test lines("this is not julia (((") == Int[]
end

@testset "robust z" begin
    xs = [1.0, 1.0, 2.0, 1.0, 1.5, 9.0]
    @test robust_z(9.0, xs) > 3.5
    @test robust_z(1.5, xs) < 3.5
    @test robust_z(0.0, zeros(5)) == 0.0
end

@testset "population outliers" begin
    scores = Dict("a.$i" => Dict("process" => 1.0 + 0.1i, "network" => 0.0) for i in 1:6)
    scores["evil.x"] = Dict("process" => 1.0, "network" => 9.0)
    out = population_outliers(scores)
    @test length(out) == 1 && out[1][1] == "evil.x" && out[1][2] == "network"
    @test isempty(population_outliers(Dict("a" => Dict("x" => 9.0))))
end

@testset "protocol" begin
    dir = mktempdir()
    write(joinpath(dir, "tool.jl"), "run(`rm -rf /tmp/x`)\n")
    mkpath(joinpath(dir, "node_modules"))
    write(joinpath(dir, "node_modules", "skip.jl"), "run(`ls`)")
    exts = [Dict("id" => "a.$i", "version" => "1", "path" => mktempdir(), "manifest" => Dict(), "categoryScores" => Dict("process" => 1.0)) for i in 1:5]
    push!(exts, Dict("id" => "jl.ext", "version" => "1", "path" => dir, "manifest" => Dict(), "categoryScores" => Dict("process" => 12.0)))
    req = Dict("protocol" => 1, "extensions" => exts, "vectors" => ["ext/julia-exec", "ext/population-outlier", "ext/calibrated-risk"], "options" => Dict())
    io = IOBuffer()
    analyze(req, io)
    msgs = [JSON.parse(l) for l in split(strip(String(take!(io))), '\n')]
    sigs = filter(m -> m["type"] == "signal", msgs)
    @test Set(m["vector"] for m in sigs) == Set(["ext/julia-exec", "ext/population-outlier"])
    exec = only(filter(m -> m["vector"] == "ext/julia-exec", sigs))
    @test exec["locations"] == [Dict("file" => "tool.jl", "line" => 1)]
    @test msgs[end]["ran"] == ["ext/julia-exec", "ext/population-outlier"]
    @test msgs[end]["skipped"][1]["id"] == "ext/calibrated-risk"
end
