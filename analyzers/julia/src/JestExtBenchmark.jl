"""
Julia analyzer of `jest-security scan-extension --deep` (protocol v1).

- `ext/julia-exec`: `.jl` files shipped in extensions, read with Julia's own parser (parsing never
  runs code): `run` of commands, `download` + `include`, `eval(Meta.parse(…))`, `include_string`.
- `ext/population-outlier`: a category score far above the other installed extensions (robust
  z-score over the category scores the scanner sends, needs ≥ 5 extensions).
- `ext/category-outlier` / `ext/calibrated-risk` need a baseline of popular extensions; they report
  as skipped until `data/extscan/baseline.json` exists.
"""
module JestExtBenchmark

using JSON

const VERSION_STR = "0.1.0"
const PROTOCOL = 1
const VECTORS = ["ext/julia-exec", "ext/population-outlier"]
const BASELINE_VECTORS = ["ext/category-outlier", "ext/calibrated-risk"]
const SKIP_DIRS = Set([".git", "node_modules", ".venv", "venv", "__pycache__"])
const MIN_POPULATION = 5
const Z_THRESHOLD = 3.5
const MIN_SCORE = 3.0

function median(xs::AbstractVector{<:Real})
    s = sort(collect(Float64, xs))
    n = length(s)
    isodd(n) ? s[(n + 1) ÷ 2] : (s[n ÷ 2] + s[n ÷ 2 + 1]) / 2
end

emit(io::IO, msg) = (println(io, JSON.json(msg)); flush(io))

# ---------- julia-exec ----------

struct ExecHit
    line::Int
    message::String
end

callname(f) = f isa Symbol ? String(f) : (f isa Expr && f.head == :. && f.args[end] isa QuoteNode) ? String(f.args[end].value) : ""

# Backticks parse to `@cmd`, a bare symbol in older parsers and `GlobalRef(Core, Symbol("@cmd"))` in newer ones.
iscmd(x) = x isa Expr && x.head == :macrocall && (x.args[1] == Symbol("@cmd") || (x.args[1] isa GlobalRef && x.args[1].name == Symbol("@cmd")))
isliteral(x) = x isa AbstractString

"""Walks a parsed file; returns the hits and whether it downloads and includes."""
function exec_hits(ex)
    hits = ExecHit[]
    line = Ref(1)
    downloads = Int[]
    dyn_includes = Int[]
    function walk(x)
        x isa LineNumberNode && (line[] = x.line; return)
        x isa Expr || return
        if x.head == :call && !isempty(x.args)
            name = callname(x.args[1])
            args = x.args[2:end]
            if name in ("run", "pipeline", "success", "read", "open") && any(iscmd, args)
                push!(hits, ExecHit(line[], "`$(name)` runs an external command"))
            elseif name == "Cmd" && !isempty(args)
                push!(hits, ExecHit(line[], "builds a command with `Cmd(…)`"))
            elseif name == "download"
                push!(downloads, line[])
            elseif name == "include" && !isempty(args) && !isliteral(args[end])
                push!(dyn_includes, line[])
            elseif name == "include_string"
                push!(hits, ExecHit(line[], "`include_string` evaluates text as code"))
            elseif name == "eval" && !isempty(args) && args[end] isa Expr && args[end].head == :call && callname(args[end].args[1]) in ("parse", "parseall")
                push!(hits, ExecHit(line[], "`eval(Meta.parse(…))` runs code built at run time"))
            end
        end
        foreach(walk, x.args)
    end
    walk(ex)
    if !isempty(downloads) && !isempty(dyn_includes)
        push!(hits, ExecHit(dyn_includes[1], "downloads (line $(downloads[1])) and `include`s a computed path"))
    end
    sort!(hits; by = h -> h.line)
end

function exec_hits_text(text::AbstractString, filename::AbstractString = "none")
    ex = try
        Meta.parseall(text; filename)
    catch
        return ExecHit[]
    end
    exec_hits(ex)
end

function julia_files(root::AbstractString, max_files::Int, max_bytes::Int)
    out = String[]
    for (dir, dirs, files) in walkdir(root; follow_symlinks = false)
        filter!(d -> !(d in SKIP_DIRS), dirs)
        for f in files
            endswith(f, ".jl") || continue
            p = joinpath(dir, f)
            (islink(p) || filesize(p) > max_bytes) && continue
            push!(out, p)
            length(out) >= max_files && return out
        end
    end
    out
end

relpath_slash(p, root) = replace(relpath(p, root), '\\' => '/')

# ---------- population-outlier ----------

"""Robust z-score (Iglewicz–Hoaglin): 0.6745 (x - median) / MAD; falls back to the mean absolute deviation."""
function robust_z(x::Real, xs::AbstractVector{<:Real})
    m = median(xs)
    mad = median(abs.(xs .- m))
    if mad > 0
        return 0.6745 * (x - m) / mad
    end
    meanad = sum(abs.(xs .- m)) / length(xs)
    meanad > 0 ? (x - m) / (1.253314 * meanad) : 0.0
end

"""(ext id, category, score, median, z) for every category score far above the population."""
function population_outliers(scores::Dict{String,Dict{String,Float64}})
    length(scores) < MIN_POPULATION && return Tuple{String,String,Float64,Float64,Float64}[]
    cats = sort!(unique(vcat([collect(keys(v)) for v in values(scores)]...)))
    out = Tuple{String,String,Float64,Float64,Float64}[]
    for c in cats
        xs = [get(v, c, 0.0) for v in values(scores)]
        for (id, v) in scores
            x = get(v, c, 0.0)
            x < MIN_SCORE && continue
            z = robust_z(x, xs)
            z >= Z_THRESHOLD && push!(out, (id, c, x, median(xs), z))
        end
    end
    sort!(out; by = t -> (t[1], -t[5]))
end

# ---------- protocol ----------

function analyze(req, io::IO = stdout)
    want = Set(String.(get(req, "vectors", String[])))
    opts = get(req, "options", Dict())
    max_files = Int(something(get(opts, "maxFiles", nothing), 5000))
    max_bytes = Int(round(Float64(something(get(opts, "maxFileMB", nothing), 10)) * 1024 * 1024))
    exts = get(req, "extensions", Any[])
    if "ext/julia-exec" in want
        for ext in exts
            id, root = String(ext["id"]), String(ext["path"])
            emit(io, Dict("type" => "progress", "ext" => id, "message" => "julia files"))
            files = julia_files(root, max_files, max_bytes)
            emit(io, Dict("type" => "metric", "ext" => id, "name" => "julia.files", "value" => length(files)))
            found = Tuple{String,ExecHit}[]
            for f in files
                text = try
                    read(f, String)
                catch
                    continue
                end
                append!(found, [(f, h) for h in exec_hits_text(text, f)])
            end
            isempty(found) && continue
            nfiles = length(unique(first.(found)))
            msg = "$(found[1][2].message) ($(length(found)) hit$(length(found) == 1 ? "" : "s") in $nfiles Julia file$(nfiles == 1 ? "" : "s"))"
            locs = [Dict("file" => relpath_slash(f, root), "line" => h.line) for (f, h) in found[1:min(end, 20)]]
            emit(io, Dict("type" => "signal", "ext" => id, "vector" => "ext/julia-exec", "message" => msg, "locations" => locs, "confidence" => 0.8))
        end
    end
    if "ext/population-outlier" in want
        scores = Dict{String,Dict{String,Float64}}()
        for ext in exts
            cs = get(ext, "categoryScores", nothing)
            cs === nothing && continue
            scores[String(ext["id"])] = Dict(String(k) => Float64(v) for (k, v) in cs)
        end
        for (id, c, x, m, z) in population_outliers(scores)
            msg = "$(c) score $(round(x; digits = 1)) is far above the other $(length(scores) - 1) scanned extensions (median $(round(m; digits = 1)), robust z $(round(z; digits = 1)))"
            emit(io, Dict("type" => "signal", "ext" => id, "vector" => "ext/population-outlier", "message" => msg, "confidence" => 0.7))
        end
    end
    ran = [v for v in VECTORS if v in want]
    skipped = [Dict("id" => v, "reason" => "no baseline of popular extensions yet (tools/benchmark)") for v in BASELINE_VECTORS if v in want]
    done = Dict{String,Any}("type" => "done", "ran" => ran)
    isempty(skipped) || (done["skipped"] = skipped)
    emit(io, done)
end

function main(args::Vector{String} = ARGS)::Int
    cmd = isempty(args) ? "" : args[1]
    if cmd == "info"
        emit(stdout, Dict("name" => "jest-ext-jl", "version" => VERSION_STR, "protocol" => PROTOCOL, "vectors" => VECTORS))
        return 0
    elseif cmd in ("version", "--version")
        println(VERSION_STR)
        return 0
    elseif cmd == "analyze"
        req = try
            JSON.parse(read(stdin, String))
        catch e
            println(stderr, "invalid request: ", e)
            return 2
        end
        if get(req, "protocol", nothing) != PROTOCOL
            println(stderr, "unsupported protocol $(get(req, "protocol", nothing)) (want $PROTOCOL)")
            return 2
        end
        analyze(req)
        return 0
    end
    println(stderr, "usage: jest-ext-jl info | analyze < request.json | version")
    return 2
end

end # module
