# Collects SnoopCompile invalidation and inference data and writes it as JSON for the
# "Julia Invalidation & Compiler Profiler" VS Code extension.
#
# Usage:
#   julia --startup-file=no --project=<user project> collect.jl <out.json> <tool env dir> [package] [workload.jl]
#
# The JSON tree is built from heterogeneous values, so Any containers are intended here:
# ide-ext-ignore-file julia/untyped-container
#
# SnoopCompile is installed into <tool env dir> (a private environment stacked onto LOAD_PATH),
# so the user's Project.toml / Manifest.toml are never modified.

const OUT = ARGS[1]
const TOOL_ENV = ARGS[2]
const PKGNAME = length(ARGS) >= 3 ? ARGS[3] : ""
const WORKLOAD = length(ARGS) >= 4 ? ARGS[4] : ""
const WARNINGS = String[]

import Pkg
let user = Base.active_project()
    Pkg.activate(TOOL_ENV; io = devnull)
    deps = keys(Pkg.project().dependencies)
    if !("SnoopCompile" in deps && "SnoopCompileCore" in deps)
        println(stderr, "[collect] installing SnoopCompile into $TOOL_ENV")
        Pkg.add(["SnoopCompileCore", "SnoopCompile"]; io = stderr)
    end
    user === nothing ? Pkg.activate(; io = devnull) : Pkg.activate(user; io = devnull)
end
push!(LOAD_PATH, TOOL_ENV)

using SnoopCompileCore

println(stderr, "[collect] recording invalidations")
invs = @snoop_invalidations begin
    isempty(PKGNAME) || Core.eval(Main, :(using $(Symbol(PKGNAME))))
end

tinf = nothing
if !isempty(WORKLOAD)
    println(stderr, "[collect] recording inference for $WORKLOAD")
    tinf = @snoop_inference Base.include(Main, WORKLOAD)
end

using SnoopCompile

# ---------------------------------------------------------------------------------------------
# Minimal JSON writer (avoids adding JSON packages to the tool environment)

function writejson(io::IO, x)
    if x === nothing
        print(io, "null")
    elseif x isa Bool
        print(io, x ? "true" : "false")
    elseif x isa Integer
        print(io, x)
    elseif x isa AbstractFloat
        isfinite(x) ? print(io, Float64(x)) : print(io, "null")
    elseif x isa AbstractString || x isa Symbol
        print(io, '"')
        for c in string(x)
            if c == '"'
                print(io, "\\\"")
            elseif c == '\\'
                print(io, "\\\\")
            elseif c == '\n'
                print(io, "\\n")
            elseif c == '\r'
                print(io, "\\r")
            elseif c == '\t'
                print(io, "\\t")
            elseif c < ' '
                print(io, "\\u", lpad(string(UInt16(c), base = 16), 4, '0'))
            else
                print(io, c)
            end
        end
        print(io, '"')
    elseif x isa AbstractDict
        print(io, '{')
        first = true
        for (k, v) in x
            first || print(io, ',')
            first = false
            writejson(io, string(k))
            print(io, ':')
            writejson(io, v)
        end
        print(io, '}')
    elseif x isa AbstractVector || x isa Tuple
        print(io, '[')
        for (i, v) in enumerate(x)
            i > 1 && print(io, ',')
            writejson(io, v)
        end
        print(io, ']')
    else
        writejson(io, string(x))
    end
end

# ---------------------------------------------------------------------------------------------
# Invalidation trees

# Base/stdlib methods report paths like "./reduce.jl"; resolve them to the installed sources.
function srcpath(file)
    f = string(file)
    isabspath(f) && return f
    full = Base.find_source_file(f)
    return full === nothing ? f : full
end

const PROJECT_DIR = dirname(something(Base.active_project(), pwd()))

const MAX_DEPTH = 8
const MAX_CHILDREN = 50

function mi_info(mi)
    m = mi isa Core.MethodInstance ? mi.def : mi
    sig = mi isa Core.MethodInstance ? string(mi.specTypes) : string(mi)
    if m isa Method
        return Dict{String,Any}("sig" => sig, "method" => string(m.name), "module" => string(m.module),
                                "file" => srcpath(m.file), "line" => Int(m.line))
    end
    return Dict{String,Any}("sig" => sig, "method" => string(m), "module" => "", "file" => "", "line" => 0)
end

nkids(n) = hasproperty(n, :children) ? sum((1 + nkids(c) for c in n.children); init = 0) : 0

function instance_node(n, depth = 0)
    if !hasproperty(n, :mi)            # a bare MethodInstance
        d = mi_info(n)
        d["total"] = 0
        d["children"] = Any[]
        return d
    end
    d = mi_info(n.mi)
    d["total"] = nkids(n)
    kids = sort(collect(n.children); by = nkids, rev = true)
    d["children"] = depth >= MAX_DEPTH ? Any[] :
                    Any[instance_node(c, depth + 1) for c in Iterators.take(kids, MAX_CHILDREN)]
    return d
end

function tree_json(t)
    m = t.method
    backedges = Any[instance_node(n) for n in t.backedges]
    mt = Any[Dict{String,Any}("trigger" => string(sig), "root" => instance_node(n)) for (sig, n) in t.mt_backedges]
    count = sum((1 + nkids(n) for n in t.backedges); init = 0) +
            sum((1 + nkids(n) for (_, n) in t.mt_backedges); init = 0)
    d = Dict{String,Any}(
        "reason" => string(t.reason),
        "ninvalidated" => count,
        "backedges" => backedges,
        "mt_backedges" => mt,
        "mt_cache" => length(t.mt_cache),
        "mt_disable" => length(t.mt_disable),
    )
    if m isa Method
        merge!(d, Dict("method" => string(m.name), "module" => string(m.module), "sig" => string(m.sig),
                       "file" => srcpath(m.file), "line" => Int(m.line)))
    else
        merge!(d, Dict("method" => string(m), "module" => "", "sig" => string(m), "file" => "", "line" => 0))
    end
    return d
end

trees = Any[]
try
    for t in invalidation_trees(invs)
        push!(trees, tree_json(t))
    end
catch err
    push!(WARNINGS, "invalidation_trees failed: " * sprint(showerror, err))
end

# ---------------------------------------------------------------------------------------------
# Inference flame tree and triggers

const MIN_TIME = 1e-5      # seconds; smaller subtrees are folded into "(other)"

function flame_node(n)
    mi = Core.MethodInstance(n)
    d = mi_info(mi)
    d["name"] = d["method"]
    d["self"] = SnoopCompile.exclusive(n)
    d["total"] = SnoopCompile.inclusive(n)
    kids = Any[]
    other = 0.0
    for c in n.children
        t = SnoopCompile.inclusive(c)
        if t < MIN_TIME
            other += t
        else
            push!(kids, flame_node(c))
        end
    end
    if other > 0
        push!(kids, Dict{String,Any}("name" => "(other)", "sig" => "", "method" => "(other)", "module" => "",
                                     "file" => "", "line" => 0, "self" => other, "total" => other,
                                     "children" => Any[]))
    end
    d["children"] = kids
    return d
end

inference = nothing
triggers = Any[]
if tinf !== nothing
    try
        root = flame_node(tinf)
        root["name"] = "ROOT"
        global inference = Dict{String,Any}("total" => SnoopCompile.inclusive(tinf),
                                     "inferenceTime" => SnoopCompile.inclusive(tinf) - SnoopCompile.exclusive(tinf),
                                     "root" => root)
    catch err
        push!(WARNINGS, "flame tree failed: " * sprint(showerror, err))
    end
    try
        for itrig in inference_triggers(tinf)
            callee = mi_info(Core.MethodInstance(itrig.node))
            frame(sf) = sf === nothing ? Dict{String,Any}("func" => "", "file" => "", "line" => 0) :
                        Dict{String,Any}("func" => string(sf.func), "file" => srcpath(sf.file), "line" => Int(sf.line))
            frames = itrig.callerframes
            # The innermost caller is often inside Base (e.g. map/reduce); also report the first frame
            # in the user's project, which is where a fix would go.
            site = findfirst(sf -> startswith(srcpath(sf.file), PROJECT_DIR), frames)
            push!(triggers, Dict{String,Any}("callee" => callee,
                                             "caller" => frame(isempty(frames) ? nothing : frames[1]),
                                             "site" => site === nothing ? nothing : frame(frames[site]),
                                             "time" => SnoopCompile.inclusive(itrig.node)))
        end
    catch err
        push!(WARNINGS, "inference_triggers failed: " * sprint(showerror, err))
    end
end

const result = Dict{String,Any}(
    "version" => 1,
    "julia" => string(VERSION),
    "project" => something(Base.active_project(), ""),
    "package" => PKGNAME,
    "workload" => WORKLOAD,
    "createdAt" => string(Base.Libc.strftime("%Y-%m-%dT%H:%M:%S", time())),
    "invalidations" => trees,
    "inference" => inference,
    "triggers" => triggers,
    "warnings" => WARNINGS,
)
open(OUT, "w") do io
    writejson(io, result)
end
println(stderr, "[collect] wrote $(length(trees)) invalidation tree(s), $(length(triggers)) inference trigger(s) to $OUT")
