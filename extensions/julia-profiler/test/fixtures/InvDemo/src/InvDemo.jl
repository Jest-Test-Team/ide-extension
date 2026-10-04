module InvDemo

struct Wrapper
    x::Real
    tag
end

# Type piracy-ish broad methods that tend to invalidate compiled Base code.
Base.convert(::Type{T}, w::Wrapper) where {T<:Integer} = T(round(w.x))
Base.:(==)(a::Wrapper, b) = a.x == b
Base.length(::Wrapper) = 1

counter = 0

function process(v)
    global counter += 1
    acc = []
    for x in v
        push!(acc, Wrapper(x, :a))
    end
    return sum(w -> w.x, acc)
end

end
