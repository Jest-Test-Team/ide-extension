import { RuleEngine, type Finding } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { JULIA_RULES } from '../../src/rules';

const engine = new RuleEngine(testHost(), JULIA_RULES);
let n = 0;
const lint = (text: string) => engine.run({ uri: `file:///t${n++}.jl`, path: '/t.jl', languageId: 'julia', text });
const ids = (fs: Finding[]) => fs.map((f) => `${f.ruleId}@${f.range.start.line}`);

describe('julia rules', () => {
  it('flags abstract and untyped struct fields, with a parametrize fix', async () => {
    const src = 'struct A{T}\n  x::Real\n  y\n  z::Vector{Any}\n  w::T\n  v::Vector{Float64}\nend\n';
    const out = (await lint(src)).filter((f) => f.ruleId === 'julia/abstract-field');
    expect(ids(out)).toEqual(['julia/abstract-field@1', 'julia/abstract-field@2', 'julia/abstract-field@3']);
    const fix = out[0].fix!;
    expect(fix.title).toContain('S<:Real');
    expect(fix.edits.map((e) => e.newText)).toEqual(['A{T, S<:Real}', 'S']);
  });

  it('understands kwdef defaults, locally declared abstract types and inner constructors', async () => {
    const src = 'abstract type Shape end\nBase.@kwdef struct K <: Shape\n  a::Shape = 1\n  b::Int = 2\n  K(a) = new(a, 2)\nend\n';
    const out = (await lint(src)).filter((f) => f.ruleId === 'julia/abstract-field');
    expect(ids(out)).toEqual(['julia/abstract-field@2']);
  });

  it('flags non-const globals used in functions', async () => {
    const src = 'module M\nlimit = 10\nunused = 1\ncounter = 0\nf(x) = x < limit\nfunction g()\n  global counter += 1\nend\nend\n';
    const out = (await lint(src)).filter((f) => f.ruleId === 'julia/nonconst-global');
    expect(ids(out)).toEqual(['julia/nonconst-global@1', 'julia/nonconst-global@3']);
    expect(out[0].fix?.edits[0].newText).toBe('const ');
    expect(out[1].fix).toBeUndefined();
    expect(out[1].message).toContain('Ref');
  });

  it('flags Any containers and global mutation', async () => {
    const src = 'function f()\n  a = []\n  b = Any[]\n  c = Dict()\n  d = Float64[]\n  global q = 1\nend\n';
    const out = await lint(src);
    expect(ids(out.filter((f) => f.ruleId === 'julia/untyped-container'))).toEqual([
      'julia/untyped-container@1',
      'julia/untyped-container@2',
      'julia/untyped-container@3',
    ]);
    expect(out.some((f) => f.ruleId === 'julia/global-in-function')).toBe(true);
  });

  it('detects type piracy and broad Base methods', async () => {
    const src = [
      'struct W; x::Int; end',
      'Base.length(::W) = 1',
      'Base.:(==)(a::W, b) = a.x == b',
      'Base.convert(::Type{T}, w::W) where {T<:Integer} = T(w.x)',
      'Base.show(io::IO, x::Int) = nothing',
      'import Base: +',
      '+(a::Int, b::Int) = 3',
    ].join('\n');
    const out = (await lint(src)).filter((f) => f.ruleId === 'julia/base-method-extension');
    // convert(::Type{T}, ::W) where T<:Integer is owned and bounded, so it is not reported.
    expect(ids(out)).toEqual(['julia/base-method-extension@2', 'julia/base-method-extension@4', 'julia/base-method-extension@6']);
    expect(out[0].message).toContain('`b`');
    expect(out[1].message).toContain('Type piracy');
  });

  it('lints the InvDemo fixture', async () => {
    const src = readFileSync(join(__dirname, '../fixtures/InvDemo/src/InvDemo.jl'), 'utf8');
    const rules = new Set((await lint(src)).map((f) => f.ruleId));
    expect([...rules].sort()).toEqual([
      'julia/abstract-field',
      'julia/base-method-extension',
      'julia/global-in-function',
      'julia/nonconst-global',
      'julia/untyped-container',
    ]);
  });
});
