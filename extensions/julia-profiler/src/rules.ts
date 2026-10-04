import type { CustomRule, Finding, QueryRule, Rule, RuleContext, RuleRef } from '@ide-ext/core';
import type { Node } from 'web-tree-sitter';

const PERF_TIPS: RuleRef = {
  label: 'Julia manual — Performance Tips',
  url: 'https://docs.julialang.org/en/v1/manual/performance-tips/',
};
const FIELD_TIPS: RuleRef = {
  label: 'Performance Tips — Avoid fields with abstract type',
  url: 'https://docs.julialang.org/en/v1/manual/performance-tips/#Avoid-fields-with-abstract-type',
};
const GLOBAL_TIPS: RuleRef = {
  label: 'Performance Tips — Avoid untyped global variables',
  url: 'https://docs.julialang.org/en/v1/manual/performance-tips/#Avoid-untyped-global-variables',
};
const CONTAINER_TIPS: RuleRef = {
  label: 'Performance Tips — Avoid containers with abstract type parameters',
  url: 'https://docs.julialang.org/en/v1/manual/performance-tips/#man-performance-abstract-container',
};
const PIRACY: RuleRef = {
  label: 'Julia manual — Style Guide: Avoid type piracy',
  url: 'https://docs.julialang.org/en/v1/manual/style-guide/#Avoid-type-piracy',
};
const SNOOP: RuleRef = {
  label: 'SnoopCompile.jl — Tutorial on @snoop_invalidations',
  url: 'https://timholy.github.io/SnoopCompile.jl/stable/tutorials/invalidations/',
};

/** Abstract types from Base/Core commonly (mis)used as field or element types. */
export const ABSTRACT_TYPES = new Set([
  'Any', 'Number', 'Real', 'Integer', 'Signed', 'Unsigned', 'AbstractFloat', 'AbstractIrrational', 'Complex',
  'AbstractString', 'AbstractChar', 'AbstractArray', 'AbstractVector', 'AbstractMatrix', 'AbstractVecOrMat',
  'AbstractRange', 'AbstractDict', 'AbstractSet', 'AbstractUnitRange', 'DenseArray', 'DenseVector', 'DenseMatrix',
  'StridedArray', 'StridedVector', 'StridedMatrix', 'Function', 'Type', 'DataType', 'Union', 'UnionAll', 'IO',
  'Exception', 'Enum', 'AbstractDisplay', 'AbstractChannel', 'AbstractLock', 'Base.AbstractCartesianIndex',
  'Array', 'Vector', 'Matrix', // without parameters these are UnionAlls
]);
/** Base types that take parameters; unparameterized use is abstract (UnionAll). */
const NEEDS_PARAMS = new Set(['Array', 'Vector', 'Matrix', 'Dict', 'Set', 'Tuple', 'NamedTuple', 'Ref', 'Complex', 'Type']);

const kids = (n: Node): Node[] => n.namedChildren.filter((c): c is Node => c !== null && c.type !== 'comment' && c.type !== 'line_comment' && c.type !== 'block_comment');

function hasError(n: Node): boolean {
  return n.hasError || n.descendantsOfType('ERROR').length > 0;
}

interface StructInfo {
  node: Node;
  nameNode: Node;
  name: string;
  /** Node to edit when adding type parameters: identifier or parametrized_type_expression. */
  headNode: Node;
  params: string[];
}

function structInfo(node: Node): StructInfo | undefined {
  const head = kids(node).find((c) => c.type === 'type_head');
  let target = head && kids(head)[0];
  if (target?.type === 'binary_expression') {
    target = kids(target)[0]; // `Name{T} <: Super`
  }
  if (!target) {
    return undefined;
  }
  if (target.type === 'identifier') {
    return { node, nameNode: target, name: target.text, headNode: target, params: [] };
  }
  if (target.type === 'parametrized_type_expression') {
    const [nameNode, curly] = kids(target);
    const params = curly
      ? kids(curly).map((p) => (p.type === 'binary_expression' ? kids(p)[0]?.text ?? '' : p.text))
      : [];
    return { node, nameNode, name: nameNode.text, headNode: target, params };
  }
  return undefined;
}

interface Field {
  name: Node;
  type?: Node;
}

function structFields(node: Node): Field[] {
  const out: Field[] = [];
  const visit = (c: Node) => {
    switch (c.type) {
      case 'identifier':
        out.push({ name: c });
        break;
      case 'typed_expression': {
        const [name, type] = kids(c);
        if (name?.type === 'identifier' && type) {
          out.push({ name, type });
        }
        break;
      }
      case 'assignment': {
        // @kwdef default (`x::T = 1`); skip short-form inner constructors (`A(x) = new(x)`).
        const left = kids(c)[0];
        if (left && (left.type === 'identifier' || left.type === 'typed_expression')) {
          visit(left);
        }
        break;
      }
    }
  };
  kids(node)
    .filter((c) => c.type !== 'type_head')
    .forEach(visit);
  return out;
}

/** Why a type annotation is abstract, or undefined when it looks concrete. */
export function abstractReason(type: Node, params: ReadonlySet<string>, localAbstract: ReadonlySet<string>): string | undefined {
  if (type.type === 'identifier') {
    const t = type.text;
    if (params.has(t)) {
      return undefined;
    }
    if (localAbstract.has(t)) {
      return `\`${t}\` is an abstract type`;
    }
    if (NEEDS_PARAMS.has(t)) {
      return `\`${t}\` without parameters is not a concrete type`;
    }
    return ABSTRACT_TYPES.has(t) ? `\`${t}\` is an abstract type` : undefined;
  }
  if (type.type === 'parametrized_type_expression') {
    const [base, curly] = kids(type);
    if (base && ABSTRACT_TYPES.has(base.text) && !NEEDS_PARAMS.has(base.text)) {
      return `\`${base.text}\` is an abstract type`;
    }
    for (const p of curly ? kids(curly) : []) {
      if (p.type === 'identifier' && !params.has(p.text) && (ABSTRACT_TYPES.has(p.text) || localAbstract.has(p.text)) && !NEEDS_PARAMS.has(p.text)) {
        return `element type \`${p.text}\` is abstract`;
      }
    }
  }
  return undefined;
}

function localTypeNames(root: Node): { all: Set<string>; abstract: Set<string> } {
  const all = new Set<string>();
  const abstract = new Set<string>();
  for (const d of root.descendantsOfType(['abstract_definition', 'primitive_definition', 'struct_definition'])) {
    if (!d) {
      continue;
    }
    const info = d.type === 'struct_definition' ? structInfo(d) : undefined;
    const name = info?.name ?? (d.type !== 'struct_definition' ? firstIdentifier(d) : undefined);
    if (name) {
      all.add(name);
      if (d.type === 'abstract_definition') {
        abstract.add(name);
      }
    }
  }
  return { all, abstract };
}

function firstIdentifier(n: Node): string | undefined {
  const head = kids(n).find((c) => c.type === 'type_head') ?? n;
  return head.descendantsOfType('identifier')[0]?.text;
}

function freshParam(taken: Set<string>): string {
  for (const name of ['T', 'S', 'U', 'V', 'W']) {
    if (!taken.has(name)) {
      return name;
    }
  }
  let i = 1;
  while (taken.has(`T${i}`)) {
    i++;
  }
  return `T${i}`;
}

const abstractField: CustomRule = {
  kind: 'custom',
  id: 'julia/abstract-field',
  title: 'Struct field with abstract or missing type',
  description:
    'Fields typed with an abstract type (or not typed at all, i.e. `::Any`) force boxed storage and dynamic dispatch on every access, which defeats type inference and makes code using the struct more prone to invalidation.',
  severity: 'warning',
  languages: ['julia'],
  message: '',
  refs: [FIELD_TIPS, PERF_TIPS],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const { abstract: localAbstract } = localTypeNames(ctx.tree.rootNode);
    const out: Finding[] = [];
    for (const s of ctx.tree.rootNode.descendantsOfType('struct_definition')) {
      if (!s || hasError(s)) {
        continue;
      }
      const info = structInfo(s);
      if (!info) {
        continue;
      }
      const params = new Set(info.params);
      const taken = new Set([...info.params, ...structFields(s).map((f) => f.name.text)]);
      for (const f of structFields(s)) {
        if (!f.type) {
          out.push(ctx.report(f.name, `Field \`${f.name.text}\` of \`${info.name}\` has no type annotation, so it is stored as \`Any\`.`));
          continue;
        }
        const why = abstractReason(f.type, params, localAbstract);
        if (!why) {
          continue;
        }
        const finding = ctx.report(f.type, `Field \`${f.name.text}\` of \`${info.name}\`: ${why}. Consider a type parameter.`);
        if (f.type.type === 'identifier' && !NEEDS_PARAMS.has(f.type.text)) {
          // `x::Real` → `x::T` and `A` → `A{T<:Real}` (or `A{S, T<:Real}`).
          const p = freshParam(taken);
          const bound = f.type.text === 'Any' ? p : `${p}<:${f.type.text}`;
          const headText = info.headNode.type === 'identifier' ? `${info.name}{${bound}}` : info.headNode.text.replace(/\}\s*$/, `, ${bound}}`);
          finding.fix = {
            title: `Make \`${f.name.text}\` a type parameter (${bound})`,
            edits: [
              { range: ctx.lines.rangeOf(info.headNode.startIndex, info.headNode.endIndex), newText: headText },
              { range: ctx.lines.rangeOf(f.type.startIndex, f.type.endIndex), newText: p },
            ],
          };
        }
        out.push(finding);
      }
    }
    return out;
  },
};

/** Top-level scopes: the file itself and `module … end` bodies. */
function topLevelStatements(root: Node): Node[] {
  const out: Node[] = [];
  const visit = (scope: Node) => {
    for (const c of kids(scope)) {
      if (c.type === 'module_definition') {
        visit(c);
      } else {
        out.push(c);
      }
    }
  };
  visit(root);
  return out;
}

function isFunctionNode(n: Node): boolean {
  if (n.type === 'function_definition' || n.type === 'arrow_function_expression' || n.type === 'do_clause') {
    return true;
  }
  if (n.type === 'assignment') {
    const left = kids(n)[0];
    return left?.type === 'call_expression' || left?.type === 'where_expression';
  }
  return false;
}

const nonConstGlobal: CustomRule = {
  kind: 'custom',
  id: 'julia/nonconst-global',
  title: 'Non-constant global used inside functions',
  description:
    'Functions that read an untyped, non-`const` global cannot infer its type; every use becomes a dynamic lookup. Declare it `const`, give it a type (`x::Int = 0`, Julia ≥ 1.8), or wrap mutable state in a `const Ref`.',
  severity: 'warning',
  languages: ['julia'],
  message: '',
  refs: [GLOBAL_TIPS],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const assigned = new Map<string, Node[]>();
    for (const st of topLevelStatements(ctx.tree.rootNode)) {
      if (st.type !== 'assignment') {
        continue;
      }
      const left = kids(st)[0];
      if (left?.type === 'identifier') {
        assigned.set(left.text, [...(assigned.get(left.text) ?? []), left]);
      }
    }
    if (!assigned.size) {
      return [];
    }
    // Names read inside function bodies, and those mutated there via `global`.
    const usedInFunctions = new Set<string>();
    const mutated = new Set<string>();
    const walk = (n: Node, inFn: boolean) => {
      const fn = inFn || isFunctionNode(n);
      if (fn && n.type === 'identifier') {
        usedInFunctions.add(n.text);
      }
      if (fn && n.type === 'global_statement') {
        n.descendantsOfType('identifier').forEach((i) => i && mutated.add(i.text));
      }
      kids(n).forEach((c) => walk(c, fn));
    };
    walk(ctx.tree.rootNode, false);
    const out: Finding[] = [];
    for (const [name, nodes] of assigned) {
      if (!usedInFunctions.has(name)) {
        continue;
      }
      const first = nodes[0];
      if (nodes.length > 1 || mutated.has(name)) {
        out.push(
          ctx.report(
            first,
            `Global \`${name}\` is reassigned and used in functions; its type cannot be inferred. Use \`const ${name} = Ref(...)\` and \`${name}[]\`, or a typed global.`,
          ),
        );
      } else {
        const f = ctx.report(first, `Global \`${name}\` is not \`const\` but is used inside functions.`);
        const stmt = first.parent!;
        f.fix = { title: `Declare \`${name}\` const`, edits: [{ range: ctx.lines.rangeOf(stmt.startIndex, stmt.startIndex), newText: 'const ' }] };
        out.push(f);
      }
    }
    return out;
  },
};

const untypedContainer: QueryRule = {
  id: 'julia/untyped-container',
  title: 'Container with element type Any',
  description: '`[]`, `Any[]` and `Dict()` create containers with abstract element types; operations on their elements are dynamically dispatched.',
  severity: 'info',
  languages: ['julia'],
  message: '`{{match}}` creates a container with element type `Any`; give it a concrete element type (e.g. `Float64[]`, `Dict{String,Int}()`).',
  refs: [CONTAINER_TIPS],
  // Separate top-level patterns: text predicates are not applied inside `[...]` alternations.
  query: `
    ((assignment (identifier) (vector_expression) @match) (#eq? @match "[]"))
    ((index_expression (identifier) @_t (vector_expression) @_v) @match (#eq? @_t "Any") (#eq? @_v "[]"))
    ((call_expression (identifier) @_t (argument_list) @_args) @match (#match? @_t "^(Dict|Set)$") (#eq? @_args "()"))
  `,
};

const globalInFunction: QueryRule = {
  id: 'julia/global-in-function',
  title: '`global` assignment inside a function',
  description: 'Writing a global from a function makes the global type-unstable and the function harder to infer.',
  severity: 'info',
  languages: ['julia'],
  message: '`global` mutation inside a function is type-unstable; pass state explicitly or use a `const Ref`.',
  refs: [GLOBAL_TIPS],
  query: '(function_definition (global_statement) @match)',
};

interface MethodDef {
  node: Node;
  /** Name node: identifier, operator, or field_expression (`Base.show`). */
  nameNode: Node;
  qualifier?: string;
  name: string;
  args: { node: Node; type?: Node }[];
  whereParams: Set<string>;
}

function methodDefs(root: Node): MethodDef[] {
  const out: MethodDef[] = [];
  const consider = (node: Node, sig: Node | undefined) => {
    let call = sig;
    const whereParams = new Set<string>();
    while (call?.type === 'where_expression') {
      const [inner, ...rest] = kids(call);
      for (const r of rest) {
        (r.type === 'curly_expression' ? kids(r) : [r]).forEach((p) =>
          whereParams.add(p.type === 'binary_expression' ? kids(p)[0]?.text ?? '' : p.text),
        );
      }
      call = inner;
    }
    if (call?.type !== 'call_expression') {
      return;
    }
    const callKids = call.namedChildren.filter((c): c is Node => c !== null);
    const [nameNode] = callKids;
    const argList = callKids.find((c) => c.type === 'argument_list');
    if (!nameNode || !argList) {
      return;
    }
    let qualifier: string | undefined;
    let name = nameNode.text;
    if (nameNode.type === 'field_expression') {
      const [q, n] = kids(nameNode);
      qualifier = q?.text;
      name = (n?.text ?? '').replace(/^:\(?|\)$/g, '');
    }
    const args = kids(argList)
      .filter((a) => a.type !== 'keyword_parameters')
      .map((a) => {
        if (a.type === 'typed_expression') {
          return { node: a, type: kids(a)[1] };
        }
        if (a.type === 'unary_typed_expression') {
          return { node: a, type: kids(a)[0] };
        }
        return { node: a };
      });
    out.push({ node, nameNode, qualifier, name, args, whereParams });
  };
  for (const f of root.descendantsOfType('function_definition')) {
    const sig = f && kids(f).find((c) => c.type === 'signature');
    if (f && sig) {
      consider(f, kids(sig)[0]);
    }
  }
  for (const a of root.descendantsOfType('assignment')) {
    if (a) {
      const left = kids(a)[0];
      if (left?.type === 'call_expression' || left?.type === 'where_expression') {
        consider(a, left);
      }
    }
  }
  return out;
}

function importedFromBase(root: Node): Set<string> {
  const names = new Set<string>();
  for (const imp of root.descendantsOfType('import_statement')) {
    for (const sel of imp?.descendantsOfType('selected_import') ?? []) {
      const [mod, ...items] = sel ? kids(sel) : [];
      if (mod && /^(Base|Core)$/.test(mod.text)) {
        items.forEach((i) => names.add(i.text));
      }
    }
  }
  return names;
}

function typeNames(t: Node): string[] {
  if (t.type === 'identifier' || t.type === 'field_expression') {
    return [t.text];
  }
  return t.descendantsOfType(['identifier']).filter((n): n is Node => n !== null).map((n) => n.text);
}

const basePiracyAndBreadth: CustomRule = {
  kind: 'custom',
  id: 'julia/base-method-extension',
  title: 'Extending Base/Core methods',
  description:
    'Adding methods to Base/Core functions for types you do not own is type piracy. Methods with abstract or untyped arguments on widely-used Base functions intersect many compiled signatures and are the most common cause of invalidations.',
  severity: 'warning',
  languages: ['julia'],
  message: '',
  refs: [PIRACY, SNOOP],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const root = ctx.tree.rootNode;
    const { all: localTypes, abstract: localAbstract } = localTypeNames(root);
    const imported = importedFromBase(root);
    const out: Finding[] = [];
    for (const m of methodDefs(root)) {
      const extendsBase = (m.qualifier && /^(Base|Core)$/.test(m.qualifier)) || (!m.qualifier && imported.has(m.name));
      if (!extendsBase || m.args.length === 0) {
        continue;
      }
      const label = `${m.qualifier ?? 'Base'}.${m.name}`;
      const owned = m.args.some((a) => a.type && typeNames(a.type).some((n) => localTypes.has(n)));
      if (!owned) {
        out.push(ctx.report(m.nameNode, `Type piracy: \`${label}\` is extended only with types this file does not define.`));
        continue;
      }
      const broad = m.args.filter((a) => {
        if (!a.type) {
          return true;
        }
        if (a.type.type === 'identifier' && m.whereParams.has(a.type.text)) {
          return true; // `x::T where T` is as broad as Any
        }
        return !!abstractReason(a.type, new Set(), localAbstract);
      });
      if (broad.length) {
        const names = broad.map((a) => `\`${a.node.text}\``).join(', ');
        out.push(
          ctx.report(
            m.nameNode,
            `\`${label}\` has abstract/untyped argument(s) ${names}; broad methods on Base functions frequently invalidate compiled code. Narrow the types if possible.`,
          ),
        );
      }
    }
    return out;
  },
};

export const JULIA_RULES: Rule[] = [abstractField, nonConstGlobal, untypedContainer, globalInFunction, basePiracyAndBreadth];
