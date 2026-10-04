import type { Node } from 'web-tree-sitter';

/** Small helpers over tree-sitter-c / tree-sitter-cpp trees. */

export const named = (n: Node): Node[] => n.namedChildren.filter((c): c is Node => c !== null && c.type !== 'comment');

export function descendants(n: Node, types: string | string[]): Node[] {
  return n.descendantsOfType(types).filter((c): c is Node => c !== null);
}

export interface FunctionDef {
  node: Node;
  name: string;
  /** Text from the start of the definition up to the body (attributes, return type, params). */
  header: string;
  params: { name: string; pointer: boolean; type: string }[];
  body: Node;
}

function declaratorName(d: Node | null): { name: string; pointer: boolean } {
  let pointer = false;
  let cur = d;
  while (cur && cur.type !== 'identifier' && cur.type !== 'field_identifier') {
    if (cur.type === 'pointer_declarator' || cur.type === 'array_declarator' || cur.type === 'reference_declarator') {
      pointer = true;
    }
    cur = cur.childForFieldName('declarator') ?? named(cur).find((c) => c.type.endsWith('declarator') || c.type === 'identifier') ?? null;
  }
  return { name: cur?.text ?? '', pointer };
}

export function functionDefs(root: Node): FunctionDef[] {
  const out: FunctionDef[] = [];
  for (const f of descendants(root, 'function_definition')) {
    const body = f.childForFieldName('body');
    let decl = f.childForFieldName('declarator');
    while (decl && decl.type !== 'function_declarator') {
      decl = decl.childForFieldName('declarator');
    }
    if (!body || !decl) {
      continue;
    }
    const name = decl.childForFieldName('declarator')?.text ?? '';
    const params = descendants(decl.childForFieldName('parameters') ?? decl, 'parameter_declaration')
      .filter((p) => p.parent?.parent?.id === decl!.id)
      .map((p) => {
        const { name: pname, pointer } = declaratorName(p.childForFieldName('declarator'));
        return { name: pname, pointer, type: p.childForFieldName('type')?.text ?? '' };
      });
    const header = f.text.slice(0, body.startIndex - f.startIndex);
    out.push({ node: f, name, header, params, body });
  }
  return out;
}

export interface Call {
  node: Node;
  name: string;
  args: Node[];
}

export function calls(n: Node): Call[] {
  return descendants(n, 'call_expression').map((c) => {
    const fn = c.childForFieldName('function');
    const argList = c.childForFieldName('arguments');
    return { node: c, name: fn?.type === 'identifier' ? fn.text : (fn?.text ?? ''), args: argList ? named(argList) : [] };
  });
}

const GUARD_CALLS = /^(assert|configASSERT|ESP_RETURN_ON_FALSE|ESP_GOTO_ON_FALSE|ESP_RETURN_ON_ERROR|MIN|MAX|min|max|std::min|std::max|BOUNDS_CHECK)$/;

/** Nodes that act as checks: if/while/for conditions, ternaries, and assert-style macros. */
export function guards(scope: Node): Node[] {
  const out: Node[] = [];
  for (const s of descendants(scope, ['if_statement', 'while_statement', 'do_statement', 'for_statement', 'conditional_expression'])) {
    const cond = s.childForFieldName('condition');
    if (cond) {
      out.push(cond);
    }
  }
  for (const c of calls(scope)) {
    if (GUARD_CALLS.test(c.name)) {
      out.push(c.node);
    }
  }
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** True when `text` (an identifier or `p->field` expression) appears in a guard before `before`. */
export function guardedBefore(scope: Node, text: string, before: number): boolean {
  const re = new RegExp(`(^|[^\\w>.])${escapeRe(text)}(?![\\w])`);
  return guards(scope).some((g) => g.startIndex < before && re.test(g.text));
}

export function guardedAfter(scope: Node, text: string, after: number): boolean {
  const re = new RegExp(`(^|[^\\w>.])${escapeRe(text)}(?![\\w])`);
  return guards(scope).some((g) => g.startIndex > after && re.test(g.text));
}

/** Function names passed as the `index`-th argument to any of the registration calls. */
export function registeredCallbacks(root: Node, registrations: Record<string, number>): Set<string> {
  const out = new Set<string>();
  for (const c of calls(root)) {
    const idx = registrations[c.name];
    const arg = idx === undefined ? undefined : c.args[idx];
    if (arg) {
      out.add(arg.text.replace(/^&/, ''));
    }
  }
  return out;
}
