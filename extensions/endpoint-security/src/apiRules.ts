import type { CustomRule, Finding, PatternRule, QueryRule, Rule, RuleContext, RuleRef } from '@ide-ext/core';
import type { Node } from 'web-tree-sitter';
import { CLEANUP, FRAMEWORK_DOCS, FUNCTIONS, STATUS_FUNCTIONS } from './apiDb';

const LANGS = ['c', 'cpp', 'objective-c', 'objective-cpp', 'rust'];
const C_LANGS = ['c', 'cpp', 'objective-c', 'objective-cpp'];

const docRef = (name: string): RuleRef[] => {
  const fn = FUNCTIONS.get(name);
  return fn ? [{ label: `${fn.framework}: ${fn.name}`, url: fn.url }] : [];
};
const fwRef = (fw: string): RuleRef => ({ label: `${fw} documentation`, url: FRAMEWORK_DOCS[fw] });
const alt = (names: string[]) => names.join('|');

/** Every call in the document with its callee's bare name (handles C++ `::f` and Rust `a::b::f`). */
const CALL_QUERY = {
  c: '(call_expression function: (identifier) @fn) @call',
  cpp: `(call_expression function: (identifier) @fn) @call
        (call_expression function: (qualified_identifier name: (identifier) @fn)) @call`,
  rust: `(call_expression function: (identifier) @fn) @call
         (call_expression function: (scoped_identifier name: (identifier) @fn)) @call`,
} as const;

interface CallSite {
  name: string;
  node: Node;
  fnNode: Node;
}

async function callSites(ctx: RuleContext): Promise<CallSite[]> {
  const q = ctx.grammar === 'rust' ? CALL_QUERY.rust : ctx.grammar === 'cpp' ? CALL_QUERY.cpp : CALL_QUERY.c;
  const out: CallSite[] = [];
  for (const m of await ctx.matches(q)) {
    const fn = m.captures.find((c) => c.name === 'fn')?.node;
    const call = m.captures.find((c) => c.name === 'call')?.node;
    if (fn && call) {
      out.push({ name: fn.text, node: call, fnNode: fn });
    }
  }
  return out;
}

function enclosingFunction(n: Node): Node | undefined {
  let cur: Node | null = n.parent;
  while (cur && cur.type !== 'function_definition' && cur.type !== 'function_item') {
    cur = cur.parent;
  }
  return cur ?? undefined;
}

const missingCleanup: CustomRule = {
  kind: 'custom',
  id: 'edr/missing-cleanup',
  title: 'Resource acquired without matching release',
  description:
    'Engine sessions, ETW sessions/consumers, ES clients and kernel callouts outlive their creator if they are not released: ETW sessions keep running after the process exits (64-session limit), unregistered WFP callouts crash the system after driver unload, leaked ES clients keep receiving (and blocking on) AUTH events.',
  severity: 'warning',
  languages: LANGS,
  message: '',
  refs: [fwRef('Windows Filtering Platform'), fwRef('Event Tracing for Windows'), fwRef('Apple Endpoint Security')],
  async check(ctx) {
    const sites = await callSites(ctx);
    const called = new Set(sites.map((s) => s.name));
    const out: Finding[] = [];
    const reported = new Set<string>();
    for (const s of sites) {
      const release = CLEANUP[s.name];
      if (release && !release.some((r) => called.has(r)) && !reported.has(s.name)) {
        reported.add(s.name);
        out.push(ctx.report(s.fnNode, `\`${s.name}\` is never paired with \`${release[0]}\` in this file.`));
      }
    }
    return out;
  },
};

const STATUS_RE = `^(${alt(STATUS_FUNCTIONS)})$`;

const uncheckedStatus: QueryRule = {
  id: 'edr/unchecked-status',
  title: 'Ignored status from security API',
  description:
    'WFP, ETW and Endpoint Security report failures (missing entitlement, access denied, session exists, too many clients) only through return values. An agent that ignores them silently runs without protection.',
  severity: 'warning',
  languages: LANGS,
  message: 'Result of `{{fn}}` is ignored; check it against the documented success value.',
  refs: [{ label: 'CWE-252: Unchecked Return Value', url: 'https://cwe.mitre.org/data/definitions/252.html' }],
  query: {
    c: `((expression_statement (call_expression function: (identifier) @fn) @match) (#match? @fn "${STATUS_RE}"))`,
    cpp: `((expression_statement (call_expression function: (identifier) @fn) @match) (#match? @fn "${STATUS_RE}"))
          ((expression_statement (call_expression function: (qualified_identifier name: (identifier) @fn)) @match) (#match? @fn "${STATUS_RE}"))`,
    // `let _ = …` discards the result; `_` is an anonymous node in tree-sitter-rust.
    rust: `((let_declaration pattern: "_" value: (call_expression function: [(identifier) @fn (scoped_identifier name: (identifier) @fn)]) @match) (#match? @fn "${STATUS_RE}"))
           ((let_declaration pattern: "_" value: (unsafe_block (block (call_expression function: [(identifier) @fn (scoped_identifier name: (identifier) @fn)]) @match))) (#match? @fn "${STATUS_RE}"))`,
  },
};

const deprecatedApi: CustomRule = {
  kind: 'custom',
  id: 'edr/deprecated-api',
  title: 'Deprecated Endpoint Security API',
  severity: 'info',
  languages: LANGS,
  message: '',
  refs: [fwRef('Apple Endpoint Security')],
  async check(ctx) {
    const out: Finding[] = [];
    for (const s of await callSites(ctx)) {
      const fn = FUNCTIONS.get(s.name);
      if (fn?.deprecated) {
        const f = ctx.report(s.fnNode, `\`${s.name}\` is deprecated; use \`${fn.deprecated}\`.`);
        // es_free_message → es_release_message is a drop-in rename; the others change semantics.
        if (s.name === 'es_free_message') {
          f.fix = { title: `Replace with ${fn.deprecated}`, edits: [{ range: f.range, newText: fn.deprecated }] };
        }
        out.push(f);
      }
    }
    return out;
  },
};

const esfAuthNoResponse: PatternRule = {
  kind: 'pattern',
  id: 'edr/esf-auth-no-response',
  title: 'AUTH events subscribed without a response path',
  description: 'Every AUTH message must be answered with es_respond_auth_result / es_respond_flags_result before its deadline; otherwise the system terminates the client (and the operation is held until then).',
  severity: 'error',
  languages: LANGS,
  message: '`{{match}}` is used but this file never calls es_respond_auth_result / es_respond_flags_result.',
  refs: [...docRef('es_respond_auth_result'), fwRef('Apple Endpoint Security')],
  pattern: '\\bES_EVENT_TYPE_AUTH_[A-Z_]+\\b',
  when: '\\bes_subscribe\\b',
  unless: '\\bes_respond_(auth|flags)_result\\b',
};

const esfAuthOpenFlags: PatternRule = {
  kind: 'pattern',
  id: 'edr/esf-auth-open-flags',
  title: 'AUTH_OPEN answered with es_respond_auth_result',
  description: 'ES_EVENT_TYPE_AUTH_OPEN must be answered with es_respond_flags_result; es_respond_auth_result fails with ES_RESPOND_RESULT_ERR_EVENT_TYPE and the open eventually times out.',
  severity: 'error',
  languages: LANGS,
  message: 'ES_EVENT_TYPE_AUTH_OPEN requires es_respond_flags_result, which this file never calls.',
  refs: docRef('es_respond_flags_result'),
  pattern: '\\bES_EVENT_TYPE_AUTH_OPEN\\b',
  when: '\\bes_respond_auth_result\\b',
  unless: '\\bes_respond_flags_result\\b',
};

const wfpServerName: QueryRule = {
  id: 'edr/wfp-server-name',
  title: 'FwpmEngineOpen0 serverName must be NULL',
  severity: 'error',
  languages: C_LANGS,
  message: 'The serverName argument of FwpmEngineOpen0 must be NULL (remote engines are not supported).',
  refs: docRef('FwpmEngineOpen0'),
  query: '((call_expression function: (identifier) @_f arguments: (argument_list . (_) @match)) (#eq? @_f "FwpmEngineOpen0"))',
  where: { match: { notMatches: '^(NULL|nullptr|0|\\(\\s*void\\s*\\*\\s*\\)\\s*0)$' } },
};

const POLICY_ADD = /^(FwpmFilterAdd0|FwpmSubLayerAdd0|FwpmProviderAdd0|FwpmCalloutAdd0|FwpmProviderContextAdd\d)$/;

const wfpTransactions: CustomRule = {
  kind: 'custom',
  id: 'edr/wfp-transaction',
  title: 'WFP policy changes outside a transaction / without abort',
  description: 'Several FwpmXxxAdd calls without FwpmTransactionBegin0 can leave a half-applied policy (e.g. a sublayer without its filters) when one fails; a transaction without FwpmTransactionAbort0 leaves the session locked on error paths.',
  severity: 'warning',
  languages: C_LANGS,
  message: '',
  refs: [...docRef('FwpmTransactionBegin0'), ...docRef('FwpmTransactionAbort0')],
  async check(ctx) {
    const byFn = new Map<number, { fn: Node; sites: CallSite[] }>();
    for (const s of await callSites(ctx)) {
      const fn = enclosingFunction(s.node);
      if (fn) {
        const e = byFn.get(fn.id) ?? { fn, sites: [] };
        e.sites.push(s);
        byFn.set(fn.id, e);
      }
    }
    const out: Finding[] = [];
    for (const { sites } of byFn.values()) {
      const adds = sites.filter((s) => POLICY_ADD.test(s.name));
      const begin = sites.find((s) => s.name === 'FwpmTransactionBegin0');
      if (adds.length >= 2 && !begin) {
        out.push(ctx.report(adds[0].fnNode, `${adds.length} WFP policy changes in this function are not wrapped in FwpmTransactionBegin0/Commit0.`));
      }
      if (begin && !sites.some((s) => s.name === 'FwpmTransactionAbort0')) {
        out.push(ctx.report(begin.fnNode, 'Transaction is begun but never aborted on error paths (FwpmTransactionAbort0).'));
      }
    }
    return out;
  },
};

const etwVerbose: QueryRule = {
  id: 'edr/etw-broad-enable',
  title: 'Provider enabled at VERBOSE / all keywords',
  description: 'Verbose level with all keywords (e.g. Microsoft-Windows-Kernel-*) produces very high event rates; consumers fall behind and the session drops events, creating blind spots. Enable only the keywords the detection needs.',
  severity: 'info',
  languages: C_LANGS,
  message: 'EnableTraceEx2 enables `{{match}}`; restrict level/keywords to what detections need.',
  refs: docRef('EnableTraceEx2'),
  query: '((call_expression function: (identifier) @_f arguments: (argument_list (_) @match)) (#eq? @_f "EnableTraceEx2"))',
  where: { match: { matches: '^(TRACE_LEVEL_VERBOSE|5|0x[fF]{16}(ULL|ull)?|ULLONG_MAX|~0(ULL|ull)?|MAXULONGLONG)$' } },
};

const openTraceCheck: CustomRule = {
  kind: 'custom',
  id: 'edr/etw-opentrace-check',
  title: 'OpenTrace failure checked against the wrong value',
  description: 'OpenTrace returns INVALID_PROCESSTRACE_HANDLE on failure. Comparing with INVALID_HANDLE_VALUE, NULL or 0 never detects the error (and 0 can be a valid handle on 32-bit), so ProcessTrace is called with a bad handle.',
  severity: 'error',
  languages: C_LANGS,
  message: '',
  refs: docRef('OpenTraceW'),
  async check(ctx) {
    const out: Finding[] = [];
    for (const s of (await callSites(ctx)).filter((x) => /^OpenTrace[AW]?$/.test(x.name))) {
      const parent = s.node.parent;
      const target =
        parent?.type === 'init_declarator'
          ? parent.childForFieldName('declarator')?.text
          : parent?.type === 'assignment_expression'
            ? parent.childForFieldName('left')?.text
            : undefined;
      const scope = enclosingFunction(s.node);
      if (!target || !scope) {
        continue;
      }
      for (const b of scope.descendantsOfType('binary_expression')) {
        if (!b) {
          continue;
        }
        const [l, r] = [b.childForFieldName('left')?.text, b.childForFieldName('right')?.text];
        const other = l === target ? r : r === target ? l : undefined;
        if (other && /^(INVALID_HANDLE_VALUE|NULL|nullptr|0)$/.test(other)) {
          out.push(ctx.report(b, `\`${target}\` from ${s.name} is compared with ${other}; check for INVALID_PROCESSTRACE_HANDLE instead.`));
        }
      }
    }
    return out;
  },
};

export const API_RULES: Rule[] = [missingCleanup, uncheckedStatus, deprecatedApi, esfAuthNoResponse, esfAuthOpenFlags, wfpServerName, wfpTransactions, etwVerbose, openTraceCheck];
