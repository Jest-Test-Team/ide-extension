import type { CustomRule, Finding, RuleContext, RuleRef } from '@ide-ext/core';
import type { Node } from 'web-tree-sitter';

const GO_TS = ['go', 'typescript', 'javascript', 'typescriptreact', 'javascriptreact'];
const PCI: RuleRef = { label: 'PCI DSS v4.0.1 (PCI SSC document library)', url: 'https://www.pcisecuritystandards.org/document_library/' };
const CCSP: RuleRef = { label: 'ISC2 CCSP Exam Outline — Domain 2: Cloud Data Security', url: 'https://www.isc2.org/certifications/ccsp/ccsp-certification-exam-outline' };

const snake = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

/** Account data per PCI DSS: PAN and sensitive authentication data (CVV, track, PIN block). */
const SENSITIVE = /(^|_)(pan|primary_account(_number)?|card_?(number|num|no)|cc_?(number|num)|credit_card(_number)?|cvv2?|cvc2?|card_verification(_code|_value)?|track_?[12]?(_data)?|pin_?block|ssn|social_security(_number)?)(_|$)/;
const isSensitiveName = (name: string) => SENSITIVE.test(snake(name));
const SANITIZER = /(mask|redact|truncate|last_?4|last_?four|hash|tokeni[sz]e|encrypt|hmac|bcrypt|scrypt|argon|sha256|digest)/i;

const NAME_TYPES = ['identifier', 'field_identifier', 'property_identifier', 'shorthand_property_identifier'];
const FUNCTION_TYPES = ['function_declaration', 'method_declaration', 'func_literal', 'method_definition', 'arrow_function', 'function_expression', 'function'];

function calleeName(call: Node): string {
  const fn = call.childForFieldName('function');
  return fn?.text ?? '';
}

/** Identifier-like descendants of `expr` that are not inside a sanitising call. */
function exposedNames(expr: Node): Node[] {
  const out: Node[] = [];
  const visit = (n: Node) => {
    if (n.type === 'call_expression' && SANITIZER.test(calleeName(n))) {
      return;
    }
    if (NAME_TYPES.includes(n.type)) {
      out.push(n);
    }
    for (const c of n.namedChildren) {
      if (c) {
        visit(c);
      }
    }
  };
  visit(expr);
  return out;
}

function exposesSensitive(expr: Node, tainted: Set<string>): Node | undefined {
  return exposedNames(expr).find((n) => tainted.has(n.text) || isSensitiveName(n.text));
}

const GO_LOG = /^(log\.(Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)|fmt\.(Print|Printf|Println|Fprint|Fprintf|Fprintln)|slog\.(Info|Debug|Warn|Error|Log)|[\w.]+\.(Info|Infof|Infow|Debug|Debugf|Debugw|Warn|Warnf|Warnw|Error|Errorf|Errorw|Fatal|Fatalf|WithField|WithFields|Msg|Msgf|Str|Interface|Print|Printf|Println))$/;
const TS_LOG = /^(console\.(log|info|debug|warn|error|trace|dir)|[\w$.]*(log|logger|winston|pino|bunyan)\w*\.(log|info|debug|warn|error|trace|fatal|verbose|silly))$/i;

/** Assignment-like statements: [targets, value]. */
function assignment(n: Node): [Node[], Node] | undefined {
  switch (n.type) {
    case 'short_var_declaration':
    case 'assignment_statement': {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      return left && right ? [left.namedChildren.filter((c): c is Node => c !== null), right] : undefined;
    }
    case 'var_spec':
    case 'const_spec': {
      const value = n.childForFieldName('value');
      const names = n.namedChildren.filter((c): c is Node => c !== null && c.type === 'identifier');
      return value ? [names, value] : undefined;
    }
    case 'variable_declarator': {
      const name = n.childForFieldName('name');
      const value = n.childForFieldName('value');
      return name && value ? [[name], value] : undefined;
    }
    case 'assignment_expression': {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      return left && right ? [[left], right] : undefined;
    }
  }
  return undefined;
}

export const sensitiveLogging: CustomRule = {
  kind: 'custom',
  id: 'pci/account-data-logged',
  title: 'Account data written to logs',
  description:
    'PAN or sensitive authentication data (CVV, track data, PIN block) reaches a logging call. Logs are storage: PAN there must be unreadable (PCI DSS 3.5.1) and SAD must not be retained after authorisation (3.3.1). Mask (first 6 / last 4), tokenise or drop the value before logging. Tracks values through local assignments within a function.',
  severity: 'error',
  languages: GO_TS,
  message: '',
  refs: [
    { label: 'PCI DSS 3.3.1 (SAD not retained) and 3.5.1 (PAN unreadable where stored)', url: PCI.url },
    { label: 'CCSP Domain 2 — data loss prevention', url: CCSP.url },
    { label: 'CWE-532: Insertion of Sensitive Information into Log File', url: 'https://cwe.mitre.org/data/definitions/532.html' },
  ],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const sink = ctx.grammar === 'go' ? GO_LOG : TS_LOG;
    const out: Finding[] = [];
    const roots = ctx.tree.rootNode.descendantsOfType(FUNCTION_TYPES).filter((n): n is Node => n !== null);
    const seen = new Set<number>();
    for (const fn of roots) {
      const tainted = new Set<string>();
      // Statements and calls in source order (descendantsOfType returns document order).
      for (const n of fn.descendantsOfType(['short_var_declaration', 'assignment_statement', 'var_spec', 'const_spec', 'variable_declarator', 'assignment_expression', 'call_expression'])) {
        if (!n) {
          continue;
        }
        if (n.type === 'call_expression') {
          if (!sink.test(calleeName(n)) || seen.has(n.id)) {
            continue;
          }
          const args = n.childForFieldName('arguments');
          const hit = args && exposesSensitive(args, tainted);
          if (hit) {
            seen.add(n.id);
            out.push(ctx.report(hit, `\`${hit.text}\` (account data) is passed to \`${calleeName(n)}\`; mask or tokenise it before logging.`));
          }
          continue;
        }
        const a = assignment(n);
        if (a && exposesSensitive(a[1], tainted)) {
          a[0].forEach((t) => tainted.add(t.text));
        }
      }
    }
    return out;
  },
};

export const storageWithoutKms: CustomRule = {
  kind: 'custom',
  id: 'ccsp/s3-without-sse',
  title: 'Object written without explicit server-side encryption',
  description:
    'S3 encrypts new objects with SSE-S3 by default, but key ownership, rotation and access separation (CCSP Domain 2 key management; PCI DSS 3.6/3.7) require choosing SSE-KMS with a customer-managed key explicitly.',
  severity: 'info',
  languages: GO_TS,
  message: '',
  refs: [
    { label: 'CCSP Domain 2 — data storage security, encryption and key management', url: CCSP.url },
    { label: 'AWS — Protecting data with server-side encryption', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html' },
  ],
  async check(ctx) {
    const q =
      ctx.grammar === 'go'
        ? '((composite_literal type: (_) @_t body: (literal_value) @body) @match (#match? @_t "PutObjectInput$|CreateMultipartUploadInput$"))'
        : `((new_expression constructor: (identifier) @_t arguments: (arguments (object) @body)) @match (#match? @_t "^(PutObjectCommand|CreateMultipartUploadCommand)$"))
           ((call_expression function: (member_expression property: (property_identifier) @_t) arguments: (arguments (object) @body)) @match (#match? @_t "^(putObject|upload|createMultipartUpload)$"))`;
    const out: Finding[] = [];
    for (const m of await ctx.matches(q)) {
      const body = m.captures.find((c) => c.name === 'body')?.node;
      const type = m.captures.find((c) => c.name === '_t')?.node;
      if (body && type && !/ServerSideEncryption|SSEKMSKeyId|SSECustomerKey/.test(body.text)) {
        out.push(ctx.report(type, `\`${type.text}\` does not set ServerSideEncryption (e.g. aws:kms with a customer-managed key).`));
      }
    }
    return out;
  },
};

export const presignedExpiry: CustomRule = {
  kind: 'custom',
  id: 'ccsp/presigned-url-expiry',
  title: 'Long-lived pre-signed URL',
  description: 'A pre-signed URL is a bearer credential; anyone holding it can read the object until it expires. Keep lifetimes short (minutes) for sensitive data.',
  severity: 'info',
  languages: GO_TS,
  message: '',
  refs: [{ label: 'CCSP Domain 2 — data access controls / data in transit', url: CCSP.url }],
  check(ctx) {
    const out: Finding[] = [];
    const maxSeconds = 3600;
    const ts = /\bexpiresIn\s*:\s*(\d[\d_]*)(?:\s*\*\s*(\d+))?(?:\s*\*\s*(\d+))?/g;
    const go = /WithPresignExpires\(\s*(\d+)\s*\*\s*time\.(Hour|Minute|Second)\s*\)|Expires\s*:\s*(\d+)\s*\*\s*time\.(Hour|Minute)/g;
    const unit: Record<string, number> = { Hour: 3600, Minute: 60, Second: 1 };
    const re = ctx.grammar === 'go' ? go : ts;
    for (const m of ctx.text.matchAll(re)) {
      const seconds =
        ctx.grammar === 'go'
          ? Number(m[1] ?? m[3]) * unit[m[2] ?? m[4]]
          : Number(m[1].replace(/_/g, '')) * Number(m[2] ?? 1) * Number(m[3] ?? 1);
      if (seconds > maxSeconds) {
        const start = m.index ?? 0;
        out.push(ctx.report(ctx.lines.rangeOf(start, start + m[0].length), `Pre-signed URL lives ${Math.round(seconds / 3600)} h; keep sensitive-data links short-lived (≤ 1 h).`));
      }
    }
    return out;
  },
};

export const COMPLIANCE_CUSTOM_RULES = [sensitiveLogging, storageWithoutKms, presignedExpiry];
