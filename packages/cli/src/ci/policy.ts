import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

export type FailOn = 'high' | 'medium' | 'none';

/** Team policy for extension lists (`.github/jest-security.yml`). Every field is optional. */
export interface Policy {
  /** Fail when a new or changed extension reaches this risk level (default high). */
  failOn?: FailOn;
  /** Trusted extensions: `publisher.name` or `publisher.name@version`. */
  allowlist: string[];
  /** Never allowed: `publisher.name`, or `publisher.*` for a whole publisher. */
  blocked: string[];
  /** When non-empty, only these publishers may be added. */
  allowedPublishers: string[];
  /** Require a Marketplace-verified publisher domain. */
  requireVerifiedPublisher: boolean;
  /** Extra publishers treated as well known by the scoring. */
  trustedPublishers: string[];
}

export interface Violation {
  rule: 'policy/blocked' | 'policy/publisher-not-allowed' | 'policy/unverified-publisher';
  message: string;
}

export const EMPTY_POLICY: Policy = { allowlist: [], blocked: [], allowedPublishers: [], requireVerifiedPublisher: false, trustedPublishers: [] };

const KEYS = ['fail-on', 'allowlist', 'blocked', 'allowed-publishers', 'require-verified-publisher', 'trusted-publishers'];

function list(v: unknown, key: string, file: string): string[] {
  if (v === undefined || v === null) {
    return [];
  }
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
    throw new Error(`${file}: "${key}" must be a list of strings`);
  }
  return (v as string[]).map((s) => s.trim().toLowerCase()).filter(Boolean);
}

/** Parses a policy file (YAML or JSON). Unknown keys are errors, so typos do not silently weaken it. */
export function parsePolicy(text: string, file = 'policy'): Policy {
  const raw = (parseYaml(text) ?? {}) as Record<string, unknown>;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${file}: expected a mapping`);
  }
  const unknown = Object.keys(raw).filter((k) => !KEYS.includes(k));
  if (unknown.length) {
    throw new Error(`${file}: unknown key(s) ${unknown.join(', ')} (expected ${KEYS.join(', ')})`);
  }
  const failOn = raw['fail-on'];
  if (failOn !== undefined && !['high', 'medium', 'none'].includes(String(failOn))) {
    throw new Error(`${file}: "fail-on" must be high, medium or none`);
  }
  const verified = raw['require-verified-publisher'];
  if (verified !== undefined && typeof verified !== 'boolean') {
    throw new Error(`${file}: "require-verified-publisher" must be true or false`);
  }
  return {
    failOn: failOn as FailOn | undefined,
    allowlist: list(raw.allowlist, 'allowlist', file),
    blocked: list(raw.blocked, 'blocked', file),
    allowedPublishers: list(raw['allowed-publishers'], 'allowed-publishers', file),
    requireVerifiedPublisher: verified === true,
    trustedPublishers: list(raw['trusted-publishers'], 'trusted-publishers', file),
  };
}

export function loadPolicy(path: string): Policy {
  return parsePolicy(readFileSync(path, 'utf8'), path);
}

/**
 * Policy checks for one extension. `verified` is the Marketplace verification state (undefined
 * when it could not be determined, e.g. not on the Marketplace).
 */
export function evaluatePolicy(id: string, policy: Policy, verified: boolean | undefined): Violation[] {
  const lower = id.toLowerCase();
  const publisher = lower.split('.')[0];
  const out: Violation[] = [];
  const block = policy.blocked.find((b) => b === lower || b === `${publisher}.*`);
  if (block) {
    out.push({ rule: 'policy/blocked', message: `\`${lower}\` is blocked by the policy (${block}).` });
  }
  if (policy.allowedPublishers.length && !policy.allowedPublishers.includes(publisher)) {
    out.push({ rule: 'policy/publisher-not-allowed', message: `Publisher \`${publisher}\` is not on the policy's allowed-publishers list.` });
  }
  if (policy.requireVerifiedPublisher && verified !== true) {
    out.push({
      rule: 'policy/unverified-publisher',
      message: verified === false ? `Publisher \`${publisher}\` has no verified domain on the Marketplace.` : `Publisher verification for \`${publisher}\` could not be confirmed.`,
    });
  }
  return out;
}
