import { RuleEngine, type Finding } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { COMPLIANCE_CUSTOM_RULES } from '../../src/complianceRules';
import { loadBuiltInPacks, rulesOf } from '../../src/rulePacks';

const packs = loadBuiltInPacks(join(__dirname, '../../data/rules'));
const engine = new RuleEngine(testHost(), [...rulesOf(packs), ...COMPLIANCE_CUSTOM_RULES]);
const lint = (file: string, languageId: string) => {
  const path = join(__dirname, '../fixtures/backend', file);
  return engine.run({ uri: `file://${path}`, path, languageId, text: readFileSync(path, 'utf8') });
};
const byRule = (fs: Finding[]) => {
  const m: Record<string, number[]> = {};
  fs.forEach((f) => (m[f.ruleId] ??= []).push(f.range.start.line + 1));
  Object.values(m).forEach((v) => v.sort((a, b) => a - b));
  return m;
};

describe('compliance packs', () => {
  it('load without errors', () => {
    expect(packs.map((p) => p.id)).toEqual(['ccsp-d2', 'pci-dss-4.0.1']);
    expect(rulesOf(packs).every((r) => r.refs?.length)).toBe(true);
  });

  it('Go payment service', async () => {
    expect(byRule(await lint('payments.go', 'go'))).toEqual({
      'pci/hardcoded-credential': [15],
      'pci/pan-literal': [16],
      'pci/tls-verification-disabled': [18],
      'pci/weak-tls-version': [18],
      'pci/account-data-logged': [23],
      'pci/weak-crypto': [25],
      'pci/sql-injection': [26],
      'pci/cleartext-http': [27],
      'ccsp/sensitive-in-url': [27],
      'ccsp/s3-without-sse': [33],
      'ccsp/public-object-acl': [33],
    });
  });

  it('TypeScript SOAR service', async () => {
    expect(byRule(await lint('payments.ts', 'typescript'))).toEqual({
      'pci/tls-verification-disabled': [7],
      'pci/weak-tls-version': [7],
      'pci/hardcoded-credential': [8],
      'pci/account-data-logged': [13, 14],
      'pci/weak-crypto': [16],
      'pci/sql-injection': [17],
      'ccsp/s3-without-sse': [18],
      'ccsp/presigned-url-expiry': [19],
    });
  });
});
