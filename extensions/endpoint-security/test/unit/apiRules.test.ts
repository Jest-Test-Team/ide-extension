import { RuleEngine, type Finding } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { CLEANUP, FUNCTIONS, signature, STATUS_FUNCTIONS } from '../../src/apiDb';
import { enclosingCall } from '../../src/callContext';
import { API_RULES } from '../../src/apiRules';

const engine = new RuleEngine(testHost(), API_RULES);
const lint = (file: string, languageId: string) => {
  const path = join(__dirname, '../fixtures/agent', file);
  return engine.run({ uri: `file://${path}`, path, languageId, text: readFileSync(path, 'utf8') });
};
const byRule = (fs: Finding[]) => {
  const m: Record<string, number[]> = {};
  fs.forEach((f) => (m[f.ruleId] ??= []).push(f.range.start.line + 1));
  return m;
};

describe('API database', () => {
  it('builds signatures and pairings', () => {
    expect(signature(FUNCTIONS.get('FwpmEngineClose0')!)).toBe('DWORD FwpmEngineClose0(HANDLE engineHandle);');
    expect(CLEANUP.es_new_client).toEqual(['es_delete_client']);
    expect(CLEANUP.StartTraceW).toContain('StopTraceW');
    expect(CLEANUP.FwpsCalloutRegister3).toContain('FwpsCalloutUnregisterByKey0');
    expect(STATUS_FUNCTIONS).toContain('es_subscribe');
    expect(STATUS_FUNCTIONS).not.toContain('FwpmEngineClose0');
    expect(STATUS_FUNCTIONS).not.toContain('OpenTraceW');
  });

  it('finds the enclosing call for signature help', () => {
    expect(enclosingCall('x = FwpmFilterAdd0(engine, &f, ')).toEqual({ name: 'FwpmFilterAdd0', arg: 2 });
    expect(enclosingCall('EnableTraceEx2(s, &g, f(a, b), ')).toEqual({ name: 'EnableTraceEx2', arg: 3 });
    expect(enclosingCall('foo(); bar')).toBeUndefined();
  });
});

describe('API rules', () => {
  it('Endpoint Security client', async () => {
    expect(byRule(await lint('esf_client.c', 'c'))).toEqual({
      'edr/missing-cleanup': [16],
      'edr/unchecked-status': [16],
      'edr/deprecated-api': [9, 11],
      'edr/esf-auth-no-response': [17],
    });
    const fix = (await lint('esf_client.c', 'c')).find((f) => f.fix)!;
    expect(fix.fix!.edits[0].newText).toBe('es_release_message');
  });

  it('WFP policy installer', async () => {
    expect(byRule(await lint('wfp_policy.c', 'c'))).toEqual({
      'edr/missing-cleanup': [7],
      'edr/unchecked-status': [11],
      'edr/wfp-server-name': [7],
      'edr/wfp-transaction': [11, 17],
    });
  });

  it('ETW consumer', async () => {
    expect(byRule(await lint('etw_consumer.cpp', 'cpp'))).toEqual({
      'edr/missing-cleanup': [9, 11],
      'edr/unchecked-status': [9, 10, 15],
      'edr/etw-broad-enable': [10],
      'edr/etw-opentrace-check': [12],
    });
  });

  it('Rust agent', async () => {
    expect(byRule(await lint('edr.rs', 'rust'))).toEqual({
      'edr/missing-cleanup': [7],
      'edr/unchecked-status': [7],
    });
  });
});
