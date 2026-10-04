// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../../src/ptree/agent';

const scenario = readFileSync(join(__dirname, '../fixtures/scenarios/ransom.ptree.yaml'), 'utf8');
const rules = readFileSync(join(__dirname, '../../data/ptree/default-rules.yaml'), 'utf8');

describe('simulation agent protocol', () => {
  it('answers ping and simulate', () => {
    expect(handle({ jsonrpc: '2.0', id: 1, method: 'ping' })).toMatchObject({ id: 1, result: { version: '1.0.0' } });
    const res = handle({ jsonrpc: '2.0', id: 2, method: 'simulate', params: { scenario, rules: [rules] } }) as { result: { detections: unknown[] } };
    expect(res.result.detections.length).toBe(10);
  });

  it('reports errors with the scenario line', () => {
    const res = handle({ jsonrpc: '2.0', id: 3, method: 'simulate', params: { scenario: 'events:\n  - { type: bogus, process: x }\n' } });
    expect(res).toMatchObject({ id: 3, error: { code: -32000, data: { line: 2 } } });
    expect(handle({ jsonrpc: '2.0', id: 4, method: 'nope' })).toMatchObject({ error: { code: -32601 } });
  });
});

describe('process tree webview', () => {
  const posted: { type: string; line?: number }[] = [];
  beforeAll(async () => {
    (globalThis as Record<string, unknown>).acquireVsCodeApi = () => ({ postMessage: (m: { type: string }) => posted.push(m), getState: () => undefined, setState: () => undefined });
    document.body.innerHTML = '<div id="app"></div>';
    await import('../../src/web/ptree');
  });

  it('renders tree, detections with ATT&CK links and a clickable timeline', () => {
    const { result } = handle({ jsonrpc: '2.0', id: 5, method: 'simulate', params: { scenario, rules: [rules] } }) as { result: unknown };
    window.dispatchEvent(new MessageEvent('message', { data: { type: 'simulation', file: 'ransom.ptree.yaml', result } }));
    const app = document.getElementById('app')!;
    expect(app.querySelectorAll('svg g').length).toBe(7);
    expect([...app.querySelectorAll('a')].some((a) => a.getAttribute('href') === 'https://attack.mitre.org/techniques/T1003/001/')).toBe(true);
    (app.querySelector('td .link') as HTMLElement).click();
    expect(posted.at(-1)).toEqual({ type: 'reveal', line: 15 });
  });
});
