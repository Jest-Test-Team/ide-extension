// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { parsePufCsv } from '../../src/entropy/parse';
import { pufMetrics } from '../../src/entropy/puf';
import { nonIidAssessment } from '../../src/entropy/sp80090b';

const posted: { type: string; content?: string }[] = [];
const send = (data: unknown) => window.dispatchEvent(new MessageEvent('message', { data }));

beforeAll(async () => {
  (globalThis as Record<string, unknown>).acquireVsCodeApi = () => ({ postMessage: (m: { type: string }) => posted.push(m), getState: () => undefined, setState: () => undefined });
  document.body.innerHTML = '<div id="app"></div>';
  await import('../../src/web/report');
});

describe('HW report webview', () => {
  const app = () => document.getElementById('app')!;

  it('renders an entropy assessment with charts and exports Markdown', () => {
    const data = new Uint8Array(readFileSync(join(__dirname, '../fixtures/entropy/rand8_short.bin')));
    const result = nonIidAssessment(data, { wordSize: 8 });
    send({ type: 'entropy', name: 'rand8_short.bin', result, histogram: new Array(256).fill(39) });
    expect(app().querySelector('h1')?.textContent).toContain('SP 800-90B');
    expect(app().querySelectorAll('svg').length).toBe(2);
    expect(app().textContent).toContain('◀ min');
    const exportMd = [...app().querySelectorAll('button')].find((b) => b.textContent === 'Export Markdown')!;
    exportMd.click();
    expect(posted.at(-1)?.content).toContain('Assessed min-entropy: 5.860894');
  });

  it('renders PUF metrics with a two-series legend', () => {
    const report = pufMetrics(parsePufCsv(readFileSync(join(__dirname, '../fixtures/puf/sram.csv'), 'utf8')));
    send({ type: 'puf', name: 'sram.csv', report, ecc: { n: 255, target: 1e-6, t: 30, failureAtT: 5e-7 } });
    expect(app().textContent).toContain('Inter-device (uniqueness)');
    expect(app().textContent).toContain('Intra-device (reliability)');
    expect(app().querySelectorAll('svg path').length).toBeGreaterThan(2);
  });

  it('renders a restart result', () => {
    send({ type: 'restart', name: 'r.bin', result: { rows: 1000, cols: 1000, hI: 1.2, xMax: 450, xCutoff: 470, sanityPassed: true, hRow: 1.3, hCol: 1.29, passed: true, simulationRounds: 1000 } });
    expect(app().textContent).toContain('✔ Passed');
  });
});
