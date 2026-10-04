// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseProfile } from '../../src/profile';

const posted: { type: string }[] = [];

beforeAll(async () => {
  (globalThis as Record<string, unknown>).acquireVsCodeApi = () => ({
    postMessage: (m: { type: string }) => posted.push(m),
    getState: () => undefined,
    setState: () => undefined,
  });
  document.body.innerHTML = '<div id="app"></div>';
  await import('../../src/web/report');
});

describe('report webview', () => {
  it('announces readiness and renders the profile', async () => {
    expect(posted[0]).toEqual({ type: 'ready' });
    const profile = parseProfile(readFileSync(join(__dirname, '../fixtures/invdemo.profile.json'), 'utf8'));
    window.dispatchEvent(new MessageEvent('message', { data: { type: 'profile', profile } }));
    const app = document.getElementById('app')!;
    expect(app.querySelector('h1')?.textContent).toContain('InvDemo');
    expect(app.querySelectorAll('svg rect').length).toBeGreaterThan(5);
    expect(app.querySelectorAll('table').length).toBe(2);
    // Clicking a source link asks the host to open it.
    (app.querySelector('table .link') as HTMLElement).click();
    expect(posted.at(-1)?.type).toBe('openLocation');
  });
});
