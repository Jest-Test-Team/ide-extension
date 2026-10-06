import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { classify } from '../src/runtime/classify';
import { runHarness } from '../src/runtime/run';
import { REPO } from './io';

const FX = join(REPO, 'packages/cli/test/fixtures/runtime');
const manifest = (name: string) => JSON.parse(readFileSync(join(FX, name, 'package.json'), 'utf8')) as Record<string, unknown>;

describe('runtime audit (headless harness)', () => {
  it('records and classifies a stealer-shaped extension', async () => {
    const run = await runHarness(join(FX, 'evil'), { duration: 1, offline: true });
    expect(run.timedOut).toBe(false);
    const c = classify(run.events, run.sandbox, { duration: 1, manifest: manifest('evil') });
    const by = Object.fromEntries(c.signals.map((s) => [s.id, s]));
    expect(Object.keys(by).sort()).toEqual([
      'runtime/child-process-spawned',
      'runtime/clipboard-poll-frequency',
      'runtime/dns-and-http-destinations',
      'runtime/dynamic-eval-execution',
      'runtime/fs-access-violation',
      'runtime/network-raw-socket',
    ]);
    expect(by['runtime/child-process-spawned'].message).toMatch(/curl -fsSL .*blocked by the audit.*downloads and runs code/);
    expect(by['runtime/child-process-spawned'].force).toBe('high');
    expect(by['runtime/fs-access-violation'].message).toContain('~/.ssh/id_rsa');
    expect(by['runtime/fs-access-violation'].force).toBe('high');
    expect(by['runtime/dns-and-http-destinations'].message).toMatch(/sent decoy secrets to c2-box\.duckdns\.org/);
    expect(by['runtime/dynamic-eval-execution'].weight).toBe(6);
    expect(by['runtime/clipboard-poll-frequency'].message).toMatch(/2 clipboard read/);
    expect(by['runtime/network-raw-socket'].message).toContain('UDP');
    // The location points into the extension's own file.
    expect(by['runtime/fs-access-violation'].locations[0].file).toMatch(/extension\.js$/);
    expect(c.api.map((e) => e.api)).toEqual(expect.arrayContaining(['commands.registerCommand', 'window.createTerminal', 'terminal.sendText']));
  }, 60_000);

  it('finds nothing worth reporting in an ordinary extension', async () => {
    const run = await runHarness(join(FX, 'benign'), { duration: 1, offline: true });
    const c = classify(run.events, run.sandbox, { duration: 1, manifest: manifest('benign') });
    expect(c.signals).toEqual([]);
    expect(c.errors).toEqual([]);
    expect(c.api.some((e) => e.api === 'commands.registerCommand' && e.id === 'benign.hello')).toBe(true);
  }, 60_000);
});
