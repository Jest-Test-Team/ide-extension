import { cpSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { classify } from '../src/runtime/classify';
import { findOrphans, parseTrace } from '../src/runtime/dast';
import { runHarness } from '../src/runtime/run';
import { injectAgent } from '../src/runtime/vscode';
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

  it.runIf(process.platform !== 'win32')('reports and kills processes that outlive the extension (DAST)', async () => {
    const run = await runHarness(join(FX, 'daemon'), { duration: 1, offline: true, allowExec: true });
    const orphans = findOrphans(run.events);
    expect(orphans).toHaveLength(1);
    expect(orphans[0].command).toContain('sleep 30');
    expect(findOrphans(run.events)).toEqual([]); // killed
    const c = classify(run.events, run.sandbox, { duration: 1, manifest: manifest('daemon'), orphans });
    const o = c.signals.find((s) => s.id === 'runtime/orphan-process-daemon');
    expect(o?.force).toBe('high');
    expect(o?.message).toContain('sleep 30');
  }, 60_000);
});

describe('runtime audit helpers', () => {
  it('parses kernel probe output and subtracts the JIT baseline', () => {
    const k = parseTrace('Attaching 6 probes...\nREADY\nRAWSOCK 42 2 node\nRWX mprotect 42 4096 node\nRWX mmap 43 8192 helper\n');
    expect(k.rawSockets).toEqual([{ pid: 42, family: 2, comm: 'node' }]);
    expect(k.rwx).toHaveLength(2);
    const sb = { root: '/s', home: '/s/home', workspace: '/s/ws', ext: '/s/ext', log: '/s/l' };
    const ids = (baselineRwx: number) => classify([], sb, { duration: 1, manifest: {}, kernel: k, baselineRwx }).signals.map((s) => s.id);
    expect(ids(0)).toEqual(['runtime/network-raw-socket', 'runtime/mprotect-rwx']);
    expect(ids(2)).toEqual(['runtime/network-raw-socket']);
  });

  it('injects the agent ahead of the extension entry point', () => {
    const dir = mkdtempSync(join(tmpdir(), 'inject-'));
    cpSync(join(FX, 'benign'), dir, { recursive: true });
    injectAgent(dir);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { main: string };
    expect(pkg.main).toBe('./__jest_audit_main.js');
    const shim = readFileSync(join(dir, '__jest_audit_main.js'), 'utf8');
    expect(shim).toMatch(/audit-agent\.cjs/);
    expect(shim).toContain("require(\"./extension.js\")");
  });
});

describe('jest-security audit-extension', () => {
  it('refuses to run code without --yes', async () => {
    const { main } = await import('../src/security');
    const { captureIo } = await import('./io');
    const io = captureIo(REPO);
    expect(await main(['audit-extension', join(FX, 'evil')], io)).toBe(2);
    expect(io.stderr()).toContain('RUNS THE EXTENSION');
  });

  it('cross-references static findings with runtime evidence', async () => {
    const { main } = await import('../src/security');
    const { captureIo } = await import('./io');
    const io = captureIo(REPO);
    const code = await main(['audit-extension', join(FX, 'evil'), '--yes', '--offline', '--duration', '1', '--format', 'json', '--out', '-'], io);
    expect(code).toBe(1);
    const r = JSON.parse(io.stdout()) as { combined: { level: string }; chain: { confirmed: number; links: { vector: string; verdict: string }[] } };
    expect(r.combined.level).toBe('high');
    const verdict = Object.fromEntries(r.chain.links.map((l) => [l.vector, l.verdict]));
    expect(verdict).toMatchObject({ 'ext/ssh-keys': 'confirmed', 'ext/pipe-to-shell': 'confirmed', 'ext/command-override': 'confirmed', 'ext/terminal-injection': 'confirmed', 'ext/raw-socket': 'confirmed' });
    const benign = captureIo(REPO);
    expect(await main(['audit-extension', join(FX, 'benign'), '--yes', '--offline', '--duration', '1', '--format', 'json', '--out', '-'], benign)).toBe(0);
  }, 120_000);
});
