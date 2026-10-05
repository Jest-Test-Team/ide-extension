import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseMessage } from '../src/analyzers/protocol';
import { main } from '../src/security';
import { captureIo, REPO } from './io';

const MOCKS = join(REPO, 'packages/cli/test/fixtures/analyzers');
const DEEP = join(REPO, 'packages/cli/test/fixtures/deep-ext');
const posix = process.platform !== 'win32';

describe('analyzer protocol', () => {
  it('validates messages', () => {
    expect(parseMessage('{"type":"signal","ext":"a.b","vector":"ext/x","message":"m"}')?.type).toBe('signal');
    expect(parseMessage('{"type":"signal","ext":"a.b"}')).toBeUndefined();
    expect(parseMessage('{"type":"done","ran":[]}')?.type).toBe('done');
    expect(parseMessage('nope')).toBeUndefined();
  });
});

describe.runIf(posix)('deep scan with analyzers', () => {
  let saved: string | undefined;
  let savedCache: string | undefined;
  beforeEach(() => {
    saved = process.env.JEST_ANALYZERS_DIR;
    savedCache = process.env.XDG_CACHE_HOME;
    process.env.JEST_ANALYZERS_DIR = MOCKS;
    // Analyzers the developer installed into the real cache must not leak into these tests.
    process.env.XDG_CACHE_HOME = mkdtempSync(join(tmpdir(), 'jest-cache-'));
  });
  afterEach(() => {
    process.env.JEST_ANALYZERS_DIR = saved;
    process.env.XDG_CACHE_HOME = savedCache;
  });

  it('merges valid analyzer signals, rejects foreign vectors and reports coverage', async () => {
    const io = captureIo(REPO);
    await main(['scan-extension', DEEP, '--analyzers', 'rs', '--details', '--format', 'json', '--out', '-', '--fail-on', 'none'], io);
    const json = JSON.parse(io.stdout()) as {
      coverage: { vectorsRan: number; ran: Record<string, string[]>; analyzers: { engine: string; ran: number; errors: string[] }[] };
      results: { ext: { id: string }; risk: { signals: { id: string; locations: { file: string; finding: { range: { start: { line: number } } } }[] }[] } }[];
    };
    const sig = json.results[0].risk.signals.find((s) => s.id === 'ext/shell-exec');
    expect(sig?.locations[0].file).toMatch(/lib[\\/]extension\.js$/);
    expect(sig?.locations[0].finding.range.start.line).toBe(2);
    expect(json.results[0].risk.signals.some((s) => s.id === 'ext/python-exec')).toBe(false);
    expect(json.coverage.ran['ext/shell-exec']).toEqual(['ts', 'rs']);
    expect(json.coverage.ran['ext/process-exec']).toEqual(['ts']);
    const rs = json.coverage.analyzers.find((a) => a.engine === 'rs')!;
    expect(rs.ran).toBe(2);
    expect(rs.errors.join('\n')).toMatch(/not owned by the Rust analyzer/);
    expect(rs.errors.join('\n')).toMatch(/malformed output/);
  });

  it('prints a coverage table with --deep and names missing analyzers', async () => {
    const io = captureIo(REPO);
    await main(['scan-extension', DEEP, '--deep', '--format', 'text', '--fail-on', 'none'], io);
    const text = io.stdout();
    expect(text).toContain('== Coverage ==');
    expect(text).toMatch(/Coverage: \d+\/147 vectors ran \(TypeScript core, Rust analyzer 0\.0\.0-mock\)/);
    expect(text).toMatch(/Process & system\s+\S+\s+\d+\/19/);
    expect(text).toContain('Go analyzer: jest-ext-go not installed');
    expect(text).toContain('needs --online');
  });

  it('runs TypeScript only without --deep', async () => {
    const io = captureIo(REPO);
    await main(['scan-extension', DEEP, '--format', 'text', '--fail-on', 'none'], io);
    expect(io.stdout()).toMatch(/Coverage: 96\/147 vectors ran \(TypeScript core\)/);
    expect(io.stdout()).toContain('Run with --deep');
  });

  it('lists analyzers', async () => {
    const io = captureIo(REPO);
    expect(await main(['analyzers'], io)).toBe(0);
    expect(io.stdout()).toMatch(/✔ Rust analyzer\s+jest-ext-rs 0\.0\.0-mock: 3\/\d+ vectors/);
    expect(io.stdout()).toContain('– Go analyzer');
  });
});
