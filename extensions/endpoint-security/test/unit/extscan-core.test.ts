import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadManifestOptions } from '../../src/extscan/data';
import { parseRemovedPackages, removalVerdict } from '../../src/extscan/knownBad';
import { manifestSignals, type ExtInfo } from '../../src/extscan/manifest';
import { isAllowlisted, scoreExtension } from '../../src/extscan/score';
import { signal, SIGNALS, signalIdOf } from '../../src/extscan/signals';
import { editDistance, findTyposquat, foldHomoglyphs } from '../../src/extscan/typosquat';

const opts = loadManifestOptions(join(__dirname, '../../data/extscan'));

function ext(id: string, pkg: Record<string, unknown> = {}, extra: Partial<ExtInfo> = {}): ExtInfo {
  const packageJSON = { name: id.split('.')[1], publisher: id.split('.')[0], version: '1.0.0', ...pkg };
  return { id, version: '1.0.0', path: `/exts/${id}-1.0.0`, packageJSON, packageJsonText: JSON.stringify(packageJSON, null, 2), builtin: false, ...extra };
}
const ids = (e: ExtInfo) => manifestSignals(e, opts).map((s) => s.id).sort();

describe('typosquat', () => {
  it('edit distance with transpositions and early exit', () => {
    expect(editDistance('python', 'pyhton')).toBe(1);
    expect(editDistance('kitten', 'sitting')).toBe(3);
    expect(editDistance('abc', 'abcdefgh', 2)).toBe(3);
  });

  it('flags near-misses of popular IDs but not same-publisher siblings', () => {
    expect(findTyposquat('ms-pythom.python', opts.popular)).toMatchObject({ target: 'ms-python.python', distance: 1 });
    expect(findTyposquat('esbenpp.prettier-vscode', opts.popular)?.target).toBe('esbenp.prettier-vscode');
    expect(findTyposquat('ms-python.python', opts.popular)).toBeUndefined();
    expect(findTyposquat('ms-python.pylint', opts.popular)).toBeUndefined();
    expect(findTyposquat('jest-test-team.endpoint-security', opts.popular)).toBeUndefined();
  });

  it('folds homoglyphs', () => {
    expect(foldHomoglyphs('rn5-pyth0n.python')).toBe(foldHomoglyphs('ms-python.python'));
    expect(findTyposquat('dbaeurner.vscode-es1int', opts.popular)).toMatchObject({ target: 'dbaeumer.vscode-eslint', reason: 'homoglyph' });
  });
});

describe('known-bad list', () => {
  const md = [
    '| Extension Identifier | Removal Date | Type |',
    '|---|---|---|',
    '| Evil.Stealer | 10/03/2026 | Malware |',
    '| spam.thing | 4/7/2025 | Spam',
    '| fake.prettier | 1/2/2025 | Impersonation |',
    'not a row',
  ].join('\n');

  it('parses rows with and without a trailing pipe', () => {
    expect(parseRemovedPackages(md)).toEqual([
      { id: 'evil.stealer', date: '10/03/2026', type: 'Malware' },
      { id: 'spam.thing', date: '4/7/2025', type: 'Spam' },
      { id: 'fake.prettier', date: '1/2/2025', type: 'Impersonation' },
    ]);
  });

  it('maps removal reasons to weights', () => {
    expect(removalVerdict('Malware')).toEqual({ weight: 10, force: 'high' });
    expect(removalVerdict('Impersonation, Malware').force).toBe('high');
    expect(removalVerdict('Potentially malicious').force).toBe('high');
    expect(removalVerdict('Untrustworthy')).toEqual({ weight: 6 });
    expect(removalVerdict('Spam')).toEqual({ weight: 0 });
    expect(removalVerdict('Owner Request')).toEqual({ weight: 0 });
  });

  it('bundled snapshot is large and indexed by lower-case id', () => {
    expect(opts.knownBad.size).toBeGreaterThan(1000);
    expect([...opts.knownBad.keys()].every((k) => k === k.toLowerCase())).toBe(true);
  });
});

describe('manifest signals', () => {
  it('well-known publisher from the Marketplace gets credit; the same publisher sideloaded does not', () => {
    expect(ids(ext('golang.go', { activationEvents: ['onLanguage:go'] }, { source: 'gallery' }))).toEqual(['ext/trusted-publisher']);
    expect(ids(ext('golang.go', {}, { source: 'vsix' }))).toEqual(['ext/sideloaded']);
    expect(ids(ext('golang.go', {}, { builtin: true }))).toEqual([]);
  });

  it('flags startup activation, untrusted workspaces, many dependencies, sideloading, unknown publisher', () => {
    const e = ext(
      'someone.helper',
      {
        activationEvents: ['*'],
        capabilities: { untrustedWorkspaces: { supported: true } },
        extensionDependencies: ['a.a', 'b.b', 'c.c', 'd.d'],
      },
      { source: 'vsix' },
    );
    expect(ids(e)).toEqual([
      'ext/activates-on-startup',
      'ext/many-dependencies',
      'ext/sideloaded',
      'ext/unknown-publisher',
      'ext/untrusted-workspace',
    ]);
    const startup = manifestSignals(e, opts).find((s) => s.id === 'ext/activates-on-startup')!;
    expect(startup.locations[0].file).toBe('/exts/someone.helper-1.0.0/package.json');
    expect(startup.locations[0].finding.range.start.line).toBe(5);
  });

  it('onStartupFinished is the weaker startup signal; limited untrusted support is fine', () => {
    expect(ids(ext('github.foo', { activationEvents: ['onStartupFinished'], capabilities: { untrustedWorkspaces: { supported: 'limited' } } }))).toEqual([
      'ext/activates-after-startup',
      'ext/trusted-publisher',
    ]);
  });

  it('typosquat and known-bad', () => {
    expect(ids(ext('ms-pythom.python'))).toEqual(['ext/typosquat', 'ext/unknown-publisher']);
    const bad = [...opts.knownBad.values()].find((e) => e.type === 'Malware')!;
    const s = manifestSignals(ext(bad.id), opts).find((x) => x.id === 'ext/known-bad')!;
    expect(s).toMatchObject({ weight: 10, force: 'high' });
  });
});

describe('scoring', () => {
  const sig = (id: string, count = 1) => signal(id, id, [], { count });

  it('a language server that spawns processes stays low', () => {
    const r = scoreExtension([sig('ext/process-exec', 12), sig('ext/native-binary'), sig('ext/dynamic-code'), sig('ext/activates-after-startup')]);
    expect(r).toMatchObject({ score: 4, level: 'low' });
  });

  it('counts each signal once and merges duplicates', () => {
    const r = scoreExtension([sig('ext/hardcoded-ip', 3), sig('ext/hardcoded-ip', 2)]);
    expect(r.signals).toHaveLength(1);
    expect(r.signals[0].count).toBe(5);
    expect(r.score).toBe(SIGNALS['ext/hardcoded-ip'].weight);
  });

  it('credential access plus exfiltration endpoint is high', () => {
    const r = scoreExtension([sig('ext/credential-path'), sig('ext/exfil-endpoint')]);
    expect(r.boosts.map((b) => b.because)).toEqual([['ext/credential-path', 'ext/exfil-endpoint']]);
    expect(r).toMatchObject({ score: 10, level: 'high' });
  });

  it('unknown publisher + startup + process exec gets the combination boost', () => {
    const r = scoreExtension([sig('ext/unknown-publisher'), sig('ext/activates-on-startup'), sig('ext/process-exec')]);
    expect(r).toMatchObject({ score: 5, level: 'medium' });
    const squat = scoreExtension([sig('ext/typosquat'), sig('ext/unknown-publisher'), sig('ext/activates-on-startup'), sig('ext/process-exec')]);
    expect(squat).toMatchObject({ score: 9, level: 'high' });
  });

  it('capabilities alone are capped at medium; a combination unlocks high', () => {
    const caps = [sig('ext/credential-path'), sig('ext/input-capture'), sig('ext/obfuscated'), sig('ext/native-binary')];
    expect(scoreExtension(caps)).toMatchObject({ score: 9, level: 'medium', capped: true });
    expect(scoreExtension([...caps, sig('ext/exfil-endpoint')])).toMatchObject({ level: 'high', capped: false });
  });

  it('known malware forces high even when allowlisted', () => {
    const bad = signal('ext/known-bad', 'removed', [], { weight: 10, force: 'high' });
    expect(scoreExtension([bad]).level).toBe('high');
    expect(scoreExtension([bad], { allowlisted: true })).toMatchObject({ level: 'high', allowlistOverridden: true });
  });

  it('allowlisting zeroes the score but keeps the reasons', () => {
    const r = scoreExtension([sig('ext/credential-path'), sig('ext/exfil-endpoint')], { allowlisted: true });
    expect(r).toMatchObject({ score: 0, level: 'low', allowlisted: true });
    expect(r.signals).toHaveLength(2);
  });

  it('verified publisher lowers the score but never below zero', () => {
    expect(scoreExtension([sig('ext/verified-publisher')]).score).toBe(0);
  });

  it('allowlist entries with and without version pins', () => {
    expect(isAllowlisted('Foo.Bar', '1.2.3', ['foo.bar'])).toBe(true);
    expect(isAllowlisted('foo.bar', '1.2.3', ['foo.bar@1.2.3'])).toBe(true);
    expect(isAllowlisted('foo.bar', '1.2.4', ['foo.bar@1.2.3'])).toBe(false);
    expect(isAllowlisted('foo.baz', '1.2.3', ['foo.bar'])).toBe(false);
  });

  it('maps code rule ids to signals', () => {
    expect(signalIdOf('ext/dynamic-code.require')).toBe('ext/dynamic-code');
    expect(signalIdOf('ext/typosquat')).toBe('ext/typosquat');
  });
});
