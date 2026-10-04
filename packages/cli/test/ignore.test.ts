import { describe, expect, it } from 'vitest';
import { main } from '../src/security';
import { ignoreMatcher } from '../src/lib/files';
import { captureIo } from './io';

describe('ignore patterns', () => {
  it('matches gitignore-style globs', () => {
    const m = ignoreMatcher(['# comment', '', '**/test/fixtures/', '*.min.js', '/build', 'docs/**/*.md']);
    expect(m('extensions/hw/test/fixtures/a.c')).toBe(true);
    expect(m('test/fixtures')).toBe(true);
    expect(m('src/test/other.c')).toBe(false);
    expect(m('web/app.min.js')).toBe(true);
    expect(m('build/x.c')).toBe(true);
    expect(m('src/build/x.c')).toBe(false);
    expect(m('docs/a/b/c.md')).toBe(true);
    expect(m('docs/a.txt')).toBe(false);
  });

  it('skips .jestignore paths when walking but scans them when named explicitly', async () => {
    const all = captureIo();
    await main(['lint', 'extensions/hw-security', '--format', 'json', '--fail-on', 'none'], all);
    expect(all.stdout().trim()).toBe('[]');
    const named = captureIo();
    await main(['lint', 'extensions/hw-security/test/fixtures/esp-app', '--format', 'json', '--fail-on', 'none'], named);
    expect(named.stdout()).toContain('esp32/secure-boot-disabled');
    const noFile = captureIo();
    await main(['lint', 'extensions/hw-security', '--no-ignore-file', '--format', 'json', '--fail-on', 'none'], noFile);
    expect(noFile.stdout()).toContain('esp32/secure-boot-disabled');
    const extra = captureIo();
    await main(['lint', 'extensions/hw-security/test/fixtures/esp-app', '--ignore', 'sdkconfig', '--format', 'json', '--fail-on', 'none'], extra);
    expect(extra.stdout()).not.toContain('sdkconfig');
  });
});
