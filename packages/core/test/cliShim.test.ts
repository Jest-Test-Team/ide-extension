import { describe, expect, it } from 'vitest';
import { extensionsRootOf, parseShim, shimContent, shouldRefreshShim } from '../src/cliShim';

const ID = 'jest-test-team.hw-security';
const installed = (v: string) => `/Users/u/.vscode/extensions/${ID}-${v}/dist/cli/jest-hw.js`;
const RT = '/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)';

describe('CLI shims', () => {
  it('round-trips the recorded script path (POSIX and Windows)', () => {
    const odd = "/Users/o'neil/x/dist/cli/jest-hw.js";
    expect(parseShim(shimContent(ID, odd, RT, false))).toEqual({ extensionId: ID, script: odd });
    expect(parseShim(shimContent(ID, 'C:\\x\\jest-hw.js', 'C:\\Code.exe', true))).toEqual({ extensionId: ID, script: 'C:\\x\\jest-hw.js' });
    expect(parseShim('#!/bin/sh\necho hi\n')).toBeUndefined();
    expect(extensionsRootOf(installed('0.2.1'))).toBe('/Users/u/.vscode/extensions');
  });

  it('repoints after an update in the same extensions folder', () => {
    const shim = shimContent(ID, installed('0.2.0'), RT, false);
    expect(shouldRefreshShim(shim, ID, installed('0.2.1'), extensionsRootOf, () => true)).toBe(true);
    expect(shouldRefreshShim(shim, ID, installed('0.2.0'), extensionsRootOf, () => true)).toBe(false);
  });

  it('leaves shims of other editors / development copies alone while their target exists', () => {
    const fromCursor = shimContent(ID, `/Users/u/.cursor/extensions/${ID}-0.2.1/dist/cli/jest-hw.js`, RT, false);
    expect(shouldRefreshShim(fromCursor, ID, installed('0.2.1'), extensionsRootOf, () => true)).toBe(false);
    // …but takes over when the other target was removed.
    expect(shouldRefreshShim(fromCursor, ID, installed('0.2.1'), extensionsRootOf, () => false)).toBe(true);
    const devRepo = shimContent(ID, '/Users/u/repo/extensions/hw-security/dist/cli/jest-hw.js', RT, false);
    expect(shouldRefreshShim(devRepo, ID, installed('0.2.1'), extensionsRootOf, () => true)).toBe(false);
  });

  it('never touches shims of other extensions or foreign files', () => {
    expect(shouldRefreshShim(shimContent('other.ext', installed('0.2.0'), RT, false), ID, installed('0.2.1'), extensionsRootOf, () => false)).toBe(false);
    expect(shouldRefreshShim('#!/bin/sh\nexec something\n', ID, installed('0.2.1'), extensionsRootOf, () => false)).toBe(false);
  });
});
