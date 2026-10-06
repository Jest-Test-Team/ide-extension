import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ExtInfo, ManifestOptions } from '../../src/extscan/manifest';
import { combinedSignals, declaresTelemetry, DEEP_MANIFEST_VECTORS, deepManifestSignals, unusualEntry, withoutDeclared } from '../../src/extscan/manifestDeep';
import { signal } from '../../src/extscan/signals';

const opts: ManifestOptions = { trustedPublishers: new Set(['microsoft', 'ms-python']), popular: ['ms-python.python', 'esbenp.prettier-vscode'], knownBad: new Map() };

function ext(pkg: Record<string, unknown>, files: Record<string, string> = {}): ExtInfo {
  const dir = mkdtempSync(join(tmpdir(), 'mf-'));
  for (const [f, c] of Object.entries(files)) {
    writeFileSync(join(dir, f), c);
  }
  const text = JSON.stringify(pkg, null, 2);
  return { id: `${pkg.publisher}.${pkg.name}`, version: '1.0.0', path: dir, packageJSON: pkg, packageJsonText: text, builtin: false };
}

const EVIL = {
  publisher: 'evilcorp',
  name: 'python',
  displayName: 'Microsoft Python Tools',
  main: './.cache/a8f3e2b1c9d04f7e.js',
  activationEvents: ['onUri', 'workspaceContains:**/*'],
  extensionKind: ['workspace'],
  extensionDependencies: ['shady.helper'],
  scripts: { postinstall: 'node x.js' },
  contributes: {
    terminal: { profiles: [{ id: 'x', title: 'X' }] },
    taskDefinitions: [{ type: 'x' }],
    debuggers: [{ type: 'evil', program: './bin/adapter' }],
    authentication: [{ id: 'gh', label: 'GitHub' }],
    keybindings: [{ key: 'ctrl+v', command: 'evil.paste' }],
    configurationDefaults: { 'security.workspace.trust.enabled': false, 'http.proxy': 'http://1.2.3.4:8080', 'terminal.integrated.env.osx': { NODE_OPTIONS: '--require x' } },
    jsonValidation: [{ fileMatch: '*.json', url: 'https://evil.example/schema.json' }],
    walkthroughs: [{ steps: [{ media: { image: 'https://evil.example/pixel.png' } }] }],
  },
};

describe('deep manifest vectors', () => {
  it('detects every manifest vector on a hostile manifest', () => {
    const e = ext(EVIL);
    const base = [...deepManifestSignals(e, opts), signal('ext/process-exec', 'loads child_process')];
    const ids = new Set([...base, ...combinedSignals(e, base)].map((s) => s.id));
    for (const v of DEEP_MANIFEST_VECTORS) {
      expect(ids.has(v), v).toBe(true);
    }
    const sec = deepManifestSignals(e, opts).find((s) => s.id === 'ext/security-setting-defaults')!;
    expect(sec.locations[0].finding.range.start.line).toBeGreaterThan(0);
  });

  it('stays quiet on a well-formed manifest', () => {
    const e = ext(
      {
        publisher: 'acme',
        name: 'tidy',
        displayName: 'Tidy',
        main: './out/extension.js',
        license: 'MIT',
        repository: { type: 'git', url: 'https://github.com/acme/tidy' },
        activationEvents: ['onLanguage:markdown'],
        contributes: { keybindings: [{ key: 'ctrl+v', command: 'tidy.paste', when: 'editorLangId == markdown' }] },
      },
      { LICENSE: 'MIT' },
    );
    expect(deepManifestSignals(e, opts)).toEqual([]);
    expect(combinedSignals(e, [signal('ext/process-exec', 'x')])).toEqual([]);
  });

  it('judges entry points', () => {
    expect(unusualEntry('./out/extension.js')).toBeUndefined();
    expect(unusualEntry('./dist/web/extension.js')).toBeUndefined();
    expect(unusualEntry('extension.js')).toBeUndefined();
    expect(unusualEntry('./.hidden/x.js')).toMatch(/hidden/);
    expect(unusualEntry('./node_modules/x/index.js')).toMatch(/node_modules/);
    expect(unusualEntry('./out/k3j9x2m8q7z1.js')).toMatch(/random/);
    expect(unusualEntry('./assets/img/run.js')).toMatch(/outside/);
  });

  it('drops third-party tracking when the extension declares telemetry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tele-'));
    const ext = (pkg: Record<string, unknown>): ExtInfo => ({ id: 'a.b', version: '1.0.0', path: dir, packageJSON: pkg, builtin: false });
    const sigs = [signal('ext/telemetry-unauthorized', 'mixpanel'), signal('ext/network-outbound', 'https')];
    expect(withoutDeclared(ext({}), sigs).map((x) => x.id)).toEqual(['ext/telemetry-unauthorized', 'ext/network-outbound']);
    const tagged = { contributes: { configuration: { properties: { 'b.telemetry': { type: 'boolean', tags: ['telemetry'] } } } } };
    expect(declaresTelemetry(ext(tagged))).toBe(true);
    expect(declaresTelemetry(ext({ dependencies: { '@vscode/extension-telemetry': '^1' } }))).toBe(true);
    writeFileSync(join(dir, 'telemetry.json'), '{}');
    expect(withoutDeclared(ext({}), sigs).map((x) => x.id)).toEqual(['ext/network-outbound']);
  });
});
