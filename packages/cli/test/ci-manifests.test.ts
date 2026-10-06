import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { diffManifests, readManifestsAtRef, resolveRef, toScan } from '../src/ci/diff';
import { discoverManifests, isManifestPath, parseManifest, readManifests, stripJsonc } from '../src/ci/manifests';

const brief = (es: { id: string; version?: string; line: number; kind: string; remove?: boolean }[]) =>
  es.map((e) => `${e.line}:${e.kind}:${e.remove ? '-' : ''}${e.id}${e.version ? '@' + e.version : ''}`);

describe('manifest parsing', () => {
  it('strips JSONC comments and trailing commas but not string content', () => {
    const t = '{ "a": "x // not a comment, ]", /* block\n comment */ "b": [1, 2,], }';
    expect(JSON.parse(stripJsonc(t))).toEqual({ a: 'x // not a comment, ]', b: [1, 2] });
    expect(stripJsonc(t).split('\n')).toHaveLength(2);
  });

  it('.vscode/extensions.json with comments, unwanted and invalid entries', () => {
    const text = [
      '{',
      '  // team standard',
      '  "recommendations": [',
      '    "dbaeumer.vscode-eslint",',
      '    "Esbenp.Prettier-VSCode",',
      '    "not an id",',
      '  ],',
      '  "unwantedRecommendations": ["ms-vscode.vscode-typescript-tslint-plugin"]',
      '}',
    ].join('\n');
    expect(brief(parseManifest('.vscode/extensions.json', text))).toEqual([
      '4:recommendation:dbaeumer.vscode-eslint',
      '5:recommendation:esbenp.prettier-vscode',
      '8:unwanted:ms-vscode.vscode-typescript-tslint-plugin',
    ]);
  });

  it('dev container with pinned versions and removals; legacy top-level list', () => {
    const text = '{\n "customizations": { "vscode": { "extensions": [\n  "golang.go@0.42.0",\n  "-ms-azuretools.vscode-docker"\n ] } }\n}';
    expect(brief(parseManifest('.devcontainer/devcontainer.json', text))).toEqual(['3:devcontainer:golang.go@0.42.0', '4:devcontainer:-ms-azuretools.vscode-docker']);
    expect(brief(parseManifest('.devcontainer.json', '{ "extensions": ["rust-lang.rust-analyzer"] }'))).toEqual(['1:devcontainer:rust-lang.rust-analyzer']);
  });

  it('workspace file, profile extensions.json and --show-versions list', () => {
    expect(brief(parseManifest('team.code-workspace', '{"folders":[],"extensions":{"recommendations":["golang.go"]}}'))).toEqual(['1:workspace:golang.go']);
    const profile = JSON.stringify([{ identifier: { id: 'GitHub.copilot', uuid: 'x' }, version: '1.2.3' }, { identifier: { id: 'golang.go' }, version: '0.42.0' }], null, 1);
    expect(brief(parseManifest('profile/extensions.json', profile))).toEqual(['4:profile:github.copilot@1.2.3', '11:profile:golang.go@0.42.0']);
    expect(brief(parseManifest('extensions.txt', '# exported\ndbaeumer.vscode-eslint@3.0.10\n\ngolang.go\n'))).toEqual([
      '2:list:dbaeumer.vscode-eslint@3.0.10',
      '4:list:golang.go',
    ]);
  });

  it('repeated ids get their own lines', () => {
    expect(brief(parseManifest('x.code-workspace', '{"extensions":{"recommendations":[\n"a.b",\n"a.b"]}}'))).toEqual(['2:workspace:a.b', '3:workspace:a.b']);
  });

  it('reports invalid JSON with the file name', () => {
    expect(() => parseManifest('.vscode/extensions.json', '{ "recommendations": [ }')).toThrow(/\.vscode\/extensions\.json: not valid JSON/);
  });

  it('recognises manifest paths', () => {
    expect(['.vscode/extensions.json', 'apps/web/.vscode/extensions.json', '.devcontainer/devcontainer.json', '.devcontainer.json', 'a.code-workspace'].every(isManifestPath)).toBe(true);
    expect(['extensions.json', 'package.json', 'vscode/extensions.json'].some(isManifestPath)).toBe(false);
  });
});

describe('diff', () => {
  const e = (id: string, version?: string, extra: object = {}) => ({ id, version, file: 'f', line: 1, kind: 'recommendation' as const, ...extra });

  it('classifies added, changed, removed and unchanged; ignores unwanted and removals', () => {
    const base = [e('keep.same'), e('pin.me', '1.0.0'), e('gone.away'), e('was.unwanted', undefined, { kind: 'unwanted' })];
    const head = [e('keep.same'), e('pin.me', '1.1.0'), e('new.one'), e('was.unwanted'), e('dc.removal', undefined, { remove: true })];
    const changes = diffManifests(base, head);
    expect(changes.map((c) => `${c.status}:${c.id}`)).toEqual(['added:new.one', 'added:was.unwanted', 'changed:pin.me', 'removed:gone.away', 'unchanged:keep.same']);
    expect(changes.find((c) => c.id === 'pin.me')).toMatchObject({ version: '1.1.0', baseVersion: '1.0.0' });
    expect(toScan(changes).map((c) => c.id)).toEqual(['new.one', 'was.unwanted', 'pin.me']);
  });

  it('without a base everything is added', () => {
    expect(diffManifests(undefined, [e('a.b'), e('a.b'), e('c.d')]).map((c) => `${c.status}:${c.id}:${c.entries.length}`)).toEqual(['added:a.b:2', 'added:c.d:1']);
  });
});

describe('git base revision', () => {
  const repo = mkdtempSync(join(tmpdir(), 'jest-sec-ci-'));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' });
  const write = (p: string, text: string) => {
    mkdirSync(dirname(join(repo, p)), { recursive: true });
    writeFileSync(join(repo, p), text);
  };
  afterAll(() => rmSync(repo, { recursive: true, force: true }));

  it('reads manifests at a ref, including files deleted since', async () => {
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    write('.vscode/extensions.json', '{ "recommendations": ["dbaeumer.vscode-eslint"] }');
    write('.devcontainer/devcontainer.json', '{ "customizations": { "vscode": { "extensions": ["golang.go"] } } }');
    git('add', '.');
    git('commit', '-q', '-m', 'base');
    const base = git('rev-parse', 'HEAD').trim();
    write('.vscode/extensions.json', '{ "recommendations": ["dbaeumer.vscode-eslint", "ms-pythom.python"] }');
    rmSync(join(repo, '.devcontainer'), { recursive: true });
    git('add', '-A');
    git('commit', '-q', '-m', 'head');

    expect(discoverManifests(repo)).toEqual(['.vscode/extensions.json']);
    const head = readManifests(repo);
    const atBase = await readManifestsAtRef(repo, base, head.files, true);
    expect(atBase.map((x) => `${x.file}:${x.id}`)).toEqual(['.devcontainer/devcontainer.json:golang.go', '.vscode/extensions.json:dbaeumer.vscode-eslint']);
    expect(diffManifests(atBase, head.entries).map((c) => `${c.status}:${c.id}`)).toEqual(['added:ms-pythom.python', 'removed:golang.go', 'unchanged:dbaeumer.vscode-eslint']);
  });

  it('explains a missing ref', async () => {
    await expect(resolveRef(repo, 'origin/does-not-exist')).rejects.toThrow(/fetch-depth: 0/);
  });
});
