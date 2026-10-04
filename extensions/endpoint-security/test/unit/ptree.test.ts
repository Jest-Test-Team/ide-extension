import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseRules, parseScenario, ScenarioError, simulate } from '../../src/ptree/engine';

const defaults = parseRules(readFileSync(join(__dirname, '../../data/ptree/default-rules.yaml'), 'utf8'));
const run = (text: string) => simulate(parseScenario(text, defaults));

describe('process-tree simulation', () => {
  it('detects the ransomware chain', () => {
    const res = run(readFileSync(join(__dirname, '../fixtures/scenarios/ransom.ptree.yaml'), 'utf8'));
    expect(res.warnings).toEqual([]);
    expect(res.detections.map((d) => d.ruleId)).toEqual([
      'office-spawns-script-host',
      'encoded-powershell',
      'temp-binary-execution',
      'orphaning-parent-exit',
      'inhibit-system-recovery',
      'security-tool-termination',
      'lsass-access',
      'process-injection',
      'run-key-persistence',
      'mass-file-encryption',
    ]);
    const tree = Object.fromEntries(res.processes.map((p) => [p.id, p]));
    expect(tree.word.children).toEqual(['ps']);
    expect(tree.ps.children).toEqual(['payload']);
    expect(tree.defender.terminatedBy).toBe('payload');
    expect(tree.lsass.injectedBy).toEqual(['payload']);
    expect(tree.payload.detections).toContain('mass-file-encryption');
    const mass = res.detections.find((d) => d.ruleId === 'mass-file-encryption')!;
    expect(mass.events).toHaveLength(2);
    expect(res.timeline[0].summary).toContain('WINWORD.EXE (word) → spawns powershell.exe (ps)');
    expect(res.timeline[0].line).toBe(15);
  });

  it('matches sequences with bindings and time windows', () => {
    const s = `
processes:
  - { id: sshd, image: /usr/sbin/sshd }
  - { id: sh0, image: /bin/sh, parent: sshd }
events:
  - { t: 0, type: spawn, process: c, parent: sh0, image: /usr/bin/curl }
  - { t: 100, type: spawn, process: other, parent: sshd, image: /bin/bash }
  - { t: 200, type: spawn, process: b, parent: sh0, image: /bin/bash }
  - { t: 9000, type: spawn, process: c2, parent: sh0, image: /usr/bin/curl }
  - { t: 20000, type: spawn, process: b2, parent: sh0, image: /bin/bash }
`;
    const d = run(s).detections.filter((x) => x.ruleId === 'download-and-execute');
    expect(d).toHaveLength(1);
    expect(d[0].processes).toEqual(['c', 'b']);
  });

  it('reports scenario errors with line numbers', () => {
    expect(() => parseScenario('events:\n  - { type: spawnn, process: x }\n')).toThrow(/line 2: unknown event type/);
    expect(() => parseScenario('rules:\n  - id: r\n    match: { image: "(" }\n')).toThrow(ScenarioError);
    expect(() => parseScenario('rules:\n  - id: r\n')).toThrow(/exactly one of/);
  });

  it('warns about undefined processes', () => {
    const res = run('events:\n  - { type: file, process: ghost, op: write, path: /tmp/x }\n');
    expect(res.warnings[0]).toMatch(/ghost is used before it exists/);
  });
});
