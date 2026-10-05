import type { CustomRule, Finding, Rule, RuleRef, Severity } from '@ide-ext/core';
import { VECTOR_DEFS } from './vectors.generated';
import type { Engine, VectorCategory } from './vectorTypes';

export type RiskLevel = 'low' | 'medium' | 'high';

/** A finding located in a file of an installed extension (absolute path). */
export interface Located {
  file: string;
  finding: Finding;
}

/** One reason contributing to an extension's risk score. */
export interface Signal {
  /** Signal id from {@link SIGNALS} (code rules map `ext/foo.bar` → `ext/foo`). */
  id: string;
  weight: number;
  message: string;
  /** Forces at least this level regardless of the score (known-malware entries). */
  force?: RiskLevel;
  /** Where the signal was observed; empty for signals without a location. */
  locations: Located[];
  /** Total number of hits, which may exceed `locations.length` (locations are capped). */
  count: number;
}

export interface SignalInfo {
  title: string;
  weight: number;
  severity: Severity;
  description: string;
  refs?: RuleRef[];
  category: VectorCategory;
  engines: Engine[];
  /** Needs --online (network access). */
  online: boolean;
}

const ATTACK = (id: string): RuleRef => ({ label: `MITRE ATT&CK ${id}`, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` });
const CWE = (id: string): RuleRef => ({ label: `CWE-${id}`, url: `https://cwe.mitre.org/data/definitions/${id}.html` });
const DOC_REFS: Record<string, RuleRef> = {
  'ext-security': { label: 'VS Code — Extension runtime security', url: 'https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security' },
  removed: { label: 'microsoft/vsmarketplace — RemovedPackages.md', url: 'https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md' },
  activation: { label: 'VS Code API — Activation events', url: 'https://code.visualstudio.com/api/references/activation-events' },
  trust: { label: 'VS Code API — Workspace Trust extension guide', url: 'https://code.visualstudio.com/api/extension-guides/workspace-trust' },
};

/**
 * Every signal (vector) the extension scanner knows, from the registry in
 * data/extscan/vectors.yaml. Weights feed {@link scoreExtension}; weight 0 marks informational
 * signals that only amplify others through combination rules.
 */
export const SIGNALS: Record<string, SignalInfo> = Object.fromEntries(
  VECTOR_DEFS.map((v) => [
    v.id,
    {
      title: v.title,
      weight: v.weight,
      severity: v.severity as Severity,
      description: v.description,
      refs: [...v.doc.map((d) => DOC_REFS[d]), ...v.attack.map(ATTACK), ...v.cwe.map(CWE)].filter(Boolean),
      category: v.category as VectorCategory,
      engines: v.engines as Engine[],
      online: v.online,
    },
  ]),
);

/** Code rules are named `ext/<signal>.<variant>`; the signal is the part before the dot. */
export function signalIdOf(ruleId: string): string {
  const dot = ruleId.indexOf('.', ruleId.indexOf('/'));
  return dot < 0 ? ruleId : ruleId.slice(0, dot);
}

/** Signal registry entries as rules, so SARIF / Markdown exports carry titles and references. */
export function signalRules(): Rule[] {
  return Object.entries(SIGNALS).map(
    ([id, s]): CustomRule => ({
      kind: 'custom',
      id,
      title: s.title,
      severity: s.severity,
      message: s.title,
      description: s.description,
      languages: [],
      refs: s.refs ?? [],
      tags: ['extension-scan'],
      check: () => [],
    }),
  );
}

/** Builds a signal with the registry weight; `overrides` adjust weight / message / force. */
export function signal(id: string, message: string, locations: Located[] = [], overrides: Partial<Signal> = {}): Signal {
  const info = SIGNALS[id];
  if (!info) {
    throw new Error(`unknown signal ${id}`);
  }
  return { id, weight: info.weight, message, locations, count: Math.max(1, locations.length), ...overrides };
}
