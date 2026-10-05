import type { Severity } from '@ide-ext/core';

export type VectorCategory =
  | 'manifest'
  | 'process'
  | 'data'
  | 'network'
  | 'obfuscation'
  | 'native'
  | 'supply-chain'
  | 'webview'
  | 'vscode-api'
  | 'scripts'
  | 'reputation'
  | 'model'
  | 'meta';

/** Engines that can implement a vector: TypeScript core or one of the optional analyzers. */
export type Engine = 'ts' | 'rs' | 'go' | 'py' | 'jl';

/** One entry of data/extscan/vectors.yaml. */
export interface VectorDef {
  id: string;
  category: VectorCategory | string;
  engines: Engine[] | string[];
  weight: number;
  severity: Severity | string;
  /** Needs --online (network access). */
  online: boolean;
  title: string;
  description: string;
  /** MITRE ATT&CK technique ids. */
  attack: string[];
  /** CWE ids. */
  cwe: string[];
  /** Shared documentation keys (activation, trust, ext-security, removed). */
  doc: string[];
}

export const CATEGORY_TITLES: Record<VectorCategory, string> = {
  manifest: 'Manifest & metadata',
  process: 'Process & system',
  data: 'Data access',
  network: 'Network & exfiltration',
  obfuscation: 'Obfuscation & evasion',
  native: 'Native binaries & WASM',
  'supply-chain': 'Supply chain',
  webview: 'Webviews & UI',
  'vscode-api': 'VS Code API abuse',
  scripts: 'Shipped scripts (Python / Julia / shell)',
  reputation: 'Reputation & provenance',
  model: 'Behavioural model & benchmark',
  meta: 'Scan coverage',
};
