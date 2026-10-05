import type { Rule } from '@ide-ext/core';
import { DEEP_MANIFEST_VECTORS } from './manifestDeep';
import { signalIdOf } from './signals';

/** Vectors produced by the manifest checks (manifest.ts) and the file walk (codeScan.ts). */
export const MANIFEST_VECTORS = [
  'ext/activates-on-startup',
  'ext/activates-after-startup',
  'ext/untrusted-workspace',
  'ext/many-dependencies',
  'ext/typosquat',
  'ext/unknown-publisher',
  'ext/trusted-publisher',
  'ext/sideloaded',
  'ext/known-bad',
  'ext/native-binary',
  'ext/scan-incomplete',
] as const;

/** Vectors produced by the opt-in Marketplace lookup (marketplace.ts). */
export const MARKETPLACE_VECTORS = ['ext/not-on-marketplace', 'ext/unverified-publisher', 'ext/verified-publisher', 'ext/low-installs', 'ext/stale'] as const;

/** Every vector the TypeScript core implements with the given code rules. */
export function coreVectors(codeRules: readonly Rule[], online: boolean): string[] {
  return [...new Set([...MANIFEST_VECTORS, ...DEEP_MANIFEST_VECTORS, ...codeRules.map((r) => signalIdOf(r.id)), ...(online ? MARKETPLACE_VECTORS : [])])].sort();
}
