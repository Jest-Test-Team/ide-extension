/**
 * Analyzer protocol v1. An analyzer is an executable (`jest-ext-rs`, `jest-ext-go`, `jest-ext-py`,
 * `jest-ext-jl`) that the scanner runs as:
 *
 *   <analyzer> info      → one JSON object: AnalyzerInfo
 *   <analyzer> analyze   ← one JSON AnalyzeRequest on stdin
 *                        → NDJSON AnalyzerMessage lines on stdout, ending with a `done` message
 *
 * Analyzers only read files. They must never execute, import or require extension code.
 */

export const PROTOCOL_VERSION = 1;

export type EngineId = 'rs' | 'go' | 'py' | 'jl';

export const ENGINE_BINARIES: Record<EngineId, string> = {
  rs: 'jest-ext-rs',
  go: 'jest-ext-go',
  py: 'jest-ext-py',
  jl: 'jest-ext-jl',
};

export const ENGINE_NAMES: Record<EngineId | 'ts', string> = {
  ts: 'TypeScript core',
  rs: 'Rust analyzer',
  go: 'Go analyzer',
  py: 'Python analyzer',
  jl: 'Julia analyzer',
};

export interface AnalyzerInfo {
  name: string;
  version: string;
  protocol: number;
  /** Vector ids this analyzer implements. */
  vectors: string[];
}

export interface RequestExtension {
  id: string;
  version: string;
  /** Absolute install folder. */
  path: string;
  manifest: Record<string, unknown>;
}

export interface AnalyzeRequest {
  protocol: number;
  extensions: RequestExtension[];
  /** Vector ids the scanner wants from this analyzer. */
  vectors: string[];
  options: { online: boolean; maxFileMB: number; maxFiles: number };
}

export interface ProtocolLocation {
  /** Absolute path or relative to the extension folder. */
  file: string;
  line?: number;
  col?: number;
}

export type AnalyzerMessage =
  | {
      type: 'signal';
      ext: string;
      vector: string;
      message: string;
      locations?: ProtocolLocation[];
      evidence?: string;
      /** 0..1; signals below 0.5 are reported but weigh half. */
      confidence?: number;
      /** Data-flow path for taint findings (source → … → sink). */
      flow?: ProtocolLocation[];
    }
  | { type: 'metric'; ext: string; name: string; value: number }
  | { type: 'progress'; ext?: string; message?: string }
  | { type: 'error'; ext?: string; message: string }
  | { type: 'done'; ran: string[]; skipped?: { id: string; reason: string }[] };

/** Validates one NDJSON line; returns undefined for malformed messages. */
export function parseMessage(line: string): AnalyzerMessage | undefined {
  let m: unknown;
  try {
    m = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!m || typeof m !== 'object') {
    return undefined;
  }
  const o = m as Record<string, unknown>;
  switch (o.type) {
    case 'signal':
      return typeof o.ext === 'string' && typeof o.vector === 'string' && typeof o.message === 'string' ? (o as AnalyzerMessage) : undefined;
    case 'metric':
      return typeof o.ext === 'string' && typeof o.name === 'string' && typeof o.value === 'number' ? (o as AnalyzerMessage) : undefined;
    case 'progress':
      return o as AnalyzerMessage;
    case 'error':
      return typeof o.message === 'string' ? (o as AnalyzerMessage) : undefined;
    case 'done':
      return Array.isArray(o.ran) ? (o as AnalyzerMessage) : undefined;
    default:
      return undefined;
  }
}
