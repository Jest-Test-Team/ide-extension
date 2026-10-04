import { join } from 'node:path';
import type { Io } from '../src/lib/args';

export const REPO = join(__dirname, '..', '..', '..');

/** Captures output of a CLI run; `cwd` defaults to the repository root. */
export function captureIo(cwd = REPO): Io & { stdout: () => string; stderr: () => string } {
  let out = '';
  let err = '';
  return {
    out: (t) => void (out += t),
    err: (t) => void (err += t),
    color: false,
    cwd,
    stdout: () => out,
    stderr: () => err,
  };
}
