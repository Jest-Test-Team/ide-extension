// Regenerates test/fixtures/entropy/nist-reference.json by running NIST's ea_non_iid on every
// vector. Only runs when NIST_EA_NON_IID points at the binary:
//   NIST_EA_NON_IID=/path/to/ea_non_iid npx vitest run extensions/hw-security/test/unit/entropy.reference.test.ts
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'vitest';
import { RESTART_VECTOR, VECTORS } from './vectors';

const tool = process.env.NIST_EA_NON_IID;

const DESC: Record<string, [string, string]> = {
  'Most Common Value': ['mcv', 'mcv'],
  'Collision Test (for bit strings only)': ['collision', 'collision'],
  'Markov Test (for bit strings only)': ['markov', 'markov'],
  'Compression Test (for bit strings only)': ['compression', 'compression'],
  'Multi Most Common in Window Test': ['multiMcw', 'multiMcw'],
  'Lag Prediction Test': ['lag', 'lag'],
  'Multi Markov Model with Counting Test (MultiMMC)': ['multiMmc', 'multiMmc'],
  'LZ78Y Test': ['lz78y', 'lz78y'],
};

it.runIf(!!tool)('regenerates NIST reference values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ea-'));
  const out: Record<string, unknown> = {};
  for (const v of VECTORS) {
    const bin = join(dir, `${v.name}.bin`);
    const json = join(dir, `${v.name}.json`);
    writeFileSync(bin, v.data());
    execFileSync(tool!, ['-o', json, bin, String(v.wordSize)], { stdio: 'ignore' });
    const res = JSON.parse(readFileSync(json, 'utf8')) as { testCases: Record<string, number | string>[] };
    const literal: Record<string, number> = {};
    const bitstring: Record<string, number> = {};
    let overall: Record<string, number | string> = {};
    for (const t of res.testCases) {
      const desc = String(t.testCaseDesc);
      if (desc === 'Overall') {
        overall = t;
      } else if (desc === 'T-Tuple Test') {
        if (t.tTupleRes !== undefined && Number(t.tTupleRes) >= 0) literal.tTuple = Number(t.tTupleRes);
        if (t.binTTupleRes !== undefined && Number(t.binTTupleRes) >= 0) bitstring.tTuple = Number(t.binTTupleRes);
      } else if (desc === 'LRS Test') {
        if (t.lrsRes !== undefined && Number(t.lrsRes) >= 0) literal.lrs = Number(t.lrsRes);
        if (t.binLrsRes !== undefined && Number(t.binLrsRes) >= 0) bitstring.lrs = Number(t.binLrsRes);
      } else if (DESC[desc]) {
        if (t.hOriginal !== undefined) literal[DESC[desc][0]] = Number(t.hOriginal);
        if (t.hBitstring !== undefined) bitstring[DESC[desc][1]] = Number(t.hBitstring);
      }
    }
    out[v.name] = { wordSize: v.wordSize, literal, bitstring, hOriginal: overall.hOriginal, hBitstring: overall.hBitstring, hAssessed: overall.hAssessed };
  }
  writeFileSync(join(__dirname, '../fixtures/entropy/nist-reference.json'), JSON.stringify(out, null, 2) + '\n');
}, 600_000);

const restartTool = process.env.NIST_EA_RESTART;

it.runIf(!!restartTool)('regenerates NIST restart reference', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ea-'));
  const v = RESTART_VECTOR;
  const bin = join(dir, 'restart.bin');
  const json = join(dir, 'restart.json');
  writeFileSync(bin, v.data());
  try {
    execFileSync(restartTool!, ['-n', '-o', json, bin, String(v.wordSize), String(v.hI)], { stdio: 'ignore' });
  } catch {
    // ea_restart exits non-zero when validation fails; the JSON is still written.
  }
  const res = JSON.parse(readFileSync(json, 'utf8')) as { testCases: Record<string, number | string>[] };
  const sanity = res.testCases.find((t) => t.xMax !== undefined) ?? {};
  const overall = res.testCases.find((t) => t.h_r !== undefined && t.h_c !== undefined && t.testCaseDesc === 'Overall') ?? res.testCases.at(-1)!;
  writeFileSync(
    join(__dirname, '../fixtures/entropy/nist-restart-reference.json'),
    JSON.stringify({ name: v.name, wordSize: v.wordSize, hI: v.hI, sanity, overall, testCases: res.testCases }, null, 2) + '\n',
  );
}, 600_000);
