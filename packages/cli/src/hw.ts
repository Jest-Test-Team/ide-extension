import { scanTags, type TagOccurrence } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parsePufCsv, parseSamples } from '../../../extensions/hw-security/src/entropy/parse';
import { blockFailureProbability, pufMetrics, requiredCorrection } from '../../../extensions/hw-security/src/entropy/puf';
import { restartTest } from '../../../extensions/hw-security/src/entropy/restart';
import { ESTIMATORS, nonIidAssessment } from '../../../extensions/hw-security/src/entropy/sp80090b';
import { ESP32_RULES } from '../../../extensions/hw-security/src/esp32Rules';
import { scaCandidate } from '../../../extensions/hw-security/src/sca/heuristics';
import { runTool, UsageError, VERSION, type Command, type Io, type Tool } from './lib/args';
import { collectFiles } from './lib/files';
import { lintCommand } from './lib/lint';
import { emit, REPORT_FLAGS } from './lib/output';

export const hwRules = () => [...ESP32_RULES, scaCandidate];

const lint = lintCommand({
  summary: 'Lint ESP32 / ESP-IDF C/C++, sdkconfig and ESPHome YAML for firmware security issues',
  toolName: 'jest-hw',
  title: 'Embedded hardware security findings',
  rules: hwRules,
  examples: ['jest-hw lint firmware/', 'jest-hw lint . --format sarif --out hw.sarif', 'jest-hw lint sdkconfig --fail-on warning'],
});

const fmt = (x: number | undefined, d = 6) => (x === undefined ? '—' : x.toFixed(d));
const pct = (x: number) => (Number.isNaN(x) ? '—' : `${(100 * x).toFixed(2)} %`);

function readInput(io: Io, file: string | undefined): { name: string; bytes: Uint8Array } {
  if (!file) {
    throw new UsageError('expected an input file');
  }
  return { name: file, bytes: new Uint8Array(readFileSync(resolve(io.cwd, file))) };
}

const JSON_FLAG = { json: { type: 'boolean' as const, description: 'Print the result as JSON' }, out: REPORT_FLAGS.out };

const entropy: Command = {
  name: 'entropy',
  summary: 'NIST SP 800-90B non-IID min-entropy assessment of noise-source samples (.bin: one sample per byte; text: integers)',
  args: '<samples>',
  flags: {
    bits: { type: 'number', alias: 'b', description: 'Bits per sample, 1–8 (0 = infer from the data)', default: 0 },
    'all-bits': { type: 'boolean', description: 'Use the whole bitstring instead of the first 1,000,000 bits' },
    min: { type: 'number', value: '<bits>', description: 'Exit 1 if the assessed min-entropy per sample is below this value' },
    ...JSON_FLAG,
  },
  examples: ['jest-hw entropy trng.bin --bits 8', 'jest-hw entropy raw.bin -b 4 --min 3.2 --json'],
  async run({ positionals, flags }, io) {
    const { name, bytes } = readInput(io, positionals[0]);
    const r = nonIidAssessment(parseSamples(name, bytes), { wordSize: flags.bits as number, allBits: !!flags['all-bits'] });
    const lines = [
      `SP 800-90B non-IID assessment: ${name}`,
      `${r.samples.toLocaleString()} samples · ${r.wordSize} bit(s)/sample · ${r.alphSize} distinct symbols · bitstring ${r.bitstringLength.toLocaleString()} bits`,
      '',
      `${'Estimator'.padEnd(42)} ${'Literal'.padStart(10)} ${'Bitstring'.padStart(10)}`,
      ...ESTIMATORS.filter((e) => r.literal[e.id] !== undefined || r.bitstring[e.id] !== undefined).map(
        (e) => `${`${e.section} ${e.title}`.padEnd(42)} ${fmt(r.literal[e.id]).padStart(10)} ${fmt(r.bitstring[e.id]).padStart(10)}`,
      ),
      '',
      `H_original:  ${fmt(r.hOriginal)}`,
      `H_bitstring: ${fmt(r.hBitstring)}`,
      `Assessed min-entropy: ${fmt(r.hAssessed)} bits/sample (${fmt(r.hAssessed / r.wordSize)} per bit)`,
      ...r.warnings.map((w) => `warning: ${w}`),
      '',
    ];
    emit(io, flags.json ? JSON.stringify(r, null, 2) + '\n' : lines.join('\n'), flags.out);
    if (flags.min !== undefined && r.hAssessed < (flags.min as number)) {
      io.err(`assessed min-entropy ${r.hAssessed.toFixed(6)} is below --min ${flags.min}\n`);
      return 1;
    }
    return 0;
  },
};

const restart: Command = {
  name: 'restart',
  summary: 'SP 800-90B 3.1.4 restart test: validate an entropy claim H_I from restart data (rows × cols, row-major)',
  args: '<restart.bin>',
  flags: {
    hi: { type: 'number', description: 'Initial entropy estimate H_I to validate (bits/sample)' },
    bits: { type: 'number', alias: 'b', description: 'Bits per sample (0 = infer)', default: 0 },
    rows: { type: 'number', description: 'Restarts (= samples per restart; the matrix is square)', default: 1000 },
    rounds: { type: 'number', description: 'Monte-Carlo rounds for the sanity-check cutoff (NIST: 5,000,000)', default: 200000 },
    ...JSON_FLAG,
  },
  examples: ['jest-hw restart restarts.bin --hi 6.5 --bits 8'],
  async run({ positionals, flags }, io) {
    if (flags.hi === undefined) {
      throw new UsageError('--hi is required');
    }
    const { name, bytes } = readInput(io, positionals[0]);
    const n = flags.rows as number;
    const r = restartTest(bytes, flags.hi as number, { rows: n, cols: n, wordSize: flags.bits as number, simulationRounds: flags.rounds as number });
    const text = [
      `SP 800-90B restart test: ${name} (${r.rows} × ${r.cols}, H_I = ${r.hI})`,
      `Sanity check: X_max = ${r.xMax}, cutoff = ${r.xCutoff} → ${r.sanityPassed ? 'pass' : 'FAIL'}`,
      `Row min-entropy H_r:    ${fmt(r.hRow)}`,
      `Column min-entropy H_c: ${fmt(r.hCol)}`,
      `Validation min(H_r, H_c) ≥ H_I/2 = ${fmt(r.hI / 2, 4)} → ${r.passed ? `PASSED (validated entropy ${fmt(Math.min(r.hRow, r.hCol, r.hI))})` : 'FAILED'}`,
      '',
    ].join('\n');
    emit(io, flags.json ? JSON.stringify(r, null, 2) + '\n' : text, flags.out);
    return r.passed ? 0 : 1;
  },
};

const puf: Command = {
  name: 'puf',
  summary: 'PUF quality metrics from a CSV of responses (device,read,response — 0/1 or hex) with an ECC requirement',
  args: '<responses.csv>',
  flags: {
    'ecc-bits': { type: 'number', description: 'ECC block length n', default: 255 },
    target: { type: 'number', description: 'Target key-reconstruction failure rate per block', default: 1e-6 },
    'min-reliability': { type: 'number', value: '<0..1>', description: 'Exit 1 if reliability is below this' },
    ...JSON_FLAG,
  },
  examples: ['jest-hw puf sram.csv', 'jest-hw puf sram.csv --ecc-bits 127 --target 1e-9 --json'],
  async run({ positionals, flags }, io) {
    const { name, bytes } = readInput(io, positionals[0]);
    const r = pufMetrics(parsePufCsv(new TextDecoder().decode(bytes)));
    const n = flags['ecc-bits'] as number;
    const target = flags.target as number;
    const t = Number.isNaN(r.bitErrorRate) ? undefined : requiredCorrection(n, r.bitErrorRate, target);
    const ecc = { n, target, t, failureAtT: t === undefined ? undefined : blockFailureProbability(n, t, r.bitErrorRate) };
    const text = [
      `PUF quality: ${name} — ${r.devices} device(s), ~${r.readsPerDevice} read(s)/device, ${r.bits}-bit responses`,
      '',
      `Uniformity     ${pct(r.uniformity.mean).padStart(9)}   (ideal 50 %, range ${pct(r.uniformity.min)} – ${pct(r.uniformity.max)})`,
      `Uniqueness     ${pct(r.uniqueness).padStart(9)}   (ideal 50 %)`,
      `Reliability    ${pct(r.reliability).padStart(9)}   (ideal 100 %, bit error rate ${pct(r.bitErrorRate)})`,
      `Bit-aliasing   ${pct(r.bitAliasing.mean).padStart(9)}   (ideal 50 %)`,
      `Min-entropy    ${r.minEntropyPerBit.toFixed(4).padStart(9)}   bits per bit`,
      `Unstable cells ${pct(r.unstableBitFraction).padStart(9)}`,
      '',
      t === undefined ? 'ECC: needs repeated reads (or no t reaches the target).' : `ECC: ${n}-bit blocks need t = ${t} correctable errors for failure ≤ ${target} (achieved ${ecc.failureAtT!.toExponential(2)}).`,
      ...r.warnings.map((w) => `warning: ${w}`),
      '',
    ].join('\n');
    emit(io, flags.json ? JSON.stringify({ ...r, ecc }, null, 2) + '\n' : text, flags.out);
    return flags['min-reliability'] !== undefined && !(r.reliability >= (flags['min-reliability'] as number)) ? 1 : 0;
  },
};

const SCA_LANGS = new Set(['c', 'cpp', 'python', 'plaintext']);

const sca: Command = {
  name: 'sca',
  summary: 'List ChipWhisperer side-channel points: @sca(id, "…") tags in firmware and @sca-ref(id) in analysis scripts',
  args: '[paths…]',
  flags: { ...JSON_FLAG },
  examples: ['jest-hw sca firmware/ analysis/', 'jest-hw sca . --json'],
  async run({ positionals, flags }, io) {
    const files = collectFiles(positionals, io.cwd, (lang, path) => SCA_LANGS.has(lang) && /\.(c|h|cc|cpp|hpp|ino|s|py)$/i.test(path));
    const tags: (TagOccurrence & { file: string })[] = [];
    for (const f of files) {
      for (const t of scanTags(f.rel, readFileSync(f.path, 'utf8'), ['sca', 'sca-ref'])) {
        tags.push({ ...t, file: f.rel });
      }
    }
    const ids = [...new Set(tags.map((t) => t.id))].sort();
    const points = ids.map((id) => ({
      id,
      defs: tags.filter((t) => t.id === id && t.tag === 'sca'),
      refs: tags.filter((t) => t.id === id && t.tag === 'sca-ref'),
    }));
    const problems: string[] = [];
    for (const p of points) {
      if (p.defs.length > 1) {
        problems.push(`duplicate id "${p.id}": ${p.defs.map((d) => `${d.file}:${d.line + 1}`).join(', ')}`);
      }
      if (!p.defs.length) {
        problems.push(`@sca-ref(${p.id}) has no @sca tag: ${p.refs.map((d) => `${d.file}:${d.line + 1}`).join(', ')}`);
      }
    }
    if (flags.json) {
      emit(io, JSON.stringify({ points: points.map((p) => ({ id: p.id, description: p.defs[0]?.description, defs: p.defs.map((d) => ({ file: d.file, line: d.line + 1 })), refs: p.refs.map((d) => ({ file: d.file, line: d.line + 1 })) })), problems }, null, 2) + '\n', flags.out);
    } else {
      const lines = [`${points.length} side-channel point(s) in ${files.length} file(s)`, ''];
      for (const p of points) {
        const status = !p.defs.length ? 'orphan reference' : p.defs.length > 1 ? 'duplicate id' : p.refs.length ? `analysed by ${p.refs.length}` : 'not analysed';
        lines.push(`${p.id}  [${status}]${p.defs[0]?.description ? `  ${p.defs[0].description}` : ''}`);
        p.defs.forEach((d) => lines.push(`  target    ${d.file}:${d.line + 1}`));
        p.refs.forEach((d) => lines.push(`  analysis  ${d.file}:${d.line + 1}`));
      }
      lines.push('', ...problems.map((p) => `problem: ${p}`));
      emit(io, lines.join('\n') + '\n', flags.out);
    }
    return problems.length ? 1 : 0;
  },
};

export const HW_TOOL: Tool = {
  name: 'jest-hw',
  version: VERSION,
  summary: 'Embedded Hardware Security Workbench (alias: jest-embedded)',
  commands: [lint, entropy, restart, puf, sca],
  footer: 'Exit codes: 0 = clean / passed, 1 = findings, failed test or threshold, 2 = usage or runtime error.',
};

export const main = (argv: readonly string[], io?: Io) => runTool(HW_TOOL, argv, io);
