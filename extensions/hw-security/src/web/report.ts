import { el, fmt, onMessage, post } from '@ide-ext/core/web';
import type { PufReport } from '../entropy/puf';
import type { RestartResult } from '../entropy/restart';
import { ESTIMATORS, type NonIidResult } from '../entropy/sp80090b';

type Msg =
  | { type: 'entropy'; name: string; result: NonIidResult; histogram: number[]; nist?: { literal: Record<string, number>; bitstring: Record<string, number>; hAssessed?: number } }
  | { type: 'restart'; name: string; result: RestartResult }
  | { type: 'puf'; name: string; report: PufReport; ecc: { n: number; target: number; t?: number; failureAtT?: number } };

const app = document.getElementById('app')!;
const tip = el('div', { class: 'tooltip', style: 'display:none' });
document.body.append(tip);
const NS = 'http://www.w3.org/2000/svg';

// Series colours come from the active VS Code theme, so light/dark/high-contrast are handled there.
const SERIES = ['var(--vscode-charts-blue, #3794ff)', 'var(--vscode-charts-orange, #d18616)'];
const INK = 'var(--vscode-descriptionForeground)';
const GRID = 'var(--vscode-panel-border, rgba(128,128,128,.35))';

function svg(tag: string, attrs: Record<string, string | number>, ...kids: Node[]): SVGElement {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    n.setAttribute(k, String(v));
  }
  n.append(...kids);
  return n;
}

function hover(node: Element, text: string): void {
  node.addEventListener('mousemove', (e) => {
    const ev = e as MouseEvent;
    tip.style.display = 'block';
    tip.style.left = `${Math.min(ev.clientX + 12, window.innerWidth - 280)}px`;
    tip.style.top = `${ev.clientY + 12}px`;
    tip.textContent = text;
  });
  node.addEventListener('mouseleave', () => (tip.style.display = 'none'));
}

/** Rounded-top bar path anchored to the baseline (4px data-end radius). */
function barPath(x: number, y: number, w: number, h: number, horizontal: boolean): string {
  const r = Math.min(4, (horizontal ? h : w) / 2, horizontal ? w : h);
  if (horizontal) {
    return `M${x},${y} h${w - r} q${r},0 ${r},${r} v${h - 2 * r} q0,${r} ${-r},${r} h${-(w - r)} z`;
  }
  return `M${x},${y + h} v${-(h - r)} q0,${-r} ${r},${-r} h${w - 2 * r} q${r},0 ${r},${r} v${h - r} z`;
}

function card(k: string, v: string, cls = ''): HTMLElement {
  return el('div', { class: 'card' }, el('div', { class: `v ${cls}` }, v), el('div', { class: 'k' }, k));
}

function toolbar(name: string, markdown: () => string, json: unknown): HTMLElement {
  const md = el('button', { class: 'secondary' }, 'Export Markdown');
  md.addEventListener('click', () => post({ type: 'export', format: 'md', content: markdown(), suggestedName: `${name.split('/').pop()}.report.md` }));
  const js = el('button', { class: 'secondary' }, 'Export JSON');
  js.addEventListener('click', () => post({ type: 'export', format: 'json', content: JSON.stringify(json, null, 2), suggestedName: `${name.split('/').pop()}.report.json` }));
  return el('div', { class: 'toolbar' }, md, js);
}

// ---------------------------------------------------------------------------------------------

function renderEntropy(m: Extract<Msg, { type: 'entropy' }>): void {
  const r = m.result;
  const rows = ESTIMATORS.filter((e) => r.literal[e.id] !== undefined || r.bitstring[e.id] !== undefined);
  app.append(
    el('h1', {}, 'SP 800-90B non-IID entropy assessment'),
    el('p', { class: 'muted' }, `${m.name} · ${r.samples.toLocaleString()} samples · ${r.wordSize} bit(s)/sample · ${r.alphSize} distinct symbols`),
    el(
      'div',
      { class: 'cards' },
      card('Assessed min-entropy (bits / sample)', fmt(r.hAssessed, 4)),
      card('H_original (literal)', r.hOriginal !== undefined ? fmt(r.hOriginal, 4) : '—'),
      card('H_bitstring × bits/sample', r.hBitstring !== undefined ? fmt(r.hBitstring * r.wordSize, 4) : '—'),
      card('Entropy per bit', fmt(r.hAssessed / r.wordSize, 4)),
    ),
    ...r.warnings.map((w) => el('p', { class: 'warn' }, `⚠ ${w}`)),
  );

  // Estimator chart: one series (bits/sample after scaling bitstring results by word size).
  const values = rows.map((e) => {
    const lit = r.literal[e.id];
    const bit = r.bitstring[e.id];
    return { e, v: Math.min(lit ?? Infinity, bit !== undefined ? bit * r.wordSize : Infinity) };
  });
  app.append(el('h2', {}, 'Estimates (bits per sample; lowest wins)'), estimatorChart(values, r.hAssessed, r.wordSize));

  const head = ['Estimator', 'Literal (bits/sample)', 'Bitstring (bits/bit)', ...(m.nist ? ['NIST ea_non_iid', 'Δ'] : [])];
  const table = el('table', {}, el('tr', {}, ...head.map((h, i) => el('th', i ? { class: 'num' } : {}, h))));
  let maxDelta = 0;
  for (const e of rows) {
    const lit = r.literal[e.id];
    const bit = r.bitstring[e.id];
    const cells = [lit !== undefined ? fmt(lit, 6) : '—', bit !== undefined ? fmt(bit, 6) : '—'];
    if (m.nist) {
      const nv = m.nist.literal[e.id] ?? m.nist.bitstring[e.id];
      const ours = m.nist.literal[e.id] !== undefined ? lit : bit;
      const d = nv !== undefined && ours !== undefined ? Math.abs(nv - ours) : undefined;
      maxDelta = Math.max(maxDelta, d ?? 0);
      cells.push(nv !== undefined ? fmt(nv, 6) : '—', d !== undefined ? d.toExponential(1) : '—');
    }
    table.append(el('tr', {}, el('td', {}, `${e.section} ${e.title}`), ...cells.map((c) => el('td', { class: 'num' }, c))));
  }
  app.append(el('h2', {}, 'Estimator results'), table);
  if (m.nist) {
    app.append(el('p', { class: maxDelta < 1e-6 ? 'pass' : 'warn' }, `${maxDelta < 1e-6 ? '✔' : '⚠'} Cross-check against NIST ea_non_iid: max |Δ| = ${maxDelta.toExponential(2)}`));
  }

  app.append(el('h2', {}, 'Sample distribution'), histogramChart(m.histogram, m.result.samples));
  app.append(
    toolbar(m.name, () => entropyMarkdown(m), m.result),
    el('p', { class: 'muted' }, 'IID-track permutation tests (section 5) are not run here; use NIST ea_iid for an IID claim. Configure hwSecurity.nist.eaNonIidPath to cross-check these results.'),
  );
}

function estimatorChart(values: { e: (typeof ESTIMATORS)[number]; v: number }[], assessed: number, max: number): SVGElement {
  const W = Math.max(480, app.clientWidth - 8);
  const label = 230;
  const rowH = 22;
  const H = values.length * rowH + 28;
  const x = (v: number) => label + (v / max) * (W - label - 60);
  const s = svg('svg', { width: W, height: H, role: 'img', 'aria-label': 'Entropy estimate per estimator' });
  for (const t of [0, 0.25, 0.5, 0.75, 1]) {
    s.append(svg('line', { x1: x(t * max), x2: x(t * max), y1: 0, y2: H - 20, stroke: GRID, 'stroke-width': 1 }));
    s.append(svg('text', { x: x(t * max), y: H - 6, 'text-anchor': 'middle', 'font-size': 10, style: `fill:${INK}` }, document.createTextNode(fmt(t * max, 2))));
  }
  values.forEach(({ e, v }, i) => {
    const y = i * rowH + 4;
    const isMin = Math.abs(v - assessed) < 1e-12;
    s.append(svg('text', { x: label - 8, y: y + 13, 'text-anchor': 'end', 'font-size': 11 }, document.createTextNode(`${e.section} ${e.title}`)));
    const bar = svg('path', { d: barPath(label, y + 2, Math.max(1, x(v) - label), rowH - 8, true), fill: SERIES[0] });
    hover(bar, `${e.title}\n${fmt(v, 6)} bits/sample${isMin ? '\n(the assessed minimum)' : ''}`);
    s.append(bar);
    s.append(svg('text', { x: x(v) + 6, y: y + 13, 'font-size': 11 }, document.createTextNode(`${fmt(v, 3)}${isMin ? '  ◀ min' : ''}`)));
  });
  return s;
}

function histogramChart(h: number[], n: number): SVGElement {
  const W = Math.max(480, app.clientWidth - 8);
  const H = 180;
  const pad = { l: 44, r: 8, t: 8, b: 22 };
  const maxV = Math.max(...h);
  const bw = (W - pad.l - pad.r) / h.length;
  const y = (v: number) => pad.t + (1 - v / maxV) * (H - pad.t - pad.b);
  const s = svg('svg', { width: W, height: H, role: 'img', 'aria-label': 'Sample value histogram' });
  for (const t of [0, 0.5, 1]) {
    s.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y(t * maxV), y2: y(t * maxV), stroke: GRID }));
    s.append(svg('text', { x: pad.l - 6, y: y(t * maxV) + 4, 'text-anchor': 'end', 'font-size': 10, style: `fill:${INK}` }, document.createTextNode(String(Math.round(t * maxV)))));
  }
  h.forEach((v, i) => {
    const gap = bw > 4 ? 2 : 0;
    const bar = svg('path', { d: barPath(pad.l + i * bw + gap / 2, y(v), Math.max(0.5, bw - gap), H - pad.b - y(v), false), fill: SERIES[0] });
    hover(bar, `value ${i} (0x${i.toString(16)})\n${v.toLocaleString()} samples · ${fmt((100 * v) / n, 3)} %`);
    s.append(bar);
  });
  const uniform = n / h.length;
  s.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y(uniform), y2: y(uniform), stroke: INK, 'stroke-dasharray': '4 3' }));
  s.append(svg('text', { x: W - pad.r, y: y(uniform) - 4, 'text-anchor': 'end', 'font-size': 10, style: `fill:${INK}` }, document.createTextNode('uniform')));
  s.append(svg('text', { x: pad.l, y: H - 6, 'font-size': 10, style: `fill:${INK}` }, document.createTextNode('0')));
  s.append(svg('text', { x: W - pad.r, y: H - 6, 'text-anchor': 'end', 'font-size': 10, style: `fill:${INK}` }, document.createTextNode(String(h.length - 1))));
  return s;
}

function entropyMarkdown(m: Extract<Msg, { type: 'entropy' }>): string {
  const r = m.result;
  const lines = [
    `# SP 800-90B non-IID assessment: ${m.name}`,
    '',
    `- Samples: ${r.samples} (${r.wordSize} bit(s)/sample, ${r.alphSize} symbols)`,
    `- **Assessed min-entropy: ${r.hAssessed.toFixed(6)} bits/sample**`,
    `- H_original: ${r.hOriginal?.toFixed(6) ?? 'n/a'}; H_bitstring: ${r.hBitstring?.toFixed(6) ?? 'n/a'}`,
    ...r.warnings.map((w) => `- ⚠ ${w}`),
    '',
    '| Estimator | Literal | Bitstring |',
    '|---|---:|---:|',
    ...ESTIMATORS.filter((e) => r.literal[e.id] !== undefined || r.bitstring[e.id] !== undefined).map(
      (e) => `| ${e.section} ${e.title} | ${r.literal[e.id]?.toFixed(6) ?? '—'} | ${r.bitstring[e.id]?.toFixed(6) ?? '—'} |`,
    ),
    '',
    'Source: NIST SP 800-90B (2018), section 6.3; https://csrc.nist.gov/pubs/sp/800/90/b/final',
  ];
  return lines.join('\n');
}

// ---------------------------------------------------------------------------------------------

function renderRestart(m: Extract<Msg, { type: 'restart' }>): void {
  const r = m.result;
  app.append(
    el('h1', {}, 'SP 800-90B restart test (3.1.4)'),
    el('p', { class: 'muted' }, `${m.name} · ${r.rows} restarts × ${r.cols} samples · H_I = ${r.hI}`),
    el(
      'div',
      { class: 'cards' },
      card('Result', r.passed ? '✔ Passed' : '✘ Failed', r.passed ? 'pass' : 'fail'),
      card('Sanity check X_max ≤ cutoff', `${r.xMax} ≤ ${r.xCutoff} ${r.sanityPassed ? '✔' : '✘'}`, r.sanityPassed ? 'pass' : 'fail'),
      card('Row min-entropy H_r', fmt(r.hRow, 4)),
      card('Column min-entropy H_c', fmt(r.hCol, 4)),
    ),
    el('p', {}, `Validation requires min(H_r, H_c) ≥ H_I / 2 = ${fmt(r.hI / 2, 4)}. ${r.passed ? `The validated entropy is min(H_r, H_c, H_I) = ${fmt(Math.min(r.hRow, r.hCol, r.hI), 4)}.` : ''}`),
    el('p', { class: 'muted' }, `Sanity cutoff from ${r.simulationRounds.toLocaleString()} Monte-Carlo rounds (NIST ea_restart uses 5,000,000).`),
    toolbar(m.name, () => `# Restart test: ${m.name}\n\n${JSON.stringify(r, null, 2)}\n`, r),
  );
}

// ---------------------------------------------------------------------------------------------

function renderPuf(m: Extract<Msg, { type: 'puf' }>): void {
  const r = m.report;
  const pct = (x: number) => `${fmt(100 * x, 2)} %`;
  app.append(
    el('h1', {}, 'PUF quality metrics'),
    el('p', { class: 'muted' }, `${m.name} · ${r.devices} device(s) · ~${r.readsPerDevice} read(s)/device · ${r.bits}-bit responses`),
    el(
      'div',
      { class: 'cards' },
      card('Uniformity (ideal 50 %)', pct(r.uniformity.mean)),
      card('Uniqueness (ideal 50 %)', Number.isNaN(r.uniqueness) ? '—' : pct(r.uniqueness)),
      card('Reliability (ideal 100 %)', Number.isNaN(r.reliability) ? '—' : pct(r.reliability)),
      card('Bit-aliasing (ideal 50 %)', pct(r.bitAliasing.mean)),
      card('Min-entropy per bit', fmt(r.minEntropyPerBit, 4)),
      card('Unstable cells', pct(r.unstableBitFraction)),
    ),
    ...r.warnings.map((w) => el('p', { class: 'warn' }, `⚠ ${w}`)),
  );
  if (r.interHd.length || r.intraHd.length) {
    app.append(el('h2', {}, 'Hamming distance distributions'), hdChart(r.interHd, r.intraHd));
  }
  const e = m.ecc;
  app.append(
    el('h2', {}, 'Error-correction requirement'),
    el(
      'p',
      {},
      Number.isNaN(r.bitErrorRate)
        ? 'Needs repeated reads to estimate the bit error rate.'
        : e.t === undefined
          ? `No t ≤ ${e.n} reaches a block failure rate of ${e.target.toExponential(0)} at BER ${pct(r.bitErrorRate)}.`
          : `At a bit error rate of ${pct(r.bitErrorRate)}, an ${e.n}-bit block needs a code correcting t = ${e.t} errors for a failure rate ≤ ${e.target.toExponential(0)} (achieved: ${e.failureAtT!.toExponential(2)}), assuming independent bit errors.`,
    ),
    el('h2', {}, 'Most biased bit positions'),
    (() => {
      const t = el('table', {}, el('tr', {}, el('th', {}, 'Bit'), el('th', { class: 'num' }, 'Fraction of devices = 1')));
      r.bitAliasing.worst.forEach((w) => t.append(el('tr', {}, el('td', {}, String(w.index)), el('td', { class: 'num' }, pct(w.value)))));
      return t;
    })(),
    toolbar(m.name, () => pufMarkdown(m), { ...r, ecc: e }),
  );
}

function hdChart(inter: number[], intra: number[]): HTMLElement {
  const bins = 50;
  const count = (xs: number[]) => {
    const h = new Array<number>(bins).fill(0);
    xs.forEach((x) => h[Math.min(bins - 1, Math.floor(x * bins))]++);
    return h.map((c) => (xs.length ? c / xs.length : 0));
  };
  const series = [
    { name: 'Inter-device (uniqueness)', h: count(inter), n: inter.length },
    { name: 'Intra-device (reliability)', h: count(intra), n: intra.length },
  ];
  const W = Math.max(480, app.clientWidth - 8);
  const H = 200;
  const pad = { l: 44, r: 8, t: 8, b: 24 };
  const maxV = Math.max(0.01, ...series.flatMap((s) => s.h));
  const bw = (W - pad.l - pad.r) / bins;
  const y = (v: number) => pad.t + (1 - v / maxV) * (H - pad.t - pad.b);
  const s = svg('svg', { width: W, height: H, role: 'img', 'aria-label': 'Hamming distance histograms' });
  for (const t of [0, 0.25, 0.5, 0.75, 1]) {
    const x = pad.l + t * (W - pad.l - pad.r);
    s.append(svg('text', { x, y: H - 6, 'text-anchor': 'middle', 'font-size': 10, style: `fill:${INK}` }, document.createTextNode(`${t * 100}%`)));
  }
  s.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y(0), y2: y(0), stroke: GRID }));
  series.forEach((ser, si) => {
    ser.h.forEach((v, i) => {
      if (!v) {
        return;
      }
      const half = bw / 2;
      const bar = svg('path', { d: barPath(pad.l + i * bw + si * half + 1, y(v), Math.max(1, half - 2), y(0) - y(v), false), fill: SERIES[si] });
      hover(bar, `${ser.name}\nHD ${(i * 100) / bins}–${((i + 1) * 100) / bins} %\n${fmt(v * 100, 1)} % of ${ser.n} pairs`);
      s.append(bar);
    });
  });
  const legend = el(
    'div',
    { class: 'toolbar' },
    ...series.map((ser, i) =>
      el('span', {}, el('span', { style: `display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;background:${SERIES[i]}` }), `${ser.name} (n = ${ser.n})`),
    ),
  );
  return el('div', {}, legend, s as unknown as HTMLElement);
}

function pufMarkdown(m: Extract<Msg, { type: 'puf' }>): string {
  const r = m.report;
  const pct = (x: number) => `${(100 * x).toFixed(2)} %`;
  return [
    `# PUF quality report: ${m.name}`,
    '',
    `${r.devices} devices, ${r.bits}-bit responses.`,
    '',
    '| Metric | Value | Ideal |',
    '|---|---:|---:|',
    `| Uniformity | ${pct(r.uniformity.mean)} | 50 % |`,
    `| Uniqueness | ${pct(r.uniqueness)} | 50 % |`,
    `| Reliability | ${pct(r.reliability)} | 100 % |`,
    `| Bit-aliasing | ${pct(r.bitAliasing.mean)} | 50 % |`,
    `| Min-entropy / bit | ${r.minEntropyPerBit.toFixed(4)} | 1 |`,
    '',
    m.ecc.t !== undefined ? `ECC: ${m.ecc.n}-bit blocks need t = ${m.ecc.t} for failure ≤ ${m.ecc.target}.` : '',
    '',
    'Metrics per Maiti, Gunreddy & Schaumont (2013).',
  ].join('\n');
}

onMessage<Msg>((m) => {
  app.replaceChildren();
  if (m.type === 'entropy') {
    renderEntropy(m);
  } else if (m.type === 'restart') {
    renderRestart(m);
  } else if (m.type === 'puf') {
    renderPuf(m);
  }
});
