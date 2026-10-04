import { el, onMessage } from '@ide-ext/core/web';
import { formatBytes, formatNs, type Judgement, type Verdict } from '../bench';

interface Msg {
  type: 'bench';
  rows: Judgement[];
  baselineRef: string | null;
  tolerance: number;
  julia: string;
  createdAt: string;
}

const app = document.getElementById('app')!;
const CLASS: Record<Verdict, string> = { regression: 'fail', improvement: 'pass', invariant: 'muted', added: 'warn', removed: 'warn' };

onMessage<Msg>((msg) => {
  if (msg.type !== 'bench') {
    return;
  }
  app.replaceChildren();
  const counts = { regression: 0, improvement: 0, invariant: 0, added: 0, removed: 0 } as Record<Verdict, number>;
  msg.rows.forEach((r) => counts[r.time]++);
  app.append(
    el('h1', {}, msg.baselineRef ? `Benchmarks vs ${msg.baselineRef}` : 'Benchmarks'),
    el('p', { class: 'muted' }, `Julia ${msg.julia} · ${msg.createdAt} · median time, tolerance ±${(msg.tolerance * 100).toFixed(0)}%`),
  );
  if (msg.baselineRef) {
    app.append(
      el(
        'div',
        { class: 'cards' },
        ...(['regression', 'improvement', 'invariant'] as Verdict[]).map((v) =>
          el('div', { class: 'card' }, el('div', { class: `v ${CLASS[v]}` }, String(counts[v])), el('div', { class: 'k' }, `${v}s`)),
        ),
      ),
    );
  }
  const head = msg.baselineRef
    ? ['Benchmark', 'Baseline', 'Current', 'Time ratio', 'Verdict', 'Memory', 'Mem ratio']
    : ['Benchmark', 'Median', 'Minimum', 'Memory', 'Allocs'];
  const table = el('table', {}, el('tr', {}, ...head.map((h, i) => el('th', i ? { class: 'num' } : {}, h))));
  for (const r of msg.rows) {
    const c = r.current;
    const b = r.baseline;
    const cells = msg.baselineRef
      ? [
          b ? formatNs(b.median_ns) : '—',
          c ? formatNs(c.median_ns) : '—',
          r.timeRatio !== undefined ? `${r.timeRatio.toFixed(3)}×` : '—',
          r.time,
          c ? formatBytes(c.memory) : '—',
          r.memoryRatio !== undefined && Number.isFinite(r.memoryRatio) ? `${r.memoryRatio.toFixed(3)}×` : '—',
        ]
      : [formatNs(c!.median_ns), formatNs(c!.min_ns), formatBytes(c!.memory), String(c!.allocs)];
    table.append(
      el(
        'tr',
        {},
        el('td', {}, r.name),
        ...cells.map((v, i) => el('td', { class: `num ${msg.baselineRef && i === 3 ? CLASS[r.time] : ''}` }, v)),
      ),
    );
  }
  app.append(table);
});
