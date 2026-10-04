import { el, fmt, onMessage, post } from '@ide-ext/core/web';
import type { FlameNode, Profile } from '../profile';
import { flattenInference, summarize } from '../profile';

interface Msg {
  type: 'profile';
  profile: Profile | null;
  view?: 'flame' | 'table';
}

const app = document.getElementById('app')!;
const tooltip = el('div', { class: 'tooltip', style: 'display:none' });
document.body.append(tooltip);

let profile: Profile | null = null;
let zoom: FlameNode | null = null;
let search = '';

onMessage<Msg>((msg) => {
  if (msg.type === 'profile') {
    profile = msg.profile;
    zoom = null;
    render();
  }
});

function hue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) >>> 0;
  }
  return h % 360;
}

function render(): void {
  app.replaceChildren();
  if (!profile) {
    app.append(el('p', { class: 'muted' }, 'No profile loaded. Run "Julia Profiler: Analyze Invalidations & Inference".'));
    return;
  }
  const s = summarize(profile);
  app.append(
    el('h1', {}, `Compiler profile — ${profile.package || profile.project}`),
    el('p', { class: 'muted' }, `Julia ${profile.julia} · ${profile.createdAt}${profile.workload ? ` · workload ${profile.workload}` : ''}`),
    el(
      'div',
      { class: 'cards' },
      card('Invalidation trees', String(s.trees)),
      card('MethodInstances invalidated', String(s.invalidated)),
      card('Inference time', s.inferenceTime !== undefined ? `${fmt(s.inferenceTime, 3)} s` : '—'),
      card('Inference triggers', String(s.triggers)),
    ),
  );
  for (const w of profile.warnings) {
    app.append(el('p', { class: 'warn' }, `⚠ ${w}`));
  }
  if (!profile.inference) {
    app.append(el('p', { class: 'muted' }, 'No inference data: run with a workload script to record @snoop_inference.'));
    return;
  }
  const input = el('input', { type: 'search', placeholder: 'Highlight method…', value: search });
  input.addEventListener('input', () => {
    search = input.value.toLowerCase();
    drawFlame(svgHost);
  });
  const reset = el('button', { class: 'secondary' }, 'Reset zoom');
  reset.addEventListener('click', () => {
    zoom = null;
    drawFlame(svgHost);
  });
  const svgHost = el('div', {});
  app.append(
    el('h2', {}, 'Inference flame graph'),
    el('p', { class: 'muted' }, 'Width = inclusive inference time. Click to zoom, ⌘/Ctrl-click to open the source.'),
    el('div', { class: 'toolbar' }, input, reset),
    svgHost,
  );
  drawFlame(svgHost);

  const rows = flattenInference(profile.inference.root).slice(0, 50);
  const table = el(
    'table',
    {},
    el('tr', {}, el('th', {}, 'Method'), el('th', { class: 'num' }, 'Self time (ms)'), el('th', { class: 'num' }, 'Instances'), el('th', {}, 'Location')),
  );
  for (const r of rows) {
    const loc = r.file && r.line > 0 ? el('span', { class: 'link' }, `${r.file.split(/[\\/]/).pop()}:${r.line}`) : el('span', { class: 'muted' }, '—');
    loc.addEventListener('click', () => post({ type: 'openLocation', file: r.file, line: r.line }));
    table.append(
      el('tr', {}, el('td', {}, `${r.module}.${r.method}`), el('td', { class: 'num' }, fmt(r.self * 1000, 2)), el('td', { class: 'num' }, String(r.count)), el('td', {}, loc)),
    );
  }
  app.append(el('h2', {}, 'Top methods by self inference time'), table);

  if (profile.triggers.length) {
    const trig = el('table', {}, el('tr', {}, el('th', {}, 'Caller'), el('th', {}, 'Callee inferred at runtime'), el('th', { class: 'num' }, 'Time (ms)')));
    for (const t of [...profile.triggers].sort((a, b) => b.time - a.time).slice(0, 50)) {
      const caller = el('span', { class: t.caller.file ? 'link' : '' }, `${t.caller.func} (${t.caller.file.split(/[\\/]/).pop()}:${t.caller.line})`);
      caller.addEventListener('click', () => post({ type: 'openLocation', file: t.caller.file, line: t.caller.line }));
      trig.append(el('tr', {}, el('td', {}, caller), el('td', {}, `${t.callee.module}.${t.callee.method}`), el('td', { class: 'num' }, fmt(t.time * 1000, 2))));
    }
    app.append(
      el('h2', {}, 'Inference triggers'),
      el('p', { class: 'muted' }, 'Runtime dispatch from these call sites forced fresh type inference. Annotating types or adding a function barrier usually removes them.'),
      trig,
    );
  }
}

function card(k: string, v: string): HTMLElement {
  return el('div', { class: 'card' }, el('div', { class: 'v' }, v), el('div', { class: 'k' }, k));
}

const ROW = 18;
const NS = 'http://www.w3.org/2000/svg';

function drawFlame(host: HTMLElement): void {
  host.replaceChildren();
  const root = zoom ?? profile!.inference!.root;
  const width = Math.max(400, host.clientWidth || app.clientWidth || 800);
  const rects: { n: FlameNode; x: number; w: number; d: number }[] = [];
  let depth = 0;
  const layout = (n: FlameNode, x: number, w: number, d: number) => {
    if (w < 0.5) {
      return;
    }
    rects.push({ n, x, w, d });
    depth = Math.max(depth, d);
    let cx = x;
    for (const c of n.children) {
      const cw = root.total > 0 ? (c.total / root.total) * width : 0;
      layout(c, cx, cw, d + 1);
      cx += cw;
    }
  };
  layout(root, 0, width, 0);
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String((depth + 1) * ROW));
  for (const r of rects) {
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('transform', `translate(${r.x},${r.d * ROW})`);
    const rect = document.createElementNS(NS, 'rect');
    rect.setAttribute('width', String(Math.max(0, r.w - 1)));
    rect.setAttribute('height', String(ROW - 1));
    const label = `${r.n.module ? `${r.n.module}.` : ''}${r.n.name}`;
    const hit = search && label.toLowerCase().includes(search);
    rect.setAttribute('fill', hit ? 'hsl(300,70%,55%)' : r.n.name === '(other)' ? 'hsl(0,0%,55%)' : `hsl(${20 + (hue(r.n.module) % 40)},75%,${r.d % 2 ? 58 : 52}%)`);
    rect.setAttribute('rx', '2');
    g.append(rect);
    if (r.w > 40) {
      const text = document.createElementNS(NS, 'text');
      text.setAttribute('x', '4');
      text.setAttribute('y', String(ROW - 5));
      text.setAttribute('font-size', '11');
      text.setAttribute('style', 'fill:#111');
      const max = Math.floor((r.w - 8) / 6.5);
      text.textContent = label.length > max ? `${label.slice(0, Math.max(0, max - 1))}…` : label;
      g.append(text);
    }
    g.style.cursor = 'pointer';
    g.addEventListener('mousemove', (e) => {
      tooltip.style.display = 'block';
      tooltip.style.left = `${Math.min(e.clientX + 12, window.innerWidth - 360)}px`;
      tooltip.style.top = `${e.clientY + 12}px`;
      tooltip.textContent = `${label}\n${r.n.sig}\ninclusive ${fmt(r.n.total * 1000, 2)} ms · self ${fmt(r.n.self * 1000, 2)} ms\n${r.n.file ? `${r.n.file}:${r.n.line}` : ''}`;
    });
    g.addEventListener('mouseleave', () => (tooltip.style.display = 'none'));
    g.addEventListener('click', (e) => {
      if ((e.metaKey || e.ctrlKey) && r.n.file) {
        post({ type: 'openLocation', file: r.n.file, line: r.n.line });
        return;
      }
      zoom = r.n === root ? null : r.n;
      drawFlame(host);
    });
    svg.append(g);
  }
  host.append(svg);
}

window.addEventListener('resize', () => {
  const host = document.querySelector('svg')?.parentElement;
  if (host && profile?.inference) {
    drawFlame(host);
  }
});
