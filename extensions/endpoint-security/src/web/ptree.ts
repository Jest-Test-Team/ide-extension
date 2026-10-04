import { el, onMessage, post } from '@ide-ext/core/web';
import type { SimulationResult } from '../ptree/engine';

interface Msg {
  type: 'simulation';
  file: string;
  result: SimulationResult;
}

const app = document.getElementById('app')!;
const tip = el('div', { class: 'tooltip', style: 'display:none' });
document.body.append(tip);
const NS = 'http://www.w3.org/2000/svg';
const INK = 'var(--vscode-descriptionForeground)';
const LINE = 'var(--vscode-panel-border, rgba(128,128,128,.5))';
// Status colours for alert state; every coloured mark also carries a text badge.
const SEV: Record<string, string> = {
  critical: 'var(--vscode-errorForeground, #f14c4c)',
  high: 'var(--vscode-editorWarning-foreground, #cca700)',
  medium: 'var(--vscode-charts-blue, #3794ff)',
  low: INK,
};
const SEV_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

function svg(tag: string, attrs: Record<string, string | number>, ...kids: Node[]): SVGElement {
  const n = document.createElementNS(NS, tag);
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, String(v)));
  n.append(...kids);
  return n;
}

const mitreUrl = (t: string) => `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`;
const base = (p: string) => p.split(/[\\/]/).pop() ?? p;

function render(m: Msg): void {
  const r = m.result;
  app.replaceChildren();
  const worst = r.detections.reduce((w, d) => (SEV_RANK[d.severity] > SEV_RANK[w] ? d.severity : w), 'low');
  app.append(
    el('h1', {}, `Simulation — ${r.scenario}`),
    el('p', { class: 'muted' }, `${m.file} · ${r.timeline.length} events · ${r.processes.length} processes · data-only replay, nothing was executed`),
    el(
      'div',
      { class: 'cards' },
      el('div', { class: 'card' }, el('div', { class: 'v' }, String(r.detections.length)), el('div', { class: 'k' }, 'Detections')),
      el('div', { class: 'card' }, el('div', { class: 'v', style: `color:${SEV[worst]}` }, r.detections.length ? worst : '—'), el('div', { class: 'k' }, 'Highest severity')),
      el('div', { class: 'card' }, el('div', { class: 'v' }, String(new Set(r.detections.flatMap((d) => d.mitre)).size)), el('div', { class: 'k' }, 'ATT&CK techniques')),
    ),
    ...r.warnings.map((w) => el('p', { class: 'warn' }, `⚠ ${w}`)),
    el('h2', {}, 'Process tree'),
    tree(r),
    el('h2', {}, 'Detections'),
    detections(r),
    el('h2', {}, 'Timeline'),
    timeline(r),
  );
}

function tree(r: SimulationResult): Element {
  const byId = new Map(r.processes.map((p) => [p.id, p]));
  const roots = r.processes.filter((p) => !p.parent || !byId.has(p.parent));
  const pos = new Map<string, { x: number; y: number }>();
  let row = 0;
  const place = (id: string, depth: number) => {
    pos.set(id, { x: 16 + depth * 200, y: 16 + row * 52 });
    row++;
    byId.get(id)!.children.forEach((c) => place(c, depth + 1));
  };
  roots.forEach((p) => place(p.id, 0));
  const W = Math.max(...[...pos.values()].map((p) => p.x)) + 200;
  const H = row * 52 + 16;
  const s = svg('svg', { width: W, height: H, role: 'img', 'aria-label': 'Process tree' });
  s.append(svg('defs', {}, svg('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' }, svg('path', { d: 'M0,0 L10,5 L0,10 z', fill: INK }))));
  // Parent → child edges.
  for (const p of r.processes) {
    const a = pos.get(p.id)!;
    for (const c of p.children) {
      const b = pos.get(c)!;
      s.append(svg('path', { d: `M${a.x + 8},${a.y + 34} V${b.y + 17} H${b.x}`, fill: 'none', stroke: LINE, 'stroke-width': 2 }));
    }
  }
  // Cross edges: terminate / inject.
  for (const p of r.processes) {
    for (const [from, kind] of [...(p.injectedBy ?? []).map((f) => [f, 'inject'] as const), ...(p.terminatedBy ? [[p.terminatedBy, 'terminate'] as const] : [])]) {
      const a = pos.get(from);
      const b = pos.get(p.id);
      if (a && b) {
        const path = svg('path', { d: `M${a.x + 170},${a.y + 17} C${a.x + 230},${a.y + 17} ${b.x + 230},${b.y + 17} ${b.x + 172},${b.y + 17}`, fill: 'none', stroke: kind === 'inject' ? SEV.high : SEV.critical, 'stroke-width': 2, 'stroke-dasharray': '5 4', 'marker-end': 'url(#arrow)' });
        path.append(svg('title', {}, document.createTextNode(`${from} ${kind === 'inject' ? 'injects into' : 'terminates'} ${p.id}`)));
        s.append(path);
      }
    }
  }
  for (const p of r.processes) {
    const { x, y } = pos.get(p.id)!;
    const det = r.detections.filter((d) => d.processes.includes(p.id));
    const sev = det.reduce((w, d) => (SEV_RANK[d.severity] > SEV_RANK[w] ? d.severity : w), 'low');
    const g = svg('g', { transform: `translate(${x},${y})`, style: 'cursor:default' });
    g.append(
      svg('rect', { width: 170, height: 34, rx: 4, fill: 'var(--vscode-editorWidget-background, transparent)', stroke: det.length ? SEV[sev] : LINE, 'stroke-width': det.length ? 2 : 1, 'stroke-dasharray': p.end !== undefined ? '4 3' : '' }),
      svg('text', { x: 8, y: 14, 'font-size': 12, 'font-weight': 600 }, document.createTextNode(base(p.image).slice(0, 22))),
      svg('text', { x: 8, y: 28, 'font-size': 10, style: `fill:${INK}` }, document.createTextNode(`${p.id}${p.end !== undefined ? ' · exited' : ''}${p.injectedBy ? ' · injected' : ''}`)),
    );
    if (det.length) {
      g.append(svg('text', { x: 162, y: 14, 'text-anchor': 'end', 'font-size': 11, style: `fill:${SEV[sev]}` }, document.createTextNode(`⚠ ${det.length}`)));
    }
    g.addEventListener('mousemove', (e) => {
      tip.style.display = 'block';
      tip.style.left = `${Math.min(e.clientX + 12, window.innerWidth - 400)}px`;
      tip.style.top = `${e.clientY + 12}px`;
      tip.textContent = `${p.image}\n${p.cmdline ?? ''}\n${det.map((d) => `⚠ ${d.severity}: ${d.title}`).join('\n')}`.trim();
    });
    g.addEventListener('mouseleave', () => (tip.style.display = 'none'));
    s.append(g);
  }
  const legend = el('p', { class: 'muted' }, 'Solid box = running at end · dashed box = exited · coloured outline/⚠ = involved in detections · dashed arrows = terminate / inject');
  return el('div', { style: 'overflow-x:auto' }, s as unknown as HTMLElement, legend);
}

function detections(r: SimulationResult): Element {
  if (!r.detections.length) {
    return el('p', { class: 'muted' }, 'No rule matched this scenario.');
  }
  const t = el('table', {}, el('tr', {}, el('th', {}, 'Severity'), el('th', {}, 'Rule'), el('th', {}, 'ATT&CK'), el('th', { class: 'num' }, 't (ms)'), el('th', {}, 'Processes')));
  for (const d of [...r.detections].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.t - b.t)) {
    const mitre = el('td', {});
    d.mitre.forEach((m, i) => {
      if (i) {
        mitre.append(', ');
      }
      mitre.append(el('a', { href: mitreUrl(m) }, m));
    });
    t.append(el('tr', {}, el('td', { style: `color:${SEV[d.severity]}` }, `● ${d.severity}`), el('td', {}, `${d.title} (${d.ruleId})`), mitre, el('td', { class: 'num' }, String(d.t)), el('td', {}, d.processes.join(', '))));
  }
  return t;
}

function timeline(r: SimulationResult): Element {
  const t = el('table', {}, el('tr', {}, el('th', { class: 'num' }, 't (ms)'), el('th', {}, 'Event'), el('th', {}, 'Detections')));
  for (const e of r.timeline) {
    const summary = el('span', { class: e.line ? 'link' : '' }, e.summary);
    summary.addEventListener('click', () => e.line && post({ type: 'reveal', line: e.line }));
    t.append(el('tr', {}, el('td', { class: 'num' }, String(e.t)), el('td', {}, summary), el('td', { class: e.detections.length ? 'warn' : 'muted' }, e.detections.join(', ') || '—')));
  }
  return t;
}

onMessage<Msg>((m) => {
  if (m.type === 'simulation') {
    render(m);
  }
});
