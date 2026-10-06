import { isIP } from 'node:net';
import { dirname, isAbsolute, relative } from 'node:path';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { signal, type Located, type Signal } from '../../../../extensions/endpoint-security/src/extscan/signals';
import type { KernelEvents, Orphan } from './dast';
import { DECOY_HOME, HONEY, type RuntimeEvent, type Sandbox } from './run';

/** Runtime vector → the events that support it (the evidence chain uses them). */
export type Evidence = Map<string, RuntimeEvent[]>;

export interface Classified {
  signals: Signal[];
  evidence: Evidence;
  /** Recorded editor API calls (terminals, commands, webviews, debug hooks…). */
  api: RuntimeEvent[];
  errors: RuntimeEvent[];
}

const SUSPICIOUS_EXEC = /(^|[\s/\\"'])(curl|wget|bash|sh|zsh|dash|powershell|pwsh|cmd(\.exe)?|nc|ncat|netcat|osascript|certutil|bitsadmin|mshta|rundll32|regsvr32|python3?|perl|ruby|launchctl|crontab|schtasks|reg)(\.exe)?(\s|$|["'])/i;
const DOWNLOAD_AND_RUN = /(curl|wget|iwr|invoke-webrequest|irm)\b[\s\S]*(\|\s*(ba|z)?sh\b|\biex\b|invoke-expression|&&\s*(chmod|\.\/))/i;
const SUSPICIOUS_EVAL = /require\s*\(|child_process|process\.env|https?:\/\/|fromCharCode|atob\(|Buffer\.from|\bexec(Sync)?\(|spawn\(/;
const BENIGN_EVAL = /^\s*(return this;?|"use strict";?return this;?)\s*$/;
const DYNDNS = /(^|\.)(duckdns\.org|no-ip\.(com|org|biz|info)|noip\.me|ddns\.net|dynu\.(com|net)|afraid\.org|hopto\.org|zapto\.org|sytes\.net|dyndns\.org|serveo\.net|loca\.lt|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com)$/i;
const WEB_PORTS = new Set([80, 443, 8080, 8443]);
const LOCAL = /^(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)$/;
const BIG_UPLOAD = 64 * 1024;
const WORKSPACE_SECRET = /(^|[/\\])(\.env|credentials\.json|secrets?\.ya?ml|[^/\\]+\.(pem|key|p12|pfx))$/i;

const inside = (p: string, root: string) => {
  const r = relative(root, p);
  return r === '' || (!!r && !r.startsWith('..') && !isAbsolute(r));
};

/** `fn (/path/file.js:12:5)` → file and position. */
function located(e: RuntimeEvent, id: string, message: string): Located[] {
  const m = e.at ? /\(?([^()]+?):(\d+):(\d+)\)?$/.exec(e.at) : null;
  if (!m) {
    return [];
  }
  const line = Math.max(0, Number(m[2]) - 1);
  const character = Math.max(0, Number(m[3]) - 1);
  return [{ file: m[1], finding: { ruleId: id, severity: 'warning', message, range: { start: { line, character }, end: { line, character } }, refs: [] } }];
}

function make(id: string, message: string, events: RuntimeEvent[], _sb: Sandbox, opts: { weight?: number; force?: 'high' | 'medium' } = {}): Signal {
  const locations = events.flatMap((e) => located(e, id, message)).slice(0, 20);
  return signal(id, message, locations, { count: events.length, ...opts });
}

function declaredHosts(manifest: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['repository', 'homepage', 'bugs']) {
    const v = manifest[key];
    const raw = typeof v === 'string' ? v : v && typeof v === 'object' ? (v as { url?: string }).url : undefined;
    try {
      if (raw) {
        out.push(new URL(raw.replace(/^git\+/, '')).hostname.toLowerCase());
      }
    } catch {
      // not a URL
    }
  }
  return out;
}
const PLATFORM = /(^|\.)(visualstudio\.com|vscode-cdn\.net|microsoft\.com|github\.com|githubusercontent\.com|npmjs\.org|open-vsx\.org)$/i;

/** Turns the agent's event log into runtime signals. */
export interface DastInput {
  /** Processes still alive after the extension host exited. */
  orphans?: Orphan[];
  /** Kernel probes (Linux, root, bpftrace). */
  kernel?: KernelEvents;
  /** W+X mappings an empty extension produces under the same runtime. */
  baselineRwx?: number;
}

export function classify(events: RuntimeEvent[], sb: Sandbox, opts: { duration: number; manifest: Record<string, unknown> } & DastInput): Classified {
  const signals: Signal[] = [];
  const evidence: Evidence = new Map();
  const add = (s: Signal, evs: RuntimeEvent[]) => {
    signals.push(s);
    evidence.set(s.id, evs);
  };
  const by = (k: string) => events.filter((e) => e.kind === k);

  // Processes.
  const spawns = by('spawn');
  if (spawns.length) {
    const line = (e: RuntimeEvent) => [e.cmd, ...((e.argv as string[]) ?? [])].join(' ');
    const bad = spawns.filter((e) => SUSPICIOUS_EXEC.test(` ${line(e)} `));
    const dl = spawns.find((e) => DOWNLOAD_AND_RUN.test(line(e)));
    const shown = (bad[0] ?? spawns[0]) as RuntimeEvent;
    const blocked = spawns.every((e) => e.blocked) ? ' (blocked by the audit; recorded only)' : '';
    const envKeys = [...new Set(spawns.flatMap((e) => Object.keys((e.env as Record<string, string> | undefined) ?? {})))];
    const env = envKeys.length ? `; extra environment ${envKeys.slice(0, 6).join(', ')}` : '';
    add(
      make('runtime/child-process-spawned', `${spawns.length} process start(s), e.g. \`${line(shown).slice(0, 160)}\`${blocked}${env}${dl ? '; downloads and runs code' : ''}`, bad.length ? bad : spawns, sb, {
        weight: dl ? 9 : bad.length ? 7 : 2,
        force: dl ? 'high' : undefined,
      }),
      spawns,
    );
  }

  // Files.
  const nodeRoot = dirname(dirname(process.execPath));
  const tmp = realpathSync(tmpdir());
  const fsEvents = by('fs').filter((e) => typeof e.path === 'string' && isAbsolute(e.path));
  const inHome = fsEvents.filter((e) => inside(String(e.path), sb.home));
  const secretPath = (p: string) => {
    const r = relative(sb.home, p).replace(/\\/g, '/');
    return r in DECOY_HOME || /^(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config\/gh)(\/|$)/.test(r);
  };
  const homeReads = inHome.filter((e) => e.op !== 'write' && secretPath(String(e.path)));
  const homeWrites = inHome.filter((e) => e.op === 'write');
  const homeOther = inHome.filter((e) => e.op !== 'write' && !secretPath(String(e.path)));
  const wsSecrets = fsEvents.filter((e) => inside(String(e.path), sb.workspace) && WORKSPACE_SECRET.test(String(e.path)));
  const outside = fsEvents.filter(
    (e) =>
      ![sb.ext, sb.workspace, sb.home, nodeRoot].some((r) => inside(String(e.path), r)) &&
      !inside(String(e.path), tmp) &&
      !/^\/(dev|proc\/self)\//.test(String(e.path)),
  );
  if (homeReads.length || homeWrites.length || homeOther.length || wsSecrets.length || outside.length) {
    const rel = (e: RuntimeEvent) => (inside(String(e.path), sb.home) ? `~/${relative(sb.home, String(e.path))}` : String(e.path));
    const parts: string[] = [];
    if (homeReads.length) {parts.push(`read decoy home secrets ${[...new Set(homeReads.map(rel))].slice(0, 4).join(', ')}`);}
    if (homeWrites.length) {parts.push(`wrote into the home folder ${[...new Set(homeWrites.map(rel))].slice(0, 3).join(', ')}`);}
    if (wsSecrets.length) {parts.push(`read workspace secrets ${[...new Set(wsSecrets.map((e) => relative(sb.workspace, String(e.path))))].slice(0, 4).join(', ')}`);}
    if (homeOther.length) {parts.push(`read the home folder (${[...new Set(homeOther.map(rel))].slice(0, 3).join(', ')})`);}
    if (outside.length) {parts.push(`touched ${new Set(outside.map((e) => e.path)).size} path(s) outside its folders, e.g. ${outside[0].path}`);}
    const all = [...homeReads, ...homeWrites, ...wsSecrets, ...homeOther, ...outside];
    add(
      make('runtime/fs-access-violation', parts.join('; '), all, sb, {
        weight: homeReads.length || homeWrites.length ? 8 : wsSecrets.length ? 6 : 3,
        force: homeReads.length || homeWrites.length ? 'high' : undefined,
      }),
      all,
    );
  }

  // Dynamic code.
  const evals = by('eval').filter((e) => !BENIGN_EVAL.test(String(e.code ?? '')));
  if (evals.length) {
    const bad = evals.filter((e) => SUSPICIOUS_EVAL.test(String(e.code)));
    const shown = bad[0] ?? evals[0];
    add(
      make('runtime/dynamic-eval-execution', `${evals.length} dynamic evaluation(s) via ${[...new Set(evals.map((e) => e.fn))].join(', ')}, e.g. \`${String(shown.code).replace(/\s+/g, ' ').slice(0, 120)}\``, bad.length ? bad : evals, sb, {
        weight: bad.length ? 6 : 2,
      }),
      evals,
    );
  }

  // Network destinations.
  const net = events.filter((e) => ['http', 'connect', 'dns', 'udp-send'].includes(e.kind) && !LOCAL.test(String(e.host ?? '')) && e.host);
  if (net.length) {
    const declared = declaredHosts(opts.manifest);
    const ok = (h: string) => PLATFORM.test(h) || declared.some((d) => h === d || h.endsWith(`.${d}`));
    const hosts = [...new Set(net.map((e) => String(e.host).toLowerCase()))];
    const leaked = net.filter((e) => String(e.sample ?? '').includes(HONEY));
    const risky = hosts.filter((h) => (isIP(h) && !LOCAL.test(h)) || DYNDNS.test(h));
    const bigUndeclared = net.filter((e) => Number(e.bytes ?? 0) >= BIG_UPLOAD && !ok(String(e.host)));
    const undeclared = hosts.filter((h) => !ok(h));
    const parts = [`${hosts.length} destination(s): ${hosts.slice(0, 5).join(', ')}${hosts.length > 5 ? ', …' : ''}`];
    if (leaked.length) {parts.push(`sent decoy secrets to ${[...new Set(leaked.map((e) => e.host))].join(', ')}`);}
    if (risky.length) {parts.push(`IP-literal / dynamic-DNS hosts ${risky.join(', ')}`);}
    if (bigUndeclared.length) {parts.push(`${bigUndeclared.length} upload(s) of 64 KB+ to undeclared hosts`);}
    if (undeclared.length && !leaked.length) {parts.push(`${undeclared.length} host(s) not named in the manifest`);}
    add(
      make('runtime/dns-and-http-destinations', parts.join('; '), leaked.length ? leaked : net, sb, {
        weight: leaked.length ? 10 : risky.length ? 6 : bigUndeclared.length ? 5 : undeclared.length ? 3 : 2,
        force: leaked.length ? 'high' : undefined,
      }),
      net,
    );
  }

  // Clipboard.
  const clip = events.filter((e) => e.kind === 'clipboard' || (e.kind === 'vscode' && e.api === 'env.clipboard.readText'));
  if (clip.length) {
    const perMinute = clip.length / Math.max(opts.duration / 60, 1 / 60);
    add(
      make('runtime/clipboard-poll-frequency', `${clip.length} clipboard read(s) with no user action (${perMinute.toFixed(1)}/min)`, clip, sb, { weight: perMinute > 1 ? 6 : 3 }),
      clip,
    );
  }

  // Non-HTTP traffic: from JavaScript (UDP, TCP to non-web ports) and raw sockets from the kernel probes.
  const httpHosts = new Set(by('http').map((e) => String(e.host)));
  const raw = events.filter(
    (e) => (e.kind === 'udp' || e.kind === 'udp-send' || (e.kind === 'connect' && !WEB_PORTS.has(Number(e.port)) && !httpHosts.has(String(e.host)))) && !LOCAL.test(String(e.host ?? 'x')),
  );
  const kraw: RuntimeEvent[] = (opts.kernel?.rawSockets ?? []).map((k) => ({ t: 0, kind: 'raw-socket', pid: k.pid, family: k.family, comm: k.comm }));
  if (raw.length || kraw.length) {
    const what = raw.map((e) => (e.kind.startsWith('udp') ? `UDP${e.host ? ` ${e.host}:${e.port}` : ''}` : `TCP ${e.host}:${e.port}`));
    what.push(...kraw.map((k) => `SOCK_RAW (family ${k.family}) in ${k.comm}`));
    add(
      make('runtime/network-raw-socket', `non-HTTP traffic: ${[...new Set(what)].slice(0, 4).join(', ')}`, raw, sb, {
        weight: kraw.length ? 6 : raw.some((e) => e.kind.startsWith('udp')) ? 4 : 3,
      }),
      [...raw, ...kraw],
    );
  }

  // Processes that outlived the extension host.
  if (opts.orphans?.length) {
    const evs: RuntimeEvent[] = opts.orphans.map((o) => ({ t: 0, kind: 'orphan', pid: o.pid, ppid: o.ppid, command: o.command }));
    const spawnAt = by('spawn');
    add(
      make('runtime/orphan-process-daemon', `${opts.orphans.length} process(es) still running after exit, e.g. pid ${opts.orphans[0].pid} \`${String(opts.orphans[0].command ?? '?').slice(0, 120)}\` (killed by the audit)`, spawnAt, sb, { force: 'high' }),
      evs,
    );
  }

  // Writable + executable memory beyond what an empty extension produces.
  const rwx = opts.kernel?.rwx ?? [];
  const excess = rwx.length - (opts.baselineRwx ?? 0);
  if (excess > 0) {
    const evs: RuntimeEvent[] = rwx.map((r) => ({ t: 0, kind: 'rwx', call: r.call, pid: r.pid, len: r.len, comm: r.comm }));
    add(make('runtime/mprotect-rwx', `${rwx.length} W+X mapping(s) (${opts.baselineRwx ?? 0} expected from the JIT), e.g. ${rwx[0].call} ${rwx[0].len} bytes in ${rwx[0].comm}`, [], sb), evs);
  }

  return { signals, evidence, api: by('vscode'), errors: by('error') };
}
