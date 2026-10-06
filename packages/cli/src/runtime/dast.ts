import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { which } from '../lib/proc';
import type { RuntimeEvent } from './run';

/** A process the extension started that outlived the extension host. */
export interface Orphan {
  pid: number;
  ppid?: number;
  command?: string;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function describe(pid: number): { ppid?: number; command?: string } {
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('powershell', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}") | ForEach-Object { "$($_.ParentProcessId) $($_.CommandLine)" }`], { encoding: 'utf8' }).trim();
      const m = /^(\d+)\s+(.*)$/.exec(out);
      return m ? { ppid: Number(m[1]), command: m[2] } : {};
    } catch {
      return {};
    }
  }
  try {
    const out = execFileSync('ps', ['-o', 'ppid=,command=', '-p', String(pid)], { encoding: 'utf8' }).trim();
    const m = /^(\d+)\s+(.*)$/.exec(out);
    return m ? { ppid: Number(m[1]), command: m[2] } : {};
  } catch {
    return {};
  }
}

/**
 * DAST: processes the extension started (pids recorded by the agent) that are still alive after the
 * extension host exited. They are killed after being recorded.
 */
export function findOrphans(events: RuntimeEvent[], kill = true): Orphan[] {
  const pids = [...new Set(events.filter((e) => e.kind === 'spawn-pid').map((e) => Number(e.pid)))].filter((p) => p > 0);
  const out: Orphan[] = [];
  for (const pid of pids) {
    if (!alive(pid)) {
      continue;
    }
    out.push({ pid, ...describe(pid) });
    if (kill) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // already gone
      }
    }
  }
  return out;
}

// ---------- kernel-level tracing (Linux, root, bpftrace) ----------

/** bpftrace program: follows the audited process tree; reports raw sockets and W+X memory. */
export const BPFTRACE_SCRIPT = `BEGIN { @tree[$1] = 1; printf("READY\\n"); }
tracepoint:sched:sched_process_fork /@tree[args->parent_pid]/ { @tree[args->child_pid] = 1; }
tracepoint:syscalls:sys_enter_socket /@tree[pid] && (args->type & 0xf) == 3/ { printf("RAWSOCK %d %d %s\\n", pid, args->family, comm); }
tracepoint:syscalls:sys_enter_mprotect /@tree[pid] && (args->prot & 6) == 6/ { printf("RWX mprotect %d %d %s\\n", pid, args->len, comm); }
tracepoint:syscalls:sys_enter_mmap /@tree[pid] && (args->prot & 6) == 6/ { printf("RWX mmap %d %d %s\\n", pid, args->len, comm); }
END { clear(@tree); }
`;

export interface KernelEvents {
  rawSockets: { pid: number; family: number; comm: string }[];
  rwx: { pid: number; call: string; len: number; comm: string }[];
}

export function parseTrace(out: string): KernelEvents {
  const k: KernelEvents = { rawSockets: [], rwx: [] };
  for (const line of out.split('\n')) {
    let m = /^RAWSOCK (\d+) (\d+) (.*)$/.exec(line.trim());
    if (m) {
      k.rawSockets.push({ pid: Number(m[1]), family: Number(m[2]), comm: m[3] });
      continue;
    }
    m = /^RWX (mprotect|mmap) (\d+) (\d+) (.*)$/.exec(line.trim());
    if (m) {
      k.rwx.push({ call: m[1], pid: Number(m[2]), len: Number(m[3]), comm: m[4] });
    }
  }
  return k;
}

/** Why kernel tracing is unavailable here, or undefined when it can run. */
export function kernelTracingUnavailable(): string | undefined {
  if (process.platform === 'darwin') {
    return 'macOS needs an Endpoint Security client with Apple’s entitlement; kernel probes skipped';
  }
  if (process.platform !== 'linux') {
    return `kernel probes need Linux (bpftrace); not available on ${process.platform}`;
  }
  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    return 'kernel probes need root (run with sudo) and bpftrace';
  }
  if (!which('bpftrace')) {
    return 'bpftrace is not installed';
  }
  return undefined;
}

export interface Tracer {
  /** Resolves once the probes are attached. */
  ready: Promise<boolean>;
  /** Stops tracing and returns what was seen. */
  stop(): Promise<KernelEvents>;
}

/** Starts bpftrace for the process tree rooted at `pid`. Call only when kernelTracingUnavailable() is undefined. */
export function startTracer(pid: number, dir: string): Tracer {
  const script = join(dir, 'trace.bt');
  writeFileSync(script, BPFTRACE_SCRIPT);
  const bt: ChildProcess = spawn(which('bpftrace')!, [script, String(pid)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let resolveReady: (ok: boolean) => void = () => undefined;
  const ready = new Promise<boolean>((r) => (resolveReady = r));
  const timer = setTimeout(() => resolveReady(false), 20_000);
  bt.stdout!.on('data', (b: Buffer) => {
    out += b.toString();
    if (out.includes('READY')) {
      clearTimeout(timer);
      resolveReady(true);
    }
  });
  bt.on('error', () => resolveReady(false));
  bt.on('close', () => resolveReady(false));
  return {
    ready,
    stop: () =>
      new Promise((resolve) => {
        if (bt.exitCode !== null) {
          resolve(parseTrace(out));
          return;
        }
        bt.on('close', () => resolve(parseTrace(out)));
        bt.kill('SIGINT');
      }),
  };
}

/** The extension waits for this file before loading, so probes attach first. */
export function gateFile(root: string): string {
  return join(root, 'gate');
}

export function openGate(root: string): void {
  if (!existsSync(gateFile(root))) {
    writeFileSync(gateFile(root), '');
  }
}
