'use strict';
// jest-security runtime audit agent (IAST). Loaded with `node --require audit-agent.cjs` (or a shim)
// before an extension runs; records what the extension does as JSONL in $JEST_AUDIT_LOG.
//   JEST_AUDIT_EXT        extension folder: events are attributed by stack frames inside it
//   JEST_AUDIT_ALLOW_EXEC "1" runs child processes; otherwise they are recorded and replaced by a no-op
//   JEST_AUDIT_OFFLINE    "1" records connections but sends them to 127.0.0.1:9 (refused)
const fs = require('fs');
const Module = require('module');

const LOG = process.env.JEST_AUDIT_LOG;
const EXT = process.env.JEST_AUDIT_EXT || '';
const ALLOW_EXEC = process.env.JEST_AUDIT_ALLOW_EXEC === '1';
const OFFLINE = process.env.JEST_AUDIT_OFFLINE === '1';
const T0 = Date.now();
const writeSync = fs.writeSync;
const fd = LOG ? fs.openSync(LOG, 'a') : -1;
let busy = false;

function frame() {
  const stack = new Error().stack || '';
  const line = stack.split('\n').find((l) => EXT && l.includes(EXT) && !l.includes('audit-agent') && !l.includes('vscode-mock'));
  return line ? line.trim().replace(/^at\s+/, '') : undefined;
}

/** Writes one event; `force` skips attribution (events the harness reports for the extension). */
function record(kind, data, force) {
  if (fd < 0 || busy) {
    return;
  }
  busy = true;
  try {
    const at = frame();
    if (at || force || !EXT) {
      writeSync(fd, JSON.stringify({ t: Date.now() - T0, kind, ...data, at }) + '\n');
    }
  } catch {
    // never break the extension
  } finally {
    busy = false;
  }
}

const cp = require('child_process');
let spawning = 0; // exec → execFile → spawn internally: record the outermost call only
const str = (v, n = 300) => (typeof v === 'string' ? v : v === undefined ? '' : String(v)).slice(0, n);
function wrap(obj, name, before) {
  const orig = obj && obj[name];
  if (typeof orig !== 'function' || orig.__jestAudit) {
    return;
  }
  const w = function (...args) {
    const r = before.call(this, args, orig);
    if (r && r.replaced) {
      return r.value;
    }
    const nested = obj === cp;
    spawning += nested ? 1 : 0;
    try {
      return orig.apply(this, r && r.args ? r.args : args);
    } finally {
      spawning -= nested ? 1 : 0;
    }
  };
  w.__jestAudit = true;
  Object.defineProperty(w, 'name', { value: name });
  obj[name] = w;
}

// ---- child processes ----
const noop = [process.execPath, ['-e', 'process.exit(126)']];
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'exec', 'execSync']) {
  wrap(cp, name, function (args) {
    if (spawning) {
      return undefined;
    }
    const shell = name.startsWith('exec') && !name.startsWith('execFile');
    const cmd = str(args[0], 500);
    const argv = !shell && Array.isArray(args[1]) ? args[1].map((a) => str(a, 200)) : [];
    record('spawn', { fn: name, cmd, argv, blocked: !ALLOW_EXEC });
    if (ALLOW_EXEC) {
      return undefined;
    }
    const rest = args.slice(shell ? 1 : Array.isArray(args[1]) ? 2 : 1);
    if (name === 'fork') {
      return { args: [require.resolve('./noop.cjs'), [], ...rest.filter((a) => typeof a !== 'string')] };
    }
    return { args: shell ? [`"${noop[0]}" -e "process.exit(126)"`, ...rest] : [noop[0], noop[1], ...rest] };
  });
}
for (const name of ['spawn', 'execFile', 'fork', 'exec']) {
  const orig = cp[name];
  cp[name] = Object.assign(function (...args) {
    const child = orig.apply(this, args);
    if (child && child.pid) {
      record('spawn-pid', { pid: child.pid, fn: name });
    }
    return child;
  }, { __jestAudit: true });
}

// ---- file system ----
const pathOf = (p) => (typeof p === 'string' ? p : p && p.href ? decodeURIComponent(p.pathname) : Buffer.isBuffer(p) ? p.toString() : typeof p === 'number' ? `fd:${p}` : '');
const fsOps = { read: ['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync', 'opendir', 'opendirSync'], write: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'copyFile', 'copyFileSync', 'rename', 'renameSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'chmod', 'chmodSync'], open: ['open', 'openSync'] };
for (const [op, names] of Object.entries(fsOps)) {
  for (const name of names) {
    wrap(fs, name, (args) => record('fs', { op: op === 'open' ? (/[wa+]/.test(str(args[1])) ? 'write' : 'read') : op, fn: name, path: pathOf(args[0]) }));
    if (!name.endsWith('Sync') && !name.startsWith('create')) {
      wrap(fs.promises, name, (args) => record('fs', { op: op === 'open' ? (/[wa+]/.test(str(args[1])) ? 'write' : 'read') : op, fn: `promises.${name}`, path: pathOf(args[0]) }));
    }
  }
}

// ---- network ----
const net = require('net');
const http = require('http');
const https = require('https');
const dns = require('dns');
const dgram = require('dgram');
const refused = (host) => Object.assign(new Error(`getaddrinfo ENOTFOUND ${host} (jest-security --offline)`), { code: 'ENOTFOUND', hostname: host });
const local = (h) => /^(localhost|127\.|::1$)/.test(String(h));
wrap(net.Socket.prototype, 'connect', function (args) {
  const o = typeof args[0] === 'object' && args[0] !== null ? args[0] : { port: args[0], host: args[1] };
  if (o.path) {
    return undefined; // local IPC pipe
  }
  record('connect', { host: str(o.host || 'localhost'), port: Number(o.port) || 0, tls: !!this.encrypted || !!o.servername });
  if (OFFLINE && !local(o.host || 'localhost')) {
    const blocked = { ...o, host: '127.0.0.1', port: 9 };
    return { args: [blocked, ...args.slice(typeof args[0] === 'object' ? 1 : 2).filter((a) => typeof a === 'function')] };
  }
  return undefined;
});
for (const [mod, scheme] of [[http, 'http'], [https, 'https']]) {
  for (const name of ['request', 'get']) {
    const orig = mod[name];
    mod[name] = function (...args) {
      const u = typeof args[0] === 'string' || args[0] instanceof URL ? new URL(String(args[0])) : null;
      const o = args.find((a) => a && typeof a === 'object' && !(a instanceof URL)) || {};
      const info = { scheme, method: str(o.method || 'GET'), host: str(u ? u.hostname : o.hostname || o.host), port: Number(u ? u.port : o.port) || (scheme === 'https' ? 443 : 80), path: str(u ? u.pathname + u.search : o.path, 200) };
      const req = orig.apply(this, args);
      let bytes = 0;
      let sample = '';
      for (const m of ['write', 'end']) {
        const w = req[m];
        req[m] = function (chunk, ...rest) {
          if (chunk && typeof chunk !== 'function') {
            bytes += Buffer.byteLength(chunk);
            sample = (sample + str(Buffer.isBuffer(chunk) ? chunk.toString() : chunk, 2000)).slice(0, 2000);
          }
          if (m === 'end') {
            record('http', { ...info, bytes, sample });
          }
          return w.call(this, chunk, ...rest);
        };
      }
      return req;
    };
  }
}
if (typeof globalThis.fetch === 'function') {
  const f = globalThis.fetch;
  globalThis.fetch = function (input, init = {}) {
    const url = new URL(String(input && input.url ? input.url : input));
    const body = typeof init.body === 'string' ? init.body : init.body ? '[binary]' : '';
    record('http', { scheme: url.protocol.replace(':', ''), method: str(init.method || 'GET'), host: url.hostname, port: Number(url.port) || 0, path: str(url.pathname + url.search, 200), bytes: Buffer.byteLength(body), sample: body.slice(0, 2000), via: 'fetch' });
    return f.apply(this, arguments);
  };
}
for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveAny']) {
  wrap(dns, name, (args) => {
    record('dns', { fn: name, host: str(args[0]) });
    const cb = args.find((a) => typeof a === 'function');
    return OFFLINE && !local(args[0]) && cb ? { replaced: true, value: process.nextTick(cb, refused(args[0])) } : undefined;
  });
  wrap(dns.promises, name, (args) => {
    record('dns', { fn: `promises.${name}`, host: str(args[0]) });
    return OFFLINE && !local(args[0]) ? { replaced: true, value: Promise.reject(refused(args[0])) } : undefined;
  });
}
wrap(dgram, 'createSocket', (args) => record('udp', { type: str(typeof args[0] === 'object' ? args[0].type : args[0]) }));
wrap(dgram.Socket.prototype, 'send', function (args) {
  const port = args.find((a, i) => i > 0 && typeof a === 'number' && a > 0 && a < 65536 && args[i + 1] !== undefined);
  const host = args.find((a, i) => i > 1 && typeof a === 'string');
  record('udp-send', { host: str(host), port: port || 0 });
  return OFFLINE ? { replaced: true, value: undefined } : undefined;
});

// ---- dynamic code ----
const vm = require('vm');
for (const name of ['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction']) {
  wrap(vm, name, (args) => record('eval', { fn: `vm.${name}`, code: str(args[0], 500) }));
}
vm.Script = new Proxy(vm.Script, { construct: (T, args) => (record('eval', { fn: 'vm.Script', code: str(args[0], 500) }), new T(...args)) });
const realEval = globalThis.eval;
globalThis.eval = function (code) {
  record('eval', { fn: 'eval', code: str(code, 500) });
  return realEval(code);
};
globalThis.Function = new Proxy(Function, {
  apply: (T, self, args) => (record('eval', { fn: 'Function', code: str(args[args.length - 1], 500) }), Reflect.apply(T, self, args)),
  construct: (T, args) => (record('eval', { fn: 'Function', code: str(args[args.length - 1], 500) }), Reflect.construct(T, args)),
});

// ---- vscode API (real Extension Host): overlay the clipboard ----
function wrapVscode(api) {
  if (!api || !api.env || api.__jestAudit) {
    return api;
  }
  const clipboard = Object.create(api.env.clipboard, {
    readText: { value: (...a) => (record('clipboard', {}, true), api.env.clipboard.readText(...a)) },
  });
  const env = Object.create(api.env, { clipboard: { value: clipboard } });
  return Object.create(api, { env: { value: env }, __jestAudit: { value: true } });
}
const load = Module._load;
Module._load = function (request, ...rest) {
  const m = load.call(this, request, ...rest);
  return request === 'vscode' ? wrapVscode(m) : m;
};

globalThis.__jestAudit = { record, wrapVscode };
record('start', { pid: process.pid, ext: EXT, allowExec: ALLOW_EXEC, offline: OFFLINE }, true);
