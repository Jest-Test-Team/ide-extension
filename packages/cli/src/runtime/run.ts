import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { assetDir } from '../lib/assets';

/** Marker planted in every decoy secret; finding it in an outbound request proves exfiltration. */
export const HONEY = 'DECOY-JEST-AUDIT';

export interface RuntimeEvent {
  t: number;
  kind: string;
  at?: string;
  [key: string]: unknown;
}

export interface RunOptions {
  /** Seconds the extension runs after activation. */
  duration: number;
  invokeCommands?: boolean;
  allowExec?: boolean;
  offline?: boolean;
  /** Extra time allowed for loading and activation before the run is killed. */
  graceSeconds?: number;
}

export interface Sandbox {
  root: string;
  home: string;
  workspace: string;
  ext: string;
  log: string;
}

export interface RunResult {
  sandbox: Sandbox;
  events: RuntimeEvent[];
  exitCode: number | null;
  timedOut: boolean;
  stderr: string;
}

/** Decoy secrets in the fake home folder, relative paths → content. */
export const DECOY_HOME: Record<string, string> = {
  '.ssh/id_rsa': `-----BEGIN OPENSSH PRIVATE KEY-----\n${HONEY}_SSH_KEY\n-----END OPENSSH PRIVATE KEY-----\n`,
  '.ssh/config': `Host prod\n  HostName 10.0.0.1\n  User ${HONEY}\n`,
  '.aws/credentials': `[default]\naws_access_key_id = AKIA${HONEY.replace(/-/g, '')}\naws_secret_access_key = ${HONEY}_AWS\n`,
  '.gitconfig': `[user]\n  name = decoy\n[credential]\n  helper = store\n`,
  '.git-credentials': `https://decoy:${HONEY}_GIT@github.com\n`,
  '.npmrc': `//registry.npmjs.org/:_authToken=${HONEY}_NPM\n`,
  '.gnupg/private-keys-v1.d/decoy.key': `${HONEY}_GPG\n`,
  '.kube/config': `users:\n- name: decoy\n  user:\n    token: ${HONEY}_KUBE\n`,
  '.docker/config.json': `{"auths":{"registry.example":{"auth":"${HONEY}_DOCKER"}}}\n`,
  '.config/gh/hosts.yml': `github.com:\n  oauth_token: ${HONEY}_GH\n`,
  '.bash_history': `export GITHUB_TOKEN=${HONEY}_HISTORY\n`,
  '.zshrc': '# decoy shell profile\n',
};

/** Decoy secrets in the fake workspace. */
export const DECOY_WORKSPACE: Record<string, string> = {
  'app.js': `const token = "ghp_${HONEY}_SOURCE";\n`,
  '.env': `API_KEY=${HONEY}_ENV\n`,
  'config/credentials.json': `{"client_secret":"${HONEY}_CREDENTIALS"}\n`,
  'certs/server.pem': `-----BEGIN PRIVATE KEY-----\n${HONEY}_PEM\n-----END PRIVATE KEY-----\n`,
  'deploy/secrets.yaml': `password: ${HONEY}_YAML\n`,
};

function plant(root: string, files: Record<string, string>): void {
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body, { mode: 0o600 });
  }
}

/** A throw-away folder with a decoy home, a decoy workspace and a copy of the extension. */
export function createSandbox(extDir: string): Sandbox {
  // Real path: on macOS the temp folder is reached through a /var → /private/var link.
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'jest-audit-')));
  const sb: Sandbox = { root, home: join(root, 'home'), workspace: join(root, 'workspace'), ext: join(root, 'extension'), log: join(root, 'events.jsonl') };
  plant(sb.home, DECOY_HOME);
  plant(sb.workspace, DECOY_WORKSPACE);
  cpSync(extDir, sb.ext, { recursive: true, dereference: false, verbatimSymlinks: true });
  writeFileSync(sb.log, '');
  return sb;
}

/** Environment for the audited process: home folders point into the sandbox. */
export function sandboxEnv(sb: Sandbox, opts: RunOptions): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: sb.home,
    USERPROFILE: sb.home,
    APPDATA: join(sb.home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(sb.home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: join(sb.home, '.config'),
    XDG_CACHE_HOME: join(sb.home, '.cache'),
    XDG_DATA_HOME: join(sb.home, '.local', 'share'),
    JEST_AUDIT_LOG: sb.log,
    JEST_AUDIT_EXT: sb.ext,
    JEST_AUDIT_ALLOW_EXEC: opts.allowExec ? '1' : '0',
    JEST_AUDIT_OFFLINE: opts.offline ? '1' : '0',
    NODE_OPTIONS: '',
  };
}

export function readEvents(log: string): RuntimeEvent[] {
  if (!existsSync(log)) {
    return [];
  }
  return readFileSync(log, 'utf8')
    .split('\n')
    .filter(Boolean)
    .flatMap((l) => {
      try {
        return [JSON.parse(l) as RuntimeEvent];
      } catch {
        return [];
      }
    });
}

/**
 * Runs the extension headless: a child Node process loads the audit agent, then the harness, which
 * activates the extension against the recording `vscode` mock. THIS EXECUTES THE EXTENSION'S CODE.
 */
export function runHarness(extDir: string, opts: RunOptions, sb = createSandbox(extDir)): Promise<RunResult> {
  const dir = assetDir('runtime');
  const args = ['--require', join(dir, 'audit-agent.cjs'), join(dir, 'harness.cjs'), sb.ext, sb.workspace, String(opts.duration), ...(opts.invokeCommands ? ['--invoke-commands'] : [])];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: sb.workspace, env: sandboxEnv(sb, opts), stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    let timedOut = false;
    child.stderr.on('data', (b: Buffer) => (stderr = (stderr + b.toString()).slice(-4000)));
    const timer = setTimeout(
      () => {
        timedOut = true;
        child.kill('SIGKILL');
      },
      (opts.duration + (opts.graceSeconds ?? 30)) * 1000,
    );
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ sandbox: sb, events: readEvents(sb.log), exitCode: code, timedOut, stderr });
    });
  });
}
