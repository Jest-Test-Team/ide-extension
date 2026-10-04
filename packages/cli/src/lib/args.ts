/** Minimal argv parsing and help generation for the jest-* command-line tools (no dependencies). */

export interface FlagSpec {
  type: 'string' | 'boolean' | 'number';
  description: string;
  alias?: string;
  /** Repeatable (`--rule-pack a --rule-pack b`); values also split on commas. */
  multiple?: boolean;
  default?: string | number | boolean | string[];
  /** Placeholder in help text, e.g. `<file>`. */
  value?: string;
}

export type Flags = Record<string, string | number | boolean | string[] | undefined>;

export interface ParsedArgs {
  positionals: string[];
  flags: Flags;
}

export class UsageError extends Error {}

export function parseArgs(argv: readonly string[], specs: Record<string, FlagSpec>): ParsedArgs {
  const flags: Flags = {};
  const positionals: string[] = [];
  const byAlias = new Map(Object.entries(specs).filter(([, s]) => s.alias).map(([k, s]) => [s.alias!, k]));
  for (const [k, s] of Object.entries(specs)) {
    if (s.default !== undefined) {
      flags[k] = Array.isArray(s.default) ? [...s.default] : s.default;
    }
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (!a.startsWith('-') || a === '-') {
      positionals.push(a);
      continue;
    }
    let name: string;
    let inline: string | undefined;
    if (a.startsWith('--')) {
      [name, inline] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined];
    } else {
      name = byAlias.get(a.slice(1)) ?? a.slice(1);
    }
    let negate = false;
    if (!specs[name] && name.startsWith('no-') && specs[name.slice(3)]?.type === 'boolean') {
      name = name.slice(3);
      negate = true;
    }
    const spec = specs[name];
    if (!spec) {
      throw new UsageError(`unknown option ${a}`);
    }
    if (spec.type === 'boolean') {
      flags[name] = negate ? false : inline === undefined ? true : !/^(false|0|no)$/i.test(inline);
      continue;
    }
    const raw = inline ?? argv[++i];
    if (raw === undefined) {
      throw new UsageError(`option --${name} needs a value`);
    }
    if (spec.type === 'number') {
      const n = Number(raw);
      if (!Number.isFinite(n)) {
        throw new UsageError(`option --${name} expects a number, got "${raw}"`);
      }
      flags[name] = n;
    } else if (spec.multiple) {
      const prev = flags[name] === spec.default ? [] : ((flags[name] as string[] | undefined) ?? []);
      flags[name] = [...prev, ...raw.split(',').filter(Boolean)];
    } else {
      flags[name] = raw;
    }
  }
  return { positionals, flags };
}

export interface Io {
  out(text: string): void;
  err(text: string): void;
  /** Whether ANSI colours may be used on stdout. */
  color: boolean;
  cwd: string;
}

export const processIo = (): Io => ({
  out: (t) => process.stdout.write(t),
  err: (t) => process.stderr.write(t),
  color: !!process.stdout.isTTY && !process.env.NO_COLOR,
  cwd: process.cwd(),
});

export interface Command {
  name: string;
  summary: string;
  /** Positional arguments for help, e.g. `[paths…]`. */
  args?: string;
  flags?: Record<string, FlagSpec>;
  examples?: string[];
  run(args: ParsedArgs, io: Io): Promise<number>;
}

export interface Tool {
  name: string;
  version: string;
  summary: string;
  commands: Command[];
  /** Extra help paragraph. */
  footer?: string;
}

function flagHelp(specs: Record<string, FlagSpec>): string {
  const rows = Object.entries(specs).map(([k, s]) => {
    const left = `${s.alias ? `-${s.alias}, ` : '    '}--${k}${s.type === 'boolean' ? '' : ` ${s.value ?? `<${s.type}>`}`}`;
    const def = s.default !== undefined && s.type !== 'boolean' ? ` (default: ${Array.isArray(s.default) ? s.default.join(',') || 'none' : s.default})` : '';
    return [left, `${s.description}${s.multiple ? ' (repeatable)' : ''}${def}`];
  });
  const w = Math.max(0, ...rows.map((r) => r[0].length));
  return rows.map(([l, r]) => `  ${l.padEnd(w)}  ${r}`).join('\n');
}

export function commandHelp(tool: Tool, c: Command): string {
  return [
    `Usage: ${tool.name} ${c.name}${c.args ? ` ${c.args}` : ''} [options]`,
    '',
    c.summary,
    '',
    'Options:',
    flagHelp({ ...(c.flags ?? {}), help: { type: 'boolean', alias: 'h', description: 'Show this help' } }),
    ...(c.examples?.length ? ['', 'Examples:', ...c.examples.map((e) => `  ${e}`)] : []),
    '',
  ].join('\n');
}

export function toolHelp(tool: Tool): string {
  const w = Math.max(...tool.commands.map((c) => c.name.length));
  return [
    `${tool.name} ${tool.version} — ${tool.summary}`,
    '',
    `Usage: ${tool.name} <command> [options]`,
    '',
    'Commands:',
    ...tool.commands.map((c) => `  ${c.name.padEnd(w)}  ${c.summary}`),
    '',
    `Run "${tool.name} <command> --help" for command options.`,
    ...(tool.footer ? ['', tool.footer] : []),
    '',
  ].join('\n');
}

/** Dispatches argv to a command. Exit codes: 0 ok, 1 findings/failed check, 2 usage or runtime error. */
export async function runTool(tool: Tool, argv: readonly string[], io: Io = processIo()): Promise<number> {
  const [first, ...rest] = argv;
  if (!first || first === '--help' || first === '-h' || first === 'help') {
    const target = first === 'help' ? tool.commands.find((c) => c.name === rest[0]) : undefined;
    io.out(target ? commandHelp(tool, target) : toolHelp(tool));
    return first ? 0 : 2;
  }
  if (first === '--version' || first === '-v' || first === 'version') {
    io.out(`${tool.version}\n`);
    return 0;
  }
  const cmd = tool.commands.find((c) => c.name === first);
  if (!cmd) {
    io.err(`${tool.name}: unknown command "${first}"\n\n${toolHelp(tool)}`);
    return 2;
  }
  if (rest.includes('--help') || rest.includes('-h')) {
    io.out(commandHelp(tool, cmd));
    return 0;
  }
  try {
    return await cmd.run(parseArgs(rest, cmd.flags ?? {}), io);
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(`${tool.name} ${cmd.name}: ${err.message}\n\n${commandHelp(tool, cmd)}`);
    } else {
      io.err(`${tool.name} ${cmd.name}: ${(err as Error).message}\n`);
    }
    return 2;
  }
}

declare const __CLI_VERSION__: string | undefined;
/** Package version injected at build time (`dev` when running from source). */
export const VERSION = typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : 'dev';
