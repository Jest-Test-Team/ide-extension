import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export interface JuliaProject {
  /** Directory containing Project.toml. */
  dir: string;
  /** Package name from Project.toml, empty for plain environments. */
  name: string;
}

/** Nearest Project.toml at or above `start` (a file or directory), stopping at `stop`. */
export function findProject(start: string, stop?: string): JuliaProject | undefined {
  let dir = existsSync(join(start, 'Project.toml')) ? start : dirname(start);
  for (;;) {
    const file = join(dir, 'Project.toml');
    if (existsSync(file)) {
      return { dir, name: projectName(readFileSync(file, 'utf8')) };
    }
    if (dir === stop || dirname(dir) === dir) {
      return undefined;
    }
    dir = dirname(dir);
  }
}

export function projectName(toml: string): string {
  // `name` must appear before the first [table] header to be the package name.
  const head = toml.split(/^\s*\[/m)[0];
  return /^\s*name\s*=\s*"([^"]+)"/m.exec(head)?.[1] ?? '';
}

export const WORKLOAD_TEMPLATE = (pkg: string) => `# Workload for the Julia Invalidation & Compiler Profiler.
# Exercise the code paths whose compile latency you care about; the profiler records type
# inference while this file runs (SnoopCompile \`@snoop_inference\`).
${pkg ? `using ${pkg}\n` : ''}
# Example:
# x = rand(1000)
# ${pkg || 'MyPackage'}.process(x)
`;
