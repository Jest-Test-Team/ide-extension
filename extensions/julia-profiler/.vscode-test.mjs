import { defineConfig } from '@vscode/test-cli';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  workspaceFolder: './test/fixtures',
  // The default user-data-dir inside the repo yields an IPC socket path longer than macOS allows.
  launchArgs: ['--user-data-dir', join(tmpdir(), 'vsct-julia-profiler'), '--disable-extensions'],
  mocha: { timeout: 60000 },
});
