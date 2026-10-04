// Shared @vscode/test-cli configuration: one VS Code download in <repo>/.vscode-test for every extension.
import { defineConfig } from '@vscode/test-cli';
import { downloadAndUnzipVSCode } from '@vscode/test-electron';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

export async function extensionTestConfig(name) {
  const fromPath = await downloadAndUnzipVSCode({ cachePath: join(repoRoot, '.vscode-test') });
  return defineConfig({
    files: 'out/test/integration/**/*.test.js',
    workspaceFolder: './test/fixtures',
    useInstallation: { fromPath },
    // The default user-data-dir inside the repo yields an IPC socket path longer than macOS allows.
    launchArgs: ['--user-data-dir', join(tmpdir(), `vsct-${name}`), '--disable-extensions'],
    mocha: { timeout: 60000 },
  });
}
