import { runProcess } from '@ide-ext/core/vscode';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import * as vscode from 'vscode';
import { resolveJulia } from './julia';
import { findProject, WORKLOAD_TEMPLATE, type JuliaProject } from './project';
import { parseProfile, summarize, type Profile } from './profile';
import type { ProfileStore } from './store';

/** Picks the Julia project: the one containing the active file, else the first workspace folder's. */
export function currentProject(): JuliaProject | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  const folder = (active && vscode.workspace.getWorkspaceFolder(active)) ?? vscode.workspace.workspaceFolders?.[0];
  if (active?.scheme === 'file') {
    const p = findProject(active.fsPath, folder?.uri.fsPath);
    if (p) {
      return p;
    }
  }
  return folder ? findProject(folder.uri.fsPath, folder.uri.fsPath) : undefined;
}

async function pickWorkload(project: JuliaProject): Promise<string | null | undefined> {
  const configured = vscode.workspace.getConfiguration('juliaProfiler').get<string>('workloadScript')?.trim();
  if (configured) {
    return join(project.dir, configured);
  }
  const conventional = vscode.Uri.file(join(project.dir, 'snoop', 'workload.jl'));
  try {
    await vscode.workspace.fs.stat(conventional);
    return conventional.fsPath;
  } catch {
    // fall through to asking
  }
  const choice = await vscode.window.showQuickPick(
    [
      { label: '$(debug-step-over) Invalidations only', id: 'none', description: 'record loading the package, skip inference' },
      { label: '$(file-code) Choose workload script…', id: 'pick' },
      { label: '$(new-file) Create snoop/workload.jl', id: 'create', description: 'then edit it and run again' },
    ],
    { title: 'Inference workload', placeHolder: 'No workload script found (set juliaProfiler.workloadScript or create snoop/workload.jl)' },
  );
  if (!choice) {
    return undefined;
  }
  if (choice.id === 'none') {
    return null;
  }
  if (choice.id === 'create') {
    await createWorkload(project);
    return undefined;
  }
  const picked = await vscode.window.showOpenDialog({
    defaultUri: vscode.Uri.file(project.dir),
    filters: { Julia: ['jl'] },
    canSelectMany: false,
  });
  return picked?.[0]?.fsPath;
}

export async function createWorkload(project = currentProject()): Promise<void> {
  if (!project) {
    void vscode.window.showWarningMessage('No Julia project (Project.toml) found in the workspace.');
    return;
  }
  const uri = vscode.Uri.file(join(project.dir, 'snoop', 'workload.jl'));
  try {
    await vscode.workspace.fs.stat(uri);
  } catch {
    await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(WORKLOAD_TEMPLATE(project.name)));
  }
  await vscode.window.showTextDocument(uri);
}

export async function analyze(context: vscode.ExtensionContext, store: ProfileStore, output: vscode.OutputChannel): Promise<Profile | undefined> {
  const julia = resolveJulia();
  if (!julia) {
    const action = await vscode.window.showErrorMessage(
      'Julia executable not found. Set "juliaProfiler.executablePath" or add julia to PATH.',
      'Open Settings',
    );
    if (action) {
      void vscode.commands.executeCommand('workbench.action.openSettings', 'juliaProfiler.executablePath');
    }
    return undefined;
  }
  const project = currentProject();
  if (!project) {
    void vscode.window.showWarningMessage('No Julia project (Project.toml) found in the workspace.');
    return undefined;
  }
  const workload = await pickWorkload(project);
  if (workload === undefined) {
    return undefined;
  }
  const storage = context.globalStorageUri.fsPath;
  const toolEnv = join(storage, 'snoop-env');
  mkdirSync(toolEnv, { recursive: true });
  const out = join(storage, `profile-${Date.now()}.json`);
  const script = join(context.extensionPath, 'dist', 'scripts', 'collect.jl');
  const timeoutMin = vscode.workspace.getConfiguration('juliaProfiler').get<number>('timeoutMinutes', 30);

  output.show(true);
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Profiling ${project.name || project.dir} with SnoopCompile`,
      cancellable: true,
    },
    async (_progress, token) => {
      const res = await runProcess(
        julia,
        ['--startup-file=no', `--project=${project.dir}`, script, out, toolEnv, project.name, workload ?? ''],
        { cwd: project.dir, token, timeoutMs: timeoutMin * 60_000, output },
      );
      if (res.cancelled) {
        return undefined;
      }
      if (res.code !== 0) {
        void vscode.window.showErrorMessage(
          res.timedOut ? `Profiling timed out after ${timeoutMin} min.` : `Julia exited with code ${res.code}; see the output channel.`,
        );
        return undefined;
      }
      const profile = parseProfile(new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.file(out))));
      store.set(profile);
      const s = summarize(profile);
      void vscode.window
        .showInformationMessage(
          `${s.trees} invalidation tree(s), ${s.invalidated} MethodInstances invalidated` +
            (s.inferenceTime !== undefined ? `, ${s.inferenceTime.toFixed(2)} s in inference.` : '.'),
          'Show Invalidations',
          'Show Flame Graph',
        )
        .then((pick) => {
          if (pick === 'Show Invalidations') {
            void vscode.commands.executeCommand('juliaProfiler.showInvalidations');
          } else if (pick === 'Show Flame Graph') {
            void vscode.commands.executeCommand('juliaProfiler.showFlameGraph');
          }
        });
      return profile;
    },
  );
}
