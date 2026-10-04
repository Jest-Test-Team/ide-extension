import * as vscode from 'vscode';
import { parseProfile, type Profile } from './profile';

/** Holds the most recent profile for the workspace and persists it in workspace storage. */
export class ProfileStore implements vscode.Disposable {
  private current: Profile | undefined;
  private readonly emitter = new vscode.EventEmitter<Profile | undefined>();
  readonly onDidChange = this.emitter.event;

  constructor(private readonly context: vscode.ExtensionContext) {}

  get profile(): Profile | undefined {
    return this.current;
  }

  private get file(): vscode.Uri | undefined {
    const base = this.context.storageUri ?? this.context.globalStorageUri;
    return vscode.Uri.joinPath(base, 'last-profile.json');
  }

  async restore(): Promise<void> {
    const file = this.file;
    if (!file) {
      return;
    }
    try {
      this.set(parseProfile(new TextDecoder().decode(await vscode.workspace.fs.readFile(file))), false);
    } catch {
      // nothing stored yet
    }
  }

  async load(uri: vscode.Uri): Promise<Profile> {
    const text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
    const profile = parseProfile(text);
    this.set(profile);
    return profile;
  }

  set(profile: Profile | undefined, persist = true): void {
    this.current = profile;
    this.emitter.fire(profile);
    const file = this.file;
    if (persist && file && profile) {
      void vscode.workspace.fs
        .createDirectory(vscode.Uri.joinPath(file, '..'))
        .then(() => vscode.workspace.fs.writeFile(file, new TextEncoder().encode(JSON.stringify(profile))));
    }
  }

  dispose(): void {
    this.emitter.dispose();
  }
}
