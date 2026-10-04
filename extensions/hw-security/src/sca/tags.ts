import { TagIndex, type TagOccurrence } from '@ide-ext/core';
import { toRange } from '@ide-ext/core/vscode';
import * as vscode from 'vscode';

export const DEF_TAG = 'sca';
export const REF_TAG = 'sca-ref';
const GLOB = '**/*.{c,h,cc,cpp,hpp,ino,S,s,py,ipynb}';
const EXCLUDE = '**/{node_modules,build,managed_components,.pio,.venv,venv,__pycache__}/**';

export interface ScaPoint {
  id: string;
  defs: TagOccurrence[];
  refs: TagOccurrence[];
}

/** Workspace-wide index of @sca definitions (firmware) and @sca-ref references (analysis scripts). */
export class ScaIndex implements vscode.Disposable {
  readonly index = new TagIndex([DEF_TAG, REF_TAG]);
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.emitter.event;
  private readonly disposables: vscode.Disposable[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    const watcher = vscode.workspace.createFileSystemWatcher(GLOB);
    const reread = async (uri: vscode.Uri) => {
      try {
        this.updateText(uri, new TextDecoder().decode(await vscode.workspace.fs.readFile(uri)));
      } catch {
        this.remove(uri);
      }
    };
    this.disposables.push(
      watcher,
      this.emitter,
      watcher.onDidCreate(reread),
      watcher.onDidChange((u) => {
        if (!vscode.workspace.textDocuments.some((d) => d.uri.toString() === u.toString() && d.isDirty)) {
          void reread(u);
        }
      }),
      watcher.onDidDelete((u) => this.remove(u)),
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (vscode.languages.match([{ pattern: GLOB }], e.document)) {
          this.updateText(e.document.uri, e.document.getText());
        }
      }),
    );
  }

  async scan(): Promise<void> {
    const files = await vscode.workspace.findFiles(GLOB, EXCLUDE, 5000);
    await Promise.all(
      files.map(async (uri) => {
        const text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
        this.index.update(uri.toString(), text);
      }),
    );
    this.fire();
  }

  private updateText(uri: vscode.Uri, text: string): void {
    const before = JSON.stringify(this.index.inDocument(uri.toString()).map((t) => [t.tag, t.id, t.line]));
    const after = this.index.update(uri.toString(), text);
    if (before !== JSON.stringify(after.map((t) => [t.tag, t.id, t.line]))) {
      this.fire();
    }
  }

  private remove(uri: vscode.Uri): void {
    this.index.remove(uri.toString());
    this.fire();
  }

  private fire(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.emitter.fire(), 50);
  }

  points(): ScaPoint[] {
    const map = new Map<string, ScaPoint>();
    for (const t of this.index.all()) {
      const p = map.get(t.id) ?? { id: t.id, defs: [], refs: [] };
      (t.tag === DEF_TAG ? p.defs : p.refs).push(t);
      map.set(t.id, p);
    }
    return [...map.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  dispose(): void {
    clearTimeout(this.timer);
    this.disposables.forEach((d) => d.dispose());
  }
}

export const location = (t: TagOccurrence) => new vscode.Location(vscode.Uri.parse(t.uri), toRange(t.range));

/** Go to definition / references in both directions between @sca and @sca-ref. */
export class ScaNavigation implements vscode.DefinitionProvider, vscode.ReferenceProvider {
  constructor(private readonly sca: ScaIndex) {}

  private tagAt(doc: vscode.TextDocument, pos: vscode.Position): TagOccurrence | undefined {
    return this.sca.index.at(doc.uri.toString(), pos.line, pos.character);
  }

  provideDefinition(doc: vscode.TextDocument, pos: vscode.Position): vscode.Location[] | undefined {
    const tag = this.tagAt(doc, pos);
    if (!tag) {
      return undefined;
    }
    // From a reference jump to the firmware tag; from the firmware tag jump to the analysis scripts.
    return this.sca.index.find(tag.id, tag.tag === REF_TAG ? DEF_TAG : REF_TAG).map(location);
  }

  provideReferences(doc: vscode.TextDocument, pos: vscode.Position, ctx: vscode.ReferenceContext): vscode.Location[] | undefined {
    const tag = this.tagAt(doc, pos);
    if (!tag) {
      return undefined;
    }
    return this.sca.index
      .find(tag.id)
      .filter((t) => ctx.includeDeclaration || t.tag === REF_TAG)
      .map(location);
  }
}

export class ScaCodeLens implements vscode.CodeLensProvider {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.emitter.event;

  constructor(private readonly sca: ScaIndex) {
    sca.onDidChange(() => this.emitter.fire());
  }

  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    return this.sca.index.inDocument(doc.uri.toString()).map((t) => {
      const others = this.sca.index.find(t.id, t.tag === DEF_TAG ? REF_TAG : DEF_TAG);
      const range = toRange(t.range);
      if (!others.length) {
        return new vscode.CodeLens(range, {
          title: t.tag === DEF_TAG ? '$(warning) No analysis script references this point' : '$(warning) No @sca tag with this id',
          command: '',
        });
      }
      const title = t.tag === DEF_TAG ? `$(graph) Open analysis script${others.length > 1 ? `s (${others.length})` : ''}` : '$(go-to-file) Open target code';
      return new vscode.CodeLens(range, {
        title,
        command: 'editor.action.goToLocations',
        arguments: [vscode.Uri.parse(t.uri), range.start, others.map(location), 'goto', 'No matching tag'],
      });
    });
  }
}

/** Completion of known ids inside `@sca-ref(` / `@sca(`. */
export class ScaCompletion implements vscode.CompletionItemProvider {
  constructor(private readonly sca: ScaIndex) {}

  provideCompletionItems(doc: vscode.TextDocument, pos: vscode.Position): vscode.CompletionItem[] | undefined {
    const before = doc.lineAt(pos.line).text.slice(0, pos.character);
    if (!/@sca(-ref)?\(\s*[\w.:-]*$/.test(before)) {
      return undefined;
    }
    return this.sca.points().map((p) => {
      const item = new vscode.CompletionItem(p.id, vscode.CompletionItemKind.Reference);
      const d = p.defs[0];
      item.detail = d?.description ?? (d ? 'side-channel point' : 'referenced only');
      item.documentation = d ? `${vscode.workspace.asRelativePath(vscode.Uri.parse(d.uri))}:${d.line + 1}` : undefined;
      return item;
    });
  }
}

/** Duplicate @sca ids and @sca-ref without a matching @sca. */
export function tagDiagnostics(sca: ScaIndex, collection: vscode.DiagnosticCollection): void {
  collection.clear();
  const byUri = new Map<string, vscode.Diagnostic[]>();
  const add = (t: TagOccurrence, message: string, severity: vscode.DiagnosticSeverity) => {
    const d = new vscode.Diagnostic(toRange(t.range), message, severity);
    d.source = 'HW Security';
    d.code = t.tag === DEF_TAG ? 'sca/duplicate-id' : 'sca/orphan-ref';
    byUri.set(t.uri, [...(byUri.get(t.uri) ?? []), d]);
  };
  for (const p of sca.points()) {
    if (p.defs.length > 1) {
      p.defs.forEach((t) => add(t, `Side-channel id "${p.id}" is defined ${p.defs.length} times; ids must be unique.`, vscode.DiagnosticSeverity.Warning));
    }
    if (!p.defs.length) {
      p.refs.forEach((t) => add(t, `No @sca(${p.id}, …) tag exists in the firmware sources.`, vscode.DiagnosticSeverity.Warning));
    }
  }
  byUri.forEach((d, uri) => collection.set(vscode.Uri.parse(uri), d));
}
