import * as vscode from 'vscode';
import { languageIdForPath, lineCommentFor } from '../languages';
import type { RuleEngine } from '../rules/engine';
import type { Finding } from '../rules/schema';
import { ruleMarkdown, toDiagnostic, toRange, type FindingDiagnostic } from './convert';

export interface DiagnosticsOptions {
  /** Diagnostic collection name and `source` label. */
  name: string;
  engine: RuleEngine;
  /** Extra filter on top of "the engine has rules for this language". */
  include?: (doc: vscode.TextDocument) => boolean;
  /** Additional findings from non-rule sources (e.g. runtime profiling data). */
  extraFindings?: (doc: vscode.TextDocument) => Finding[] | Promise<Finding[]>;
  /** Setting (`section.key`) toggling lint-as-you-type; when false, documents lint on open/save only. */
  onTypeSetting?: string;
  debounceMs?: number;
}

/**
 * Runs a RuleEngine over open documents, publishes diagnostics, and provides quick fixes
 * (rule fixes plus "suppress on this line") and hovers with rule sources.
 */
export class DiagnosticsController implements vscode.Disposable {
  readonly collection: vscode.DiagnosticCollection;
  private readonly disposables: vscode.Disposable[] = [];
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly results = new Map<string, Finding[]>();
  private readonly changed = new vscode.EventEmitter<vscode.Uri>();
  readonly onDidChangeFindings = this.changed.event;

  constructor(private readonly opts: DiagnosticsOptions) {
    this.collection = vscode.languages.createDiagnosticCollection(opts.name);
    this.disposables.push(
      this.collection,
      this.changed,
      vscode.workspace.onDidOpenTextDocument((d) => this.schedule(d, 0)),
      vscode.workspace.onDidSaveTextDocument((d) => this.schedule(d, 0)),
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (this.lintOnType()) {
          this.schedule(e.document, opts.debounceMs ?? 300);
        }
      }),
      vscode.workspace.onDidCloseTextDocument((d) => {
        // Keep findings from workspace scans for files on disk; drop diagnostics for untitled buffers.
        if (d.uri.scheme === 'untitled') {
          this.clear(d.uri);
        }
      }),
      vscode.languages.registerCodeActionsProvider({ scheme: '*' }, new FixProvider(opts.name), {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      }),
      vscode.languages.registerHoverProvider({ scheme: '*' }, new RuleHoverProvider(this)),
    );
    vscode.workspace.textDocuments.forEach((d) => this.schedule(d, 0));
  }

  private lintOnType(): boolean {
    if (!this.opts.onTypeSetting) {
      return true;
    }
    const [section, ...rest] = this.opts.onTypeSetting.split('.');
    return vscode.workspace.getConfiguration(section).get<boolean>(rest.join('.'), true);
  }

  shouldLint(doc: { languageId: string; uri: vscode.Uri }): boolean {
    if (!['file', 'untitled', 'vscode-notebook-cell'].includes(doc.uri.scheme)) {
      return false;
    }
    return this.opts.engine.appliesTo(doc.languageId) || doc.languageId === 'plaintext';
  }

  private schedule(doc: vscode.TextDocument, delay: number): void {
    if (!this.shouldLint(doc) || (this.opts.include && !this.opts.include(doc))) {
      return;
    }
    const key = doc.uri.toString();
    clearTimeout(this.timers.get(key));
    this.timers.set(
      key,
      setTimeout(() => {
        this.timers.delete(key);
        void this.lintDocument(doc);
      }, delay),
    );
  }

  async lintDocument(doc: vscode.TextDocument): Promise<Finding[]> {
    const version = doc.version;
    const findings = await this.opts.engine.run({
      uri: doc.uri.toString(),
      path: doc.uri.fsPath || doc.uri.path,
      languageId: doc.languageId,
      text: doc.getText(),
      version,
    });
    if (this.opts.extraFindings) {
      findings.push(...(await this.opts.extraFindings(doc)));
    }
    if (doc.version !== version) {
      return findings; // a newer edit is already scheduled
    }
    this.publish(doc.uri, findings);
    return findings;
  }

  /** Re-lints every open document (e.g. after rules or settings change). */
  refreshOpen(): void {
    vscode.workspace.textDocuments.forEach((d) => this.schedule(d, 0));
  }

  publish(uri: vscode.Uri, findings: Finding[]): void {
    this.results.set(uri.toString(), findings);
    this.collection.set(
      uri,
      findings.map((f) => toDiagnostic(f, this.opts.name)),
    );
    this.changed.fire(uri);
  }

  clear(uri: vscode.Uri): void {
    this.results.delete(uri.toString());
    this.collection.delete(uri);
    this.changed.fire(uri);
  }

  findings(uri: vscode.Uri): Finding[] {
    return this.results.get(uri.toString()) ?? [];
  }

  /** All findings keyed by URI string. */
  allFindings(): ReadonlyMap<string, Finding[]> {
    return this.results;
  }

  /**
   * Lints every matching workspace file from disk (without opening editors), with progress and
   * cancellation. Open documents use their in-memory text.
   */
  async scanWorkspace(include: vscode.GlobPattern, exclude?: vscode.GlobPattern | null): Promise<number> {
    return vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `${this.opts.name}: scanning workspace`, cancellable: true },
      async (progress, token) => {
        const files = await vscode.workspace.findFiles(include, exclude, undefined, token);
        const open = new Map(vscode.workspace.textDocuments.map((d) => [d.uri.toString(), d]));
        let total = 0;
        for (let i = 0; i < files.length && !token.isCancellationRequested; i++) {
          const uri = files[i];
          progress.report({ message: vscode.workspace.asRelativePath(uri), increment: 100 / files.length });
          const doc = open.get(uri.toString());
          if (doc) {
            total += (await this.lintDocument(doc)).length;
            continue;
          }
          const languageId = languageIdForPath(uri.fsPath);
          if (!this.opts.engine.appliesTo(languageId)) {
            continue;
          }
          const text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
          const findings = await this.opts.engine.run({ uri: uri.toString(), path: uri.fsPath, languageId, text });
          this.publish(uri, findings);
          total += findings.length;
        }
        return total;
      },
    );
  }

  ruleFor(diagnostic: vscode.Diagnostic) {
    const f = (diagnostic as FindingDiagnostic).finding;
    return f ? this.opts.engine.getRule(f.ruleId) : undefined;
  }

  dispose(): void {
    this.timers.forEach((t) => clearTimeout(t));
    this.disposables.forEach((d) => d.dispose());
  }
}

class FixProvider implements vscode.CodeActionProvider {
  constructor(private readonly source: string) {}

  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const d of ctx.diagnostics) {
      const f = (d as FindingDiagnostic).finding;
      if (!f || d.source !== this.source) {
        continue;
      }
      if (f.fix) {
        const a = new vscode.CodeAction(f.fix.title, vscode.CodeActionKind.QuickFix);
        a.edit = new vscode.WorkspaceEdit();
        a.edit.replace(doc.uri, toRange(f.fix.range), f.fix.newText);
        a.diagnostics = [d];
        a.isPreferred = true;
        actions.push(a);
      }
      const line = doc.lineAt(f.range.start.line);
      const indent = line.text.slice(0, line.firstNonWhitespaceCharacterIndex);
      const suppress = new vscode.CodeAction(`Suppress ${f.ruleId} on this line`, vscode.CodeActionKind.QuickFix);
      suppress.edit = new vscode.WorkspaceEdit();
      suppress.edit.insert(
        doc.uri,
        line.range.start,
        `${indent}${lineCommentFor(doc.languageId)} ide-ext-ignore-next-line ${f.ruleId}\n`,
      );
      suppress.diagnostics = [d];
      actions.push(suppress);
    }
    return actions;
  }
}

class RuleHoverProvider implements vscode.HoverProvider {
  constructor(private readonly controller: DiagnosticsController) {}

  provideHover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
    const diags = this.controller.collection.get(doc.uri) ?? [];
    const hits = diags.filter((d) => d.range.contains(pos));
    const parts = hits.map((d) => this.controller.ruleFor(d)).filter((r) => r !== undefined);
    if (!parts.length) {
      return undefined;
    }
    const unique = [...new Map(parts.map((r) => [r.id, r])).values()];
    return new vscode.Hover(unique.map(ruleMarkdown));
  }
}
