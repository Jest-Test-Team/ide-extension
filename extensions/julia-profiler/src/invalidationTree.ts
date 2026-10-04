import * as vscode from 'vscode';
import { hasSource, type InstanceNode, type InvalidationTree, type MiInfo } from './profile';
import type { ProfileStore } from './store';

type Item =
  | { kind: 'root'; tree: InvalidationTree }
  | { kind: 'trigger'; label: string; node: InstanceNode }
  | { kind: 'instance'; node: InstanceNode }
  | { kind: 'info'; label: string };

/** Sidebar tree: invalidating method → backedge / method-table trigger → invalidated MethodInstances. */
export class InvalidationTreeProvider implements vscode.TreeDataProvider<Item> {
  private readonly emitter = new vscode.EventEmitter<Item | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private filter = '';

  constructor(private readonly store: ProfileStore) {
    store.onDidChange(() => this.emitter.fire(undefined));
  }

  setFilter(text: string): void {
    this.filter = text.toLowerCase();
    void vscode.commands.executeCommand('setContext', 'juliaProfiler.filtered', !!text);
    this.emitter.fire(undefined);
  }

  getChildren(item?: Item): Item[] {
    const p = this.store.profile;
    if (!p) {
      return [];
    }
    if (!item) {
      const roots = p.invalidations.filter(
        (t) => !this.filter || `${t.module}.${t.method} ${t.sig} ${t.file}`.toLowerCase().includes(this.filter),
      );
      if (!roots.length) {
        return [{ kind: 'info', label: p.invalidations.length ? 'No match for filter' : 'No invalidations recorded 🎉' }];
      }
      return roots.map((tree) => ({ kind: 'root', tree }));
    }
    switch (item.kind) {
      case 'root':
        return [
          ...item.tree.mt_backedges.map(
            (m): Item => ({ kind: 'trigger', label: `method table: ${m.trigger}`, node: m.root }),
          ),
          ...item.tree.backedges.map((node): Item => ({ kind: 'instance', node })),
        ];
      case 'trigger':
        return [{ kind: 'instance', node: item.node }];
      case 'instance':
        return item.node.children.map((node): Item => ({ kind: 'instance', node }));
      default:
        return [];
    }
  }

  getTreeItem(item: Item): vscode.TreeItem {
    switch (item.kind) {
      case 'info':
        return new vscode.TreeItem(item.label);
      case 'root': {
        const t = item.tree;
        const ti = new vscode.TreeItem(`${t.module}.${t.method}`, vscode.TreeItemCollapsibleState.Collapsed);
        ti.description = `${t.ninvalidated} invalidated · ${t.reason}`;
        ti.tooltip = tooltip(t, [
          `**${t.ninvalidated}** MethodInstances invalidated (${t.reason})`,
          t.mt_cache ? `${t.mt_cache} method-table cache entries` : '',
          t.mt_disable ? `${t.mt_disable} disabled fallback(s)` : '',
        ]);
        ti.iconPath = new vscode.ThemeIcon('flame', new vscode.ThemeColor(t.ninvalidated > 100 ? 'errorForeground' : 'editorWarning.foreground'));
        ti.contextValue = 'root';
        ti.command = openCommand(t);
        return ti;
      }
      case 'trigger': {
        const ti = new vscode.TreeItem(item.label, vscode.TreeItemCollapsibleState.Collapsed);
        ti.iconPath = new vscode.ThemeIcon('symbol-interface');
        ti.tooltip = 'Invalidated through a method-table backedge: compiled code that called this signature via runtime dispatch.';
        return ti;
      }
      case 'instance': {
        const n = item.node;
        const ti = new vscode.TreeItem(
          `${n.module ? `${n.module}.` : ''}${n.method}`,
          n.children.length ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
        );
        ti.description = `${n.total ? `${n.total} below · ` : ''}${shortSig(n.sig)}`;
        ti.tooltip = tooltip(n, []);
        ti.iconPath = new vscode.ThemeIcon('symbol-method');
        ti.command = openCommand(n);
        return ti;
      }
    }
  }
}

function shortSig(sig: string): string {
  const inner = sig.replace(/^Tuple\{/, '').replace(/\}$/, '');
  return inner.length > 80 ? `${inner.slice(0, 77)}…` : inner;
}

function tooltip(m: MiInfo, extra: string[]): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendCodeblock(m.sig, 'julia');
  extra.filter(Boolean).forEach((l) => md.appendMarkdown(`${l}\n\n`));
  if (hasSource(m)) {
    md.appendMarkdown(`\`${m.file}:${m.line}\``);
  }
  return md;
}

export function openCommand(m: { file: string; line: number }): vscode.Command | undefined {
  return hasSource(m)
    ? { command: 'juliaProfiler.openLocation', title: 'Open source', arguments: [{ file: m.file, line: m.line }] }
    : undefined;
}
