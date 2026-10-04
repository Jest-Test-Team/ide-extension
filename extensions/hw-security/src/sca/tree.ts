import type { TagOccurrence } from '@ide-ext/core';
import * as vscode from 'vscode';
import { location, type ScaIndex, type ScaPoint } from './tags';

type Item = { kind: 'point'; point: ScaPoint } | { kind: 'occ'; occ: TagOccurrence; role: 'target' | 'analysis' };

export class ScaTreeProvider implements vscode.TreeDataProvider<Item> {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly sca: ScaIndex) {
    sca.onDidChange(() => this.emitter.fire());
  }

  getChildren(item?: Item): Item[] {
    if (!item) {
      return this.sca.points().map((point) => ({ kind: 'point', point }));
    }
    if (item.kind === 'point') {
      return [
        ...item.point.defs.map((occ): Item => ({ kind: 'occ', occ, role: 'target' })),
        ...item.point.refs.map((occ): Item => ({ kind: 'occ', occ, role: 'analysis' })),
      ];
    }
    return [];
  }

  getTreeItem(item: Item): vscode.TreeItem {
    if (item.kind === 'point') {
      const p = item.point;
      const ti = new vscode.TreeItem(p.id, vscode.TreeItemCollapsibleState.Collapsed);
      const status = !p.defs.length ? 'orphan reference' : p.defs.length > 1 ? 'duplicate id' : p.refs.length ? `analysed (${p.refs.length})` : 'not analysed';
      ti.description = `${status}${p.defs[0]?.description ? ` — ${p.defs[0].description}` : ''}`;
      ti.iconPath = new vscode.ThemeIcon(
        !p.defs.length || p.defs.length > 1 ? 'warning' : p.refs.length ? 'pass' : 'circle-large-outline',
        new vscode.ThemeColor(!p.defs.length || p.defs.length > 1 ? 'editorWarning.foreground' : p.refs.length ? 'testing.iconPassed' : 'descriptionForeground'),
      );
      ti.contextValue = 'scaPoint';
      return ti;
    }
    const uri = vscode.Uri.parse(item.occ.uri);
    const ti = new vscode.TreeItem(`${vscode.workspace.asRelativePath(uri)}:${item.occ.line + 1}`);
    ti.description = item.role === 'target' ? 'target code' : 'analysis script';
    ti.iconPath = new vscode.ThemeIcon(item.role === 'target' ? 'chip' : 'graph');
    const loc = location(item.occ);
    ti.command = { command: 'vscode.open', title: 'Open', arguments: [loc.uri, { selection: loc.range }] };
    return ti;
  }
}
