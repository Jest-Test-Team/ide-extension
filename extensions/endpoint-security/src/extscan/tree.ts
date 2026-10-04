import { toRange } from '@ide-ext/core/vscode';
import { basename, relative } from 'node:path';
import * as vscode from 'vscode';
import type { ExtensionScanner, ExtResult } from './scanner';
import type { Boost } from './score';
import { SIGNALS, type Located, type Signal } from './signals';

export type ExtScanItem =
  | { kind: 'ext'; result: ExtResult }
  | { kind: 'boost'; result: ExtResult; boost: Boost }
  | { kind: 'signal'; result: ExtResult; signal: Signal }
  | { kind: 'location'; result: ExtResult; loc: Located };

const LEVEL_ICON = {
  high: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
  medium: new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground')),
  low: new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed')),
};

const signed = (n: number) => (n > 0 ? `+${n}` : String(n));

export class ExtScanTreeProvider implements vscode.TreeDataProvider<ExtScanItem> {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly scanner: ExtensionScanner) {
    scanner.onDidChange(() => this.emitter.fire());
  }

  getParent(item: ExtScanItem): ExtScanItem | undefined {
    if (item.kind === 'ext') {
      return undefined;
    }
    if (item.kind === 'location') {
      const signal = item.result.risk.signals.find((s) => s.locations.includes(item.loc));
      return signal ? { kind: 'signal', result: item.result, signal } : { kind: 'ext', result: item.result };
    }
    return { kind: 'ext', result: item.result };
  }

  getChildren(item?: ExtScanItem): ExtScanItem[] {
    if (!item) {
      return this.scanner.latest.map((result) => ({ kind: 'ext', result }));
    }
    if (item.kind === 'ext') {
      return [
        ...item.result.risk.boosts.map((boost): ExtScanItem => ({ kind: 'boost', result: item.result, boost })),
        ...item.result.risk.signals.map((signal): ExtScanItem => ({ kind: 'signal', result: item.result, signal })),
      ];
    }
    if (item.kind === 'signal') {
      // Manifest signals point at package.json; listing them again under the reason adds nothing.
      const code = item.signal.locations.filter((l) => basename(l.file) !== 'package.json' || item.signal.locations.length > 1);
      return code.map((loc): ExtScanItem => ({ kind: 'location', result: item.result, loc }));
    }
    return [];
  }

  getTreeItem(item: ExtScanItem): vscode.TreeItem {
    switch (item.kind) {
      case 'ext': {
        const { ext, risk } = item.result;
        const ti = new vscode.TreeItem(ext.displayName ?? ext.id, risk.signals.length || risk.boosts.length ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
        ti.id = `ext:${ext.id}`;
        ti.description = [risk.level, String(risk.score), risk.allowlisted ? 'allowlisted' : ext.id.split('.')[0]].join(' · ');
        ti.iconPath = risk.allowlisted && !risk.allowlistOverridden ? new vscode.ThemeIcon('verified') : LEVEL_ICON[risk.level];
        ti.contextValue = risk.allowlisted ? 'extScan.ext.allowlisted' : 'extScan.ext';
        ti.tooltip = this.tooltip(item.result);
        return ti;
      }
      case 'boost': {
        const ti = new vscode.TreeItem(item.boost.label);
        ti.id = `boost:${item.result.ext.id}:${item.boost.label}`;
        ti.description = `${signed(item.boost.weight)} combination`;
        ti.iconPath = new vscode.ThemeIcon('link');
        ti.tooltip = `Raised because these signals appear together: ${item.boost.because.join(', ')}`;
        return ti;
      }
      case 'signal': {
        const s = item.signal;
        const info = SIGNALS[s.id];
        const hasCode = this.getChildren(item).length > 0;
        const ti = new vscode.TreeItem(info?.title ?? s.id, hasCode ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
        ti.id = `signal:${item.result.ext.id}:${s.id}`;
        ti.description = `${signed(s.weight)}${s.count > 1 ? ` · ${s.count}×` : ''}${s.force ? ` · forces ${s.force}` : ''}`;
        ti.iconPath = new vscode.ThemeIcon(s.weight > 0 ? 'circle-filled' : s.weight < 0 ? 'thumbsup' : 'info', s.weight >= 3 ? new vscode.ThemeColor('editorWarning.foreground') : undefined);
        const md = new vscode.MarkdownString(`**${info?.title ?? s.id}** (\`${s.id}\`)\n\n${s.message}\n\n${info?.description ?? ''}`);
        for (const ref of info?.refs ?? []) {
          md.appendMarkdown(`\n\n- ${ref.url ? `[${ref.label}](${ref.url})` : ref.label}`);
        }
        ti.tooltip = md;
        const only = s.locations[0];
        if (!hasCode && only) {
          ti.command = this.openCommand(only);
        }
        return ti;
      }
      case 'location': {
        const { loc } = item;
        const rel = relative(item.result.ext.path, loc.file).replace(/\\/g, '/');
        const ti = new vscode.TreeItem(`${rel}:${loc.finding.range.start.line + 1}`);
        ti.description = loc.finding.message;
        ti.tooltip = `${loc.finding.ruleId}\n${loc.finding.message}`;
        ti.iconPath = new vscode.ThemeIcon('file-code');
        ti.command = this.openCommand(loc);
        return ti;
      }
    }
  }

  private openCommand(loc: Located): vscode.Command {
    // Opens read-only content in a preview tab; nothing in the extension folder is modified.
    return {
      command: 'vscode.open',
      title: 'Open',
      arguments: [vscode.Uri.file(loc.file), { selection: toRange(loc.finding.range), preview: true } satisfies vscode.TextDocumentShowOptions],
    };
  }

  private tooltip({ ext, risk }: ExtResult): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${ext.displayName ?? ext.id}** \`${ext.id}@${ext.version}\`\n\n`);
    md.appendMarkdown(`Risk: **${risk.level}** (score ${risk.score})`);
    if (risk.capped) {
      md.appendMarkdown(' — capped at medium: no combination of signals backs a higher level');
    }
    if (risk.allowlisted) {
      md.appendMarkdown(risk.allowlistOverridden ? '\n\n$(warning) Allowlisted, but listed as removed for malware.' : '\n\nAllowlisted: reasons are shown but not scored.');
    }
    md.appendMarkdown(`\n\nFolder: \`${ext.path}\``);
    if (ext.source) {
      md.appendMarkdown(`\n\nInstalled from: ${ext.source}`);
    }
    md.supportThemeIcons = true;
    return md;
  }
}
