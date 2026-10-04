import * as vscode from 'vscode';
import { CONSTANTS, FUNCTIONS, signature, type ApiFunction } from './apiDb';
import { enclosingCall } from './callContext';

export const API_LANGUAGES: vscode.DocumentSelector = [
  { language: 'c' },
  { language: 'cpp' },
  { language: 'rust' },
  { language: 'objective-c' },
  { language: 'objective-cpp' },
];

export function functionMarkdown(fn: ApiFunction): vscode.MarkdownString {
  const md = new vscode.MarkdownString(undefined, true);
  md.appendCodeblock(signature(fn), 'c');
  md.appendMarkdown(`${fn.doc}\n\n`);
  if (fn.deprecated) {
    md.appendMarkdown(`**Deprecated** — use \`${fn.deprecated}\`.\n\n`);
  }
  const facts = [
    `**Returns:** ${fn.returns}`,
    fn.irql ? `**IRQL:** ${fn.irql}` : '',
    fn.pairedWith ? `**Release with:** \`${fn.pairedWith}\`` : '',
  ].filter(Boolean);
  md.appendMarkdown(facts.join(' · ') + '\n\n');
  for (const n of fn.notes ?? []) {
    md.appendMarkdown(`- ${n}\n`);
  }
  md.appendMarkdown(`\n[${fn.framework} documentation](${fn.url})`);
  return md;
}

export class ApiHoverProvider implements vscode.HoverProvider {
  provideHover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
    const range = doc.getWordRangeAtPosition(pos, /[A-Za-z_][A-Za-z0-9_]*/);
    if (!range) {
      return undefined;
    }
    const word = doc.getText(range);
    const fn = FUNCTIONS.get(word);
    if (fn) {
      return new vscode.Hover(functionMarkdown(fn), range);
    }
    const c = CONSTANTS.get(word);
    return c ? new vscode.Hover(new vscode.MarkdownString(`\`${c.name}\` — ${c.doc}\n\n*${c.framework}*`), range) : undefined;
  }
}

export class ApiSignatureHelpProvider implements vscode.SignatureHelpProvider {
  provideSignatureHelp(doc: vscode.TextDocument, pos: vscode.Position): vscode.SignatureHelp | undefined {
    const start = doc.positionAt(Math.max(0, doc.offsetAt(pos) - 4000));
    const call = enclosingCall(doc.getText(new vscode.Range(start, pos)));
    const fn = call && FUNCTIONS.get(call.name);
    if (!fn) {
      return undefined;
    }
    const sig = new vscode.SignatureInformation(signature(fn), functionMarkdown(fn));
    sig.parameters = fn.params.map((p) => new vscode.ParameterInformation(`${p.type} ${p.name}`, p.doc));
    const help = new vscode.SignatureHelp();
    help.signatures = [sig];
    help.activeSignature = 0;
    help.activeParameter = Math.min(call.arg, Math.max(0, fn.params.length - 1));
    return help;
  }
}

export class ApiCompletionProvider implements vscode.CompletionItemProvider {
  provideCompletionItems(doc: vscode.TextDocument, pos: vscode.Position): vscode.CompletionItem[] | undefined {
    const range = doc.getWordRangeAtPosition(pos, /[A-Za-z_][A-Za-z0-9_]*/);
    const prefix = range ? doc.getText(new vscode.Range(range.start, pos)) : '';
    if (!/^(Fw|Ev|St|Co|En|Op|Pr|Cl|Td|es|ES|EV|TR|FW|PR|IN)/.test(prefix)) {
      return undefined;
    }
    const items: vscode.CompletionItem[] = [];
    for (const fn of FUNCTIONS.values()) {
      const item = new vscode.CompletionItem({ label: fn.name, description: fn.framework }, vscode.CompletionItemKind.Function);
      item.detail = signature(fn);
      item.documentation = functionMarkdown(fn);
      item.insertText = new vscode.SnippetString(`${fn.name}(${fn.params.map((p, i) => `\${${i + 1}:${p.name}}`).join(', ')})`);
      item.tags = fn.deprecated ? [vscode.CompletionItemTag.Deprecated] : undefined;
      items.push(item);
    }
    for (const c of CONSTANTS.values()) {
      const item = new vscode.CompletionItem({ label: c.name, description: c.framework }, vscode.CompletionItemKind.Constant);
      item.documentation = c.doc;
      items.push(item);
    }
    return items;
  }
}
