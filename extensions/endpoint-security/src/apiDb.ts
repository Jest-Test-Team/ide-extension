import esf from '../data/apis/esf.json';
import etw from '../data/apis/etw.json';
import wfp from '../data/apis/wfp.json';

export interface ApiParam {
  name: string;
  type: string;
  doc: string;
}

export interface ApiFunction {
  name: string;
  returns: string;
  params: ApiParam[];
  doc: string;
  url: string;
  irql?: string;
  pairedWith?: string;
  deprecated?: string;
  notes?: string[];
  framework: string;
}

export interface ApiConstant {
  name: string;
  doc: string;
  framework: string;
}

interface DbFile {
  framework: string;
  id: string;
  docs: string;
  functions: Omit<ApiFunction, 'framework'>[];
  constants: { name: string; doc: string }[];
}

const FILES = [wfp, etw, esf] as DbFile[];

export const FUNCTIONS = new Map<string, ApiFunction>(
  FILES.flatMap((f) => f.functions.map((fn) => [fn.name, { ...fn, framework: f.framework }] as const)),
);
export const CONSTANTS = new Map<string, ApiConstant>(
  FILES.flatMap((f) => f.constants.map((c) => [c.name, { ...c, framework: f.framework }] as const)),
);
export const FRAMEWORK_DOCS = Object.fromEntries(FILES.map((f) => [f.framework, f.docs]));

export const returnType = (fn: ApiFunction) => fn.returns.split(' — ')[0].trim();

export function signature(fn: ApiFunction): string {
  return `${returnType(fn)} ${fn.name}(${fn.params.map((p) => `${p.type} ${p.name}`).join(', ')});`;
}

/**
 * Cleanup functions that satisfy a pairing, keyed by the acquiring function. Derived from the
 * database's `pairedWith`, plus equivalent alternatives.
 */
export const CLEANUP: Record<string, string[]> = Object.fromEntries(
  [...FUNCTIONS.values()]
    .filter((f) => f.pairedWith && !f.name.startsWith('FwpmTransactionBegin'))
    .map((f) => {
      const alts: Record<string, string[]> = {
        FwpsCalloutUnregisterById0: ['FwpsCalloutUnregisterById0', 'FwpsCalloutUnregisterByKey0'],
        ControlTraceW: ['ControlTraceW', 'ControlTraceA', 'ControlTrace', 'StopTraceW', 'StopTraceA', 'StopTrace'],
        CloseTrace: ['CloseTrace'],
      };
      return [f.name, alts[f.pairedWith!] ?? [f.pairedWith!]];
    }),
);

/** Functions whose status result should not be discarded (cleanup calls are exempt). */
export const STATUS_FUNCTIONS = [...FUNCTIONS.values()]
  .filter((f) => returnType(f) !== 'void' && !/Close|Delete|Destroy|Unregister|Abort|release|unsubscribe|Stop/i.test(f.name) && !/HANDLE|es_message_t \*/.test(returnType(f)))
  .map((f) => f.name);
