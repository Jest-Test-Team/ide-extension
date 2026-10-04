// Browser-side helper bundled into webview scripts.
interface VsCodeApi {
  postMessage(msg: unknown): void;
  getState(): unknown;
  setState(state: unknown): void;
}
declare function acquireVsCodeApi(): VsCodeApi;

const api: VsCodeApi = acquireVsCodeApi();

export function post(msg: unknown): void {
  api.postMessage(msg);
}

/** Subscribes to host messages, then tells the host the page is ready to receive its initial data. */
export function onMessage<T = { type: string }>(handler: (msg: T) => void): void {
  window.addEventListener('message', (e: MessageEvent) => handler(e.data as T));
  api.postMessage({ type: 'ready' });
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    node.setAttribute(k, v);
  }
  node.append(...children);
  return node;
}

export function fmt(n: number, digits = 3): string {
  return Number.isFinite(n) ? n.toFixed(digits) : String(n);
}
