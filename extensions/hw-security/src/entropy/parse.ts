import type { PufReading } from './puf';

/**
 * Loads samples for entropy assessment:
 * - binary files (.bin, .dat, .raw): one sample per byte (NIST ea_* convention)
 * - text files: integers separated by whitespace/commas/newlines (decimal or 0x-hex)
 */
export function parseSamples(name: string, bytes: Uint8Array): Uint8Array {
  if (/\.(bin|dat|raw)$/i.test(name)) {
    return bytes;
  }
  const text = new TextDecoder().decode(bytes);
  const tokens = text.split(/[\s,;]+/).filter(Boolean);
  const out = new Uint8Array(tokens.length);
  tokens.forEach((t, i) => {
    const v = /^0x/i.test(t) ? parseInt(t, 16) : Number(t);
    if (!Number.isInteger(v) || v < 0 || v > 255) {
      throw new Error(`Sample ${i + 1} ("${t}") is not an integer in 0..255.`);
    }
    out[i] = v;
  });
  return out;
}

function toBits(response: string): Uint8Array {
  const r = response.trim();
  if (/^[01]+$/.test(r)) {
    return Uint8Array.from(r, (c) => (c === '1' ? 1 : 0));
  }
  const hex = r.replace(/^0x/i, '');
  if (!/^[0-9a-f]+$/i.test(hex)) {
    throw new Error(`Response "${r.slice(0, 20)}…" is neither a 0/1 string nor hex.`);
  }
  const out = new Uint8Array(hex.length * 4);
  for (let i = 0; i < hex.length; i++) {
    const v = parseInt(hex[i], 16);
    for (let b = 0; b < 4; b++) {
      out[i * 4 + b] = (v >> (3 - b)) & 1;
    }
  }
  return out;
}

/**
 * PUF CSV: header with `device`, `response` and optionally `read` columns (any order); responses
 * as 0/1 strings or hex. Without `read`, rows of the same device are numbered in file order.
 */
export function parsePufCsv(text: string): PufReading[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
  if (lines.length < 2) {
    throw new Error('PUF CSV needs a header line and at least one response.');
  }
  const header = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const di = header.indexOf('device');
  const ri = header.indexOf('response');
  const ki = header.indexOf('read');
  if (di < 0 || ri < 0) {
    throw new Error('PUF CSV header must contain "device" and "response" columns.');
  }
  const seen = new Map<string, number>();
  return lines.slice(1).map((line, i) => {
    const cols = line.split(',');
    const device = cols[di]?.trim();
    if (!device || cols[ri] === undefined) {
      throw new Error(`Line ${i + 2}: missing device or response.`);
    }
    const read = ki >= 0 ? Number(cols[ki]) : (seen.get(device) ?? 0);
    seen.set(device, (seen.get(device) ?? 0) + 1);
    return { device, read, bits: toBits(cols[ri]) };
  });
}
