/** Luhn checksum, used to tell real-looking PANs apart from arbitrary digit runs. */
export function luhn(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) {
    return false;
  }
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/**
 * Public resolvers and cloud wire-server / metadata addresses: they appear in connectivity checks and
 * SSRF block lists, not as command-and-control endpoints.
 */
const WELL_KNOWN = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '168.63.129.16']);

/**
 * A routable public IPv4 address: rejects private, loopback, link-local, CGNAT, documentation,
 * multicast / reserved ranges and well-known resolvers. Also rejects dotted values that are more
 * likely ASN.1 OIDs (`2.5.4.3`, `1.3.6.1`) or version numbers (`4.0.1.3`, `x.0.0.0`).
 */
export function publicIpv4(value: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) {
    return false;
  }
  const [a, b, c, d] = m.slice(1).map(Number);
  if ([a, b, c, d].some((o) => o > 255) || WELL_KNOWN.has(value)) {
    return false;
  }
  if (a <= 2 || [a, b, c, d].every((o) => o < 32) || (b === 0 && c === 0 && d === 0)) {
    return false;
  }
  return !(
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

export const VALIDATORS: Record<string, (value: string) => boolean> = { luhn, publicIpv4 };
