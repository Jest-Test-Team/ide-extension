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

export const VALIDATORS: Record<string, (value: string) => boolean> = { luhn };
