type Base = 2 | 8 | 10 | 16 | 32 | 36;

const baseNames: Record<Base, string> = {
  2: '二进制 (Binary)',
  8: '八进制 (Octal)',
  10: '十进制 (Decimal)',
  16: '十六进制 (Hex)',
  32: '三十二进制 (Base32)',
  36: '三十六进制 (Base36)',
};

export function getBaseNames() {
  return baseNames;
}

export function convertBase(value: string, fromBase: Base, toBase: Base): string {
  if (!value.trim()) return '';

  // Parse from source base to decimal
  let decimal: bigint;
  try {
    if (fromBase === 10) {
      decimal = BigInt(value);
    } else {
      decimal = BigInt(parseInt(value, fromBase));
    }
  } catch {
    // Fallback for large numbers
    decimal = BigInt(parseInt(value, fromBase));
    if (isNaN(Number(decimal))) return '无效输入';
  }

  // Convert decimal to target base
  if (toBase === 10) return decimal.toString();

  if (toBase === 16) return decimal.toString(16).toUpperCase();
  if (toBase === 8) return decimal.toString(8);
  if (toBase === 2) return decimal.toString(2);
  if (toBase === 32) return decimal.toString(32).toUpperCase();
  if (toBase === 36) return decimal.toString(36).toUpperCase();

  return decimal.toString(toBase);
}

// ASCII code conversion
export function textToAscii(text: string): string {
  return Array.from(text)
    .map(c => c.charCodeAt(0))
    .join(' ');
}

export function asciiToText(ascii: string): string {
  return ascii
    .trim()
    .split(/\s+/)
    .map(code => String.fromCharCode(parseInt(code, 10)))
    .join('');
}

// Byte size conversion
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
