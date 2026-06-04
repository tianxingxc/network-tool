type Base = 2 | 8 | 10 | 16 | 32 | 36 | 62;

const baseNames: Record<Base, string> = {
  2: '二进制 (Binary)',
  8: '八进制 (Octal)',
  10: '十进制 (Decimal)',
  16: '十六进制 (Hex)',
  32: '三十二进制 (Base32)',
  36: '三十六进制 (Base36)',
  62: '六十二进制 (Base62)',
};

const BASE62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export function getBaseNames() {
  return baseNames;
}

// BigInt based base62 encode/decode
function bigIntToBase62(num: bigint): string {
  if (num === 0n) return '0';
  let result = '';
  let n = num;
  while (n > 0n) {
    result = BASE62_CHARS[Number(n % 62n)] + result;
    n = n / 62n;
  }
  return result;
}

function base62ToBigInt(str: string): bigint {
  let result = 0n;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    const idx = BASE62_CHARS.indexOf(ch);
    if (idx === -1) throw new Error(`无效的Base62字符: ${ch}`);
    result = result * 62n + BigInt(idx);
  }
  return result;
}

export function convertBase(value: string, fromBase: Base, toBase: Base): string {
  if (!value.trim()) return '';

  try {
    // Parse from source base to decimal (bigint)
    let decimal: bigint;
    if (fromBase === 62) {
      decimal = base62ToBigInt(value);
    } else if (fromBase === 10) {
      decimal = BigInt(value);
    } else {
      decimal = BigInt(parseInt(value, fromBase));
    }

    // Convert decimal to target base
    if (toBase === 10) return decimal.toString();
    if (toBase === 62) return bigIntToBase62(decimal);

    if (toBase === 16) return decimal.toString(16).toUpperCase();
    if (toBase === 8) return decimal.toString(8);
    if (toBase === 2) return decimal.toString(2);
    if (toBase === 32) return decimal.toString(32).toUpperCase();
    if (toBase === 36) return decimal.toString(36).toUpperCase();

    return decimal.toString(toBase);
  } catch {
    return '无效输入';
  }
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
