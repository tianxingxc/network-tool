// ========== Base64 ==========
export function base64Encode(input: string): string {
  return btoa(unescape(encodeURIComponent(input)));
}

export function base64Decode(input: string): string {
  try {
    return decodeURIComponent(escape(atob(input)));
  } catch {
    return atob(input);
  }
}

// ========== URL Encode / Decode ==========
export function urlEncode(input: string): string {
  return encodeURIComponent(input);
}

export function urlDecode(input: string): string {
  return decodeURIComponent(input);
}

// ========== URL Encode (component level, all chars) ==========
export function urlEncodeAll(input: string): string {
  return Array.from(input)
    .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
    .join('');
}

// ========== HTML Encode / Decode ==========
export function htmlEncode(input: string): string {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}

export function htmlDecode(input: string): string {
  const div = document.createElement('div');
  div.innerHTML = input;
  return div.textContent || '';
}

// ========== Unicode Encode / Decode ==========
export function unicodeEncode(input: string): string {
  return Array.from(input)
    .map(c => {
      const code = c.codePointAt(0)!;
      return code > 0xFFFF
        ? `\\u{${code.toString(16).toUpperCase()}}`
        : `\\u${code.toString(16).padStart(4, '0').toUpperCase()}`;
    })
    .join('');
}

export function unicodeDecode(input: string): string {
  return input.replace(/\\u\{?([0-9a-fA-F]+)\}?/g, (_, hex) => {
    return String.fromCodePoint(parseInt(hex, 16));
  });
}

// ========== Hex Encode / Decode ==========
export function hexEncode(input: string): string {
  return Array.from(new TextEncoder().encode(input))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

export function hexDecode(input: string): string {
  const bytes = input.trim().split(/\s+/).map(hex => parseInt(hex, 16));
  return new TextDecoder().decode(new Uint8Array(bytes));
}
