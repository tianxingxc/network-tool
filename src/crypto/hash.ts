import CryptoJS from 'crypto-js';

// ========== MD5 ==========
export function md5(input: string): string {
  return CryptoJS.MD5(input).toString();
}

// ========== SHA1 ==========
export function sha1(input: string): string {
  return CryptoJS.SHA1(input).toString();
}

// ========== SHA256 ==========
export function sha256(input: string): string {
  return CryptoJS.SHA256(input).toString();
}

// ========== SHA512 ==========
export function sha512(input: string): string {
  return CryptoJS.SHA512(input).toString();
}

// ========== HMAC-SHA256 ==========
export function hmacSHA256(message: string, key: string): string {
  return CryptoJS.HmacSHA256(message, key).toString();
}

// ========== File hash ==========
export async function fileHash(file: File, algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512'): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await window.crypto.subtle.digest(algorithm, buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
