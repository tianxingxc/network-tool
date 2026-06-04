import CryptoJS from 'crypto-js';

// ========== AES ==========
export function aesEncrypt(plaintext: string, key: string, mode: 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR' = 'CBC'): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(32, '0').slice(0, 32));
  const iv = CryptoJS.lib.Random.create(16);
  const modeMap: Record<string, typeof CryptoJS.mode.CBC> = {
    CBC: CryptoJS.mode.CBC,
    ECB: CryptoJS.mode.ECB,
    CFB: CryptoJS.mode.CFB,
    OFB: CryptoJS.mode.OFB,
    CTR: CryptoJS.mode.CTR,
  };
  const encrypted = CryptoJS.AES.encrypt(plaintext, keyBytes, {
    iv,
    mode: modeMap[mode] || CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function aesDecrypt(ciphertext: string, key: string, mode: 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR' = 'CBC'): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(32, '0').slice(0, 32));
  const modeMap: Record<string, typeof CryptoJS.mode.CBC> = {
    CBC: CryptoJS.mode.CBC,
    ECB: CryptoJS.mode.ECB,
    CFB: CryptoJS.mode.CFB,
    OFB: CryptoJS.mode.OFB,
    CTR: CryptoJS.mode.CTR,
  };
  const bytes = CryptoJS.AES.decrypt(ciphertext, keyBytes, {
    mode: modeMap[mode] || CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}

// ========== DES ==========
export function desEncrypt(plaintext: string, key: string): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(8, '0').slice(0, 8));
  const encrypted = CryptoJS.DES.encrypt(plaintext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function desDecrypt(ciphertext: string, key: string): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(8, '0').slice(0, 8));
  const bytes = CryptoJS.DES.decrypt(ciphertext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}

// ========== Triple DES ==========
export function tripleDesEncrypt(plaintext: string, key: string): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(24, '0').slice(0, 24));
  const encrypted = CryptoJS.TripleDES.encrypt(plaintext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function tripleDesDecrypt(ciphertext: string, key: string): string {
  const keyBytes = CryptoJS.enc.Utf8.parse(key.padEnd(24, '0').slice(0, 24));
  const bytes = CryptoJS.TripleDES.decrypt(ciphertext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}
