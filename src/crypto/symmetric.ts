import CryptoJS from 'crypto-js';

// ========== AES ==========
export function aesEncrypt(plaintext: string, key: string, mode: 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR' = 'CBC'): string {
  const len = new TextEncoder().encode(key).length;
  if (len !== 16 && len !== 24 && len !== 32) {
    throw new Error(`AES密钥长度必须为16、24或32字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const modeMap: Record<string, any> = {
    CBC: CryptoJS.mode.CBC,
    ECB: CryptoJS.mode.ECB,
    CFB: CryptoJS.mode.CFB,
    OFB: CryptoJS.mode.OFB,
    CTR: CryptoJS.mode.CTR,
  };
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(plaintext, keyBytes, {
    iv,
    mode: modeMap[mode] || CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function aesDecrypt(ciphertext: string, key: string, mode: 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR' = 'CBC'): string {
  const len = new TextEncoder().encode(key).length;
  if (len !== 16 && len !== 24 && len !== 32) {
    throw new Error(`AES密钥长度必须为16、24或32字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const modeMap: Record<string, any> = {
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
  const len = new TextEncoder().encode(key).length;
  if (len !== 8) {
    throw new Error(`DES密钥长度必须为8字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const encrypted = CryptoJS.DES.encrypt(plaintext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function desDecrypt(ciphertext: string, key: string): string {
  const len = new TextEncoder().encode(key).length;
  if (len !== 8) {
    throw new Error(`DES密钥长度必须为8字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const bytes = CryptoJS.DES.decrypt(ciphertext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}

// ========== Triple DES ==========
export function tripleDesEncrypt(plaintext: string, key: string): string {
  const len = new TextEncoder().encode(key).length;
  if (len !== 24) {
    throw new Error(`3DES密钥长度必须为24字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const encrypted = CryptoJS.TripleDES.encrypt(plaintext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

export function tripleDesDecrypt(ciphertext: string, key: string): string {
  const len = new TextEncoder().encode(key).length;
  if (len !== 24) {
    throw new Error(`3DES密钥长度必须为24字节，当前为${len}字节`);
  }
  const keyBytes = CryptoJS.enc.Utf8.parse(key);
  const bytes = CryptoJS.TripleDES.decrypt(ciphertext, keyBytes, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}
