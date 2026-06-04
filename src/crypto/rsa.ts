// RSA uses Web Crypto API (native browser support)

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

export async function generateRSAKeyPair(keySize: number = 2048): Promise<RSAKeyPair> {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  const publicKey = await exportKey(keyPair.publicKey, 'public');
  const privateKey = await exportKey(keyPair.privateKey, 'private');

  return { publicKey, privateKey };
}

async function exportKey(key: CryptoKey, type: 'public' | 'private'): Promise<string> {
  const format = type === 'public' ? 'spki' : 'pkcs8';
  const exported = await window.crypto.subtle.exportKey(format, key);
  return arrayBufferToPem(exported, type);
}

function arrayBufferToPem(buffer: ArrayBuffer, type: 'public' | 'private'): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g) || [];
  const label = type === 'public' ? 'PUBLIC KEY' : 'PRIVATE KEY';
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function rsaEncrypt(plaintext: string, publicKeyPem: string): Promise<string> {
  const key = await window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    key,
    encoded
  );
  return arrayBufferToBase64(encrypted);
}

export async function rsaDecrypt(ciphertextBase64: string, privateKeyPem: string): Promise<string> {
  const key = await window.crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
  const encrypted = base64ToArrayBuffer(ciphertextBase64);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    key,
    encrypted
  );
  return new TextDecoder().decode(decrypted);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
