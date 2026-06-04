import forge from 'node-forge';

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

export type RSAPadding = 'PKCS1_V1_5' | 'OAEP';

export function generateRSAKeyPair(keySize: number = 2048): Promise<RSAKeyPair> {
  return new Promise((resolve, reject) => {
    try {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: keySize });
      const publicKey = forge.pki.publicKeyToPem(keypair.publicKey);
      const privateKey = forge.pki.privateKeyToPem(keypair.privateKey);
      resolve({ publicKey, privateKey });
    } catch (e) {
      reject(e);
    }
  });
}

export function rsaEncrypt(plaintext: string, publicKeyPem: string, padding: RSAPadding = 'PKCS1_V1_5'): string {
  const pubKey = forge.pki.publicKeyFromPem(publicKeyPem);
  let encrypted: forge.util.ByteStringBuffer;
  if (padding === 'OAEP') {
    encrypted = pubKey.encrypt(plaintext, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
  } else {
    encrypted = pubKey.encrypt(plaintext, 'RSAES-PKCS1-V1_5');
  }
  return forge.util.encode64(encrypted.getBytes());
}

export function rsaDecrypt(ciphertext: string, privateKeyPem: string, padding: RSAPadding = 'PKCS1_V1_5'): string {
  const privKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const encrypted = forge.util.decode64(ciphertext);
  if (padding === 'OAEP') {
    return privKey.decrypt(encrypted, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });
  } else {
    return privKey.decrypt(encrypted, 'RSAES-PKCS1-V1_5');
  }
}
