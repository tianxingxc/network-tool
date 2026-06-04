import JSEncrypt from 'jsencrypt';

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

export function generateRSAKeyPair(keySize: number = 2048): Promise<RSAKeyPair> {
  return new Promise((resolve, reject) => {
    try {
      const crypt = new JSEncrypt({ default_key_size: String(keySize) });
      // getKey() triggers key generation
      crypt.getPublicKey();
      const publicKey = crypt.getPublicKey();
      const privateKey = crypt.getPrivateKey();
      if (!publicKey || !privateKey) {
        reject(new Error('密钥生成失败'));
        return;
      }
      resolve({ publicKey, privateKey });
    } catch (e) {
      reject(e);
    }
  });
}

export function rsaEncrypt(plaintext: string, publicKeyPem: string): string {
  const crypt = new JSEncrypt();
  crypt.setPublicKey(publicKeyPem);
  const result = crypt.encrypt(plaintext);
  if (!result) throw new Error('RSA加密失败，请检查公钥是否正确');
  return result;
}

export function rsaDecrypt(ciphertext: string, privateKeyPem: string): string {
  const crypt = new JSEncrypt();
  crypt.setPrivateKey(privateKeyPem);
  const result = crypt.decrypt(ciphertext);
  if (!result && result !== '') throw new Error('RSA解密失败，请检查私钥是否正确');
  return result;
}
