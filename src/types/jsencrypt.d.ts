declare module 'jsencrypt' {
  export default class JSEncrypt {
    constructor(options?: { default_key_size?: string | number });
    public getPublicKey(): string;
    public getPrivateKey(): string;
    public setPublicKey(key: string): void;
    public setPrivateKey(key: string): void;
    public encrypt(str: string): string | false;
    public decrypt(str: string): string | false;
  }
}
