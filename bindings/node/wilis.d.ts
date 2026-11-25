export declare class WilisClient {
  readonly binaryPath: string;
  constructor(binaryPath?: string);
  randomHex(bytes?: number): string;
  hash256(data: Buffer | string): string;
  mac256(keyHex: string, data: Buffer | string): string;
  encryptBuffer(keyHex: string, plaintext: Buffer | Uint8Array | string, aad?: string): Buffer;
  decryptBuffer(keyHex: string, container: Buffer | Uint8Array, aad?: string): Buffer;
  encodeMnemonic(keyHex: string): string;
  decodeMnemonic(phrase: string): string;
  audit(): string;
}

export default WilisClient;
