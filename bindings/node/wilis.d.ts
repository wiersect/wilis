export interface PassgenOptions {
  words?: number;
  length?: number;
  count?: number;
}

export interface KeypairPaths {
  pkPath: string;
  skPath: string;
}

export declare class WilisClient {
  readonly binaryPath: string;
  constructor(binaryPath?: string);
  randomHex(bytes?: number): string;
  passgen(opts?: PassgenOptions): string[];
  hash256(data: Buffer | string): string;
  mac256(keyHex: string, data: Buffer | string): string;
  macVerify(keyHex: string, tagHex: string, data: Buffer | string): boolean;
  encryptBuffer(keyHex: string, plaintext: Buffer | Uint8Array | string, aad?: string): Buffer;
  decryptBuffer(keyHex: string, container: Buffer | Uint8Array, aad?: string): Buffer;
  kemKeygen(prefix: string): KeypairPaths;
  pubEncrypt(pkPaths: string | string[], inPath: string, outPath: string, opts?: { aad?: string; armor?: boolean }): string;
  pubDecrypt(skPath: string, inPath: string, outPath: string, opts?: { aad?: string }): string;
  slhKeygen(prefix: string): KeypairPaths;
  slhSign(skPath: string, inPath: string, sigOutPath: string, opts?: { armor?: boolean }): string;
  slhVerify(pkPath: string, inPath: string, sigPath: string): boolean;
  encodeMnemonic(keyHex: string): string;
  decodeMnemonic(phrase: string): string;
  splitKey(secretHex: string, total: number, threshold: number): string[];
  combineKey(shares: string[]): string;
  inspect(filePath: string): string;
  audit(): string;
  static makeTempDir(prefix?: string): string;
}

export default WilisClient;
