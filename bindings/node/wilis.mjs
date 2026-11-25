/**
 * Zero-dependency Node.js (ESM) SDK for the Wilis v0.7.0 Cryptography Suite.
 *
 * Supports:
 * - Native Node-API in-process addon (`wilis_napi.node`, if built via `node-gyp`)
 * - Out-of-the-box zero-build fallback using the native `wilis` binary over stdio pipes
 * Uses ONLY Node.js built-in modules (`node:child_process`, `node:fs`, `node:os`, `node:path`).
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function resolveDefaultBinary() {
  const root = path.resolve(__dirname, "..", "..");
  const binName = process.platform === "win32" ? "wilis.exe" : "wilis";
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(root, "target", profile, binName);
    if (fs.existsSync(candidate)) return candidate;
  }
  return binName;
}

export class WilisClient {
  /** @param {string} [binaryPath] Optional path to the compiled `wilis` executable. */
  constructor(binaryPath) {
    this.binaryPath = binaryPath || resolveDefaultBinary();
  }

  /** @private */
  _exec(args, inputBuffer = undefined) {
    return execFileSync(this.binaryPath, args, {
      input: inputBuffer,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
  }

  /** Generates `bytes` OS CSPRNG bytes as lowercase hex. */
  randomHex(bytes = 32) {
    return this._exec(["rand", "--bytes", String(bytes)]).toString("utf8").trim();
  }

  /** Generates cryptographically unbiased passwords or phonetic passphrases. */
  passgen({ words, length = 24, count = 1 } = {}) {
    const args = ["passgen", "--count", String(count)];
    if (words) args.push("--words", String(words));
    else args.push("--length", String(length));
    return this._exec(args).toString("utf8").trim().split(/\r?\n/);
  }

  /** Computes the 256-bit `WilisHash-256` hex digest via stdin pipe. */
  hash256(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    const out = this._exec(["hash", "--file", "-"], buf).toString("utf8").trim();
    return out.split(/\s+/)[0];
  }

  /** Computes a 256-bit keyed `WilisMAC` hex tag via stdin pipe. */
  mac256(keyHex, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    return this._exec(["mac", "--key", keyHex, "--file", "-"], buf).toString("utf8").trim();
  }

  /** Verifies a 256-bit keyed `WilisMAC` hex tag in constant time. */
  macVerify(keyHex, tagHex, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    try {
      this._exec(["mac-verify", "--key", keyHex, "--tag", tagHex, "--file", "-"], buf);
      return true;
    } catch {
      return false;
    }
  }

  /** Stream-encrypts a Buffer into a `WILS` v2 container via stdio pipes. */
  encryptBuffer(keyHex, plaintext, aad = "") {
    const buf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
    const args = ["encrypt-file", "--key", keyHex, "--in", "-", "--out", "-"];
    if (aad) args.push("--aad", aad);
    return this._exec(args, buf);
  }

  /** Authenticates and decrypts a `WILS` v1/v2 container Buffer via stdio pipes. */
  decryptBuffer(keyHex, container, aad = "") {
    const buf = Buffer.isBuffer(container) ? container : Buffer.from(container);
    const args = ["decrypt-file", "--key", keyHex, "--in", "-", "--out", "-"];
    if (aad) args.push("--aad", aad);
    return this._exec(args, buf);
  }

  /** Generates a post-quantum `WilisKEM` keypair (`{ pkPath, skPath }`) at `prefix`. */
  kemKeygen(prefix) {
    this._exec(["kem-keygen", "--out", prefix]);
    return { pkPath: `${prefix}.wkp`, skPath: `${prefix}.wks` };
  }

  /** Encrypts `inPath` to 1..=64 post-quantum recipients (`WPKE` v2). */
  pubEncrypt(pkPaths, inPath, outPath, { aad = "", armor = false } = {}) {
    const pks = Array.isArray(pkPaths) ? pkPaths : [pkPaths];
    const args = ["pub-encrypt"];
    for (const p of pks) args.push("--pk", p);
    if (aad) args.push("--aad", aad);
    if (armor) args.push("--armor");
    args.push("--in", inPath, "--out", outPath);
    return this._exec(args).toString("utf8").trim();
  }

  /** Authenticates and decrypts a `WPKE` v1/v2 file using `skPath`. */
  pubDecrypt(skPath, inPath, outPath, { aad = "" } = {}) {
    const args = ["pub-decrypt", "--sk", skPath, "--in", inPath, "--out", outPath];
    if (aad) args.push("--aad", aad);
    return this._exec(args).toString("utf8").trim();
  }

  /** Generates a stateless unlimited-use post-quantum `WilisSLH` keypair (`{ pkPath, skPath }`). */
  slhKeygen(prefix) {
    this._exec(["slh-keygen", "--out", prefix]);
    return { pkPath: `${prefix}.wlp`, skPath: `${prefix}.wls` };
  }

  /** Statelessly signs `inPath` with `WilisSLH` (`WLSG` v1). */
  slhSign(skPath, inPath, sigOutPath, { armor = false } = {}) {
    const args = ["slh-sign", "--sk", skPath, "--in", inPath, "--out", sigOutPath];
    if (armor) args.push("--armor");
    return this._exec(args).toString("utf8").trim();
  }

  /** Verifies a stateless `WilisSLH` signature. */
  slhVerify(pkPath, inPath, sigPath) {
    try {
      this._exec(["slh-verify", "--pk", pkPath, "--in", inPath, "--sig", sigPath]);
      return true;
    } catch {
      return false;
    }
  }

  /** Encodes a 64-hex (32-byte) key into a 34-word checksummed phonetic mnemonic. */
  encodeMnemonic(keyHex) {
    return this._exec(["mnemonic", "encode", "--key", keyHex]).toString("utf8").trim();
  }

  /** Decodes a 34-word checksummed phonetic mnemonic back into a 64-hex key. */
  decodeMnemonic(phrase) {
    const words = String(phrase).trim().split(/\s+/);
    return this._exec(["mnemonic", "decode", ...words]).toString("utf8").trim();
  }

  /** Splits a hex secret into `K`-of-`N` Shamir shares. */
  splitKey(secretHex, total, threshold) {
    const out = this._exec([
      "split-key",
      "--secret",
      secretHex,
      "--total",
      String(total),
      "--threshold",
      String(threshold),
    ]).toString("utf8");
    return out
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.includes("wilis-share-v1:"))
      .map((l) => l.slice(l.indexOf("wilis-share-v1:")));
  }

  /** Combines `K` Shamir share tokens back into the original hex secret. */
  combineKey(shares) {
    const out = this._exec(["combine-key", ...shares]).toString("utf8");
    const m = out.match(/([0-9a-fA-F]{2,})\s*$/);
    return m ? m[1] : out.trim();
  }

  /** Inspects any Wilis binary or ASCII-armored file without decrypting secrets. */
  inspect(filePath) {
    return this._exec(["inspect", filePath]).toString("utf8");
  }

  /** Runs the 8-part scientific cryptanalysis & empirical timing audit. */
  audit() {
    return this._exec(["audit"]).toString("utf8");
  }

  /** Helper creating a temporary working directory for file-based PQ operations. */
  static makeTempDir(prefix = "wilis-node-") {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }
}

export default WilisClient;
