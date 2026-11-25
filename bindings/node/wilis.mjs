/**
 * Zero-dependency Node.js (ESM) wrapper for the Wilis v0.6.0 Cryptography Suite.
 * Uses only Node.js built-in modules (`node:child_process`, `node:fs`, `node:path`).
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function resolveDefaultBinary() {
  const root = path.resolve(__dirname, "..", "..");
  const binName = process.platform === "win32" ? "wilis.exe" : "wilis";
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(root, "target", profile, binName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return binName;
}

export class WilisClient {
  /**
   * @param {string} [binaryPath] Optional path to the compiled `wilis` executable.
   */
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

  /** Generates `bytes` cryptographically secure random bytes as lowercase hex. */
  randomHex(bytes = 32) {
    return this._exec(["rand", "--bytes", String(bytes)]).toString("utf8").trim();
  }

  /** Computes the 256-bit `WilisHash-256` hex digest of a Buffer or UTF-8 string via stdin pipe. */
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

  /** Stream-encrypts a Buffer into a `WILS` v2 container using a raw 256-bit hex key via stdio pipes. */
  encryptBuffer(keyHex, plaintext, aad = "") {
    const buf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
    const args = ["encrypt-file", "--key", keyHex, "--in", "-", "--out", "-"];
    if (aad) args.push("--aad", aad);
    return this._exec(args, buf);
  }

  /** Authenticates and decrypts a `WILS` v1/v2 container Buffer using a raw 256-bit hex key via stdio pipes. */
  decryptBuffer(keyHex, container, aad = "") {
    const buf = Buffer.isBuffer(container) ? container : Buffer.from(container);
    const args = ["decrypt-file", "--key", keyHex, "--in", "-", "--out", "-"];
    if (aad) args.push("--aad", aad);
    return this._exec(args, buf);
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

  /** Runs the 8-part scientific cryptanalysis & timing audit and returns the report text. */
  audit() {
    return this._exec(["audit"]).toString("utf8");
  }
}

export default WilisClient;
