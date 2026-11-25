import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { WilisClient } from "./wilis.mjs";

const w = new WilisClient();
const key = w.randomHex(32);
assert.equal(key.length, 64);

const msg = Buffer.from("Hello from Wilis v0.7.0 Node.js ESM SDK!");
const h1 = w.hash256(msg);
assert.equal(h1.length, 64);
assert.equal(h1, w.hash256(msg));

const tag = w.mac256(key, msg);
assert.equal(w.macVerify(key, tag, msg), true);
assert.equal(w.macVerify(key, tag, "tampered"), false);

const enc = w.encryptBuffer(key, msg, "node-aad");
const dec = w.decryptBuffer(key, enc, "node-aad");
assert.deepEqual(dec, msg);

const phrase = w.encodeMnemonic(key);
assert.equal(phrase.split(/\s+/).length, 34);
assert.equal(w.decodeMnemonic(phrase), key);

const shares = w.splitKey(key, 5, 3);
assert.equal(shares.length, 5);
assert.equal(w.combineKey(shares.slice(0, 3)), key);

const tmp = WilisClient.makeTempDir();
try {
  const { pkPath, skPath } = w.kemKeygen(path.join(tmp, "alice"));
  const plainFile = path.join(tmp, "msg.bin");
  const encFile = path.join(tmp, "msg.wpke");
  const outFile = path.join(tmp, "out.bin");
  fs.writeFileSync(plainFile, msg);
  w.pubEncrypt(pkPath, plainFile, encFile, { aad: "pq-node", armor: true });
  w.pubDecrypt(skPath, encFile, outFile, { aad: "pq-node" });
  assert.deepEqual(fs.readFileSync(outFile), msg);

  const slh = w.slhKeygen(path.join(tmp, "dev"));
  const sigFile = path.join(tmp, "msg.wlsg");
  w.slhSign(slh.skPath, plainFile, sigFile, { armor: true });
  assert.equal(w.slhVerify(slh.pkPath, plainFile, sigFile), true);

  const info = w.inspect(encFile);
  assert.ok(info.includes("WPKE"));
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log("Node.js ESM SDK v0.7.0 (Hash + MAC + AEAD Pipe + KEM + SLH + Mnemonic + Shamir + Inspect): PASS");
