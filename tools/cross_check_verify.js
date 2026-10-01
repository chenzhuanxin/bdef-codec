/**
 * 一致性交叉验证 · JS 反向验证（由 cross_check.py 调用）
 * ---------------------------------------------------------------------
 * 读取 Python 端产出的 tools/_py_out.json，验证：
 *   1. JS 能解开 Python 的 AES-256-GCM 密文
 *   2. JS 与 Python 的多对多密文逐字符相同
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const BDEF = require(path.join(ROOT, "bdef-core.js"));

const codeSrc = fs.readFileSync(path.join(ROOT, "codebook.js"), "utf8");
const sandbox = {};
new Function("window", codeSrc)(sandbox);

const cb = BDEF.Codebook.fromText(sandbox.BDEF_CODEBOOK, sandbox.BDEF_CODEBOOK_GROUPS);
const codec = new BDEF.Codec(cb);

function lcg(seed) {
  let s = seed >>> 0;
  return function () {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    return s / 4294967296;
  };
}
const SEED = 20261001;

(async function () {
  const py = JSON.parse(fs.readFileSync(path.join(__dirname, "_py_out.json"), "utf8"));
  let ok = true;

  // 1. 解开 Python 的 AES 密文
  try {
    const got = await codec.decryptFull(py.aes.token, py.aesKey);
    const good = (got === py.aesPlaintext);
    ok = ok && good;
    console.log("[6a] JS 解开 Python 的 AES 密文：%s", good ? "通过" : "失败");
    if (!good) console.log("     期望 %j\n     实际 %j", py.aesPlaintext, got);
  } catch (e) {
    ok = false;
    console.log("[6a] JS 解开 Python 的 AES 密文：失败 -> %s", e.message);
  }

  // 2. 多对多密文逐字符对比
  let bad = 0;
  for (const key of Object.keys(py.multi)) {
    const mine = new BDEF.Codec(cb, lcg(SEED)).encode(py.aesPlaintext, key).text;
    if (mine !== py.multi[key]) {
      bad++;
      console.log("     密钥 %j 密文不一致", key);
    }
  }
  ok = ok && (bad === 0);
  console.log("[6b] JS 与 Python 的多对多密文逐字符一致：%s", bad === 0 ? "通过" : "失败");

  console.log("\n%s", ok ? "JS 反向验证：全部通过 ✅" : "JS 反向验证：存在不一致 ❌");
  process.exit(ok ? 0 : 1);
})().catch(function (e) {
  console.error("JS 反向验证失败：", e);
  process.exit(1);
});
