/**
 * 一致性交叉验证 · JavaScript 端
 * ---------------------------------------------------------------------
 * 用途：证明网页版（bdef-core.js）与 Python 版（bdef_core.py）产出的
 *       结果完全一致 —— 编码表、密钥派生、多对多密文、AES 密文互通。
 *
 * 用法：
 *   node tools/cross_check.js            # 生成 _js_out.json
 *   然后运行 python tools/cross_check.py # 双向比对
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const BDEF = require(path.join(ROOT, "bdef-core.js"));

/* 载入码书（codebook.js 是给浏览器用的，这里用函数沙箱跑一遍） */
const codeSrc = fs.readFileSync(path.join(ROOT, "codebook.js"), "utf8");
const sandbox = {};
new Function("window", codeSrc)(sandbox);

const cb = BDEF.Codebook.fromText(sandbox.BDEF_CODEBOOK, sandbox.BDEF_CODEBOOK_GROUPS);
const codec = new BDEF.Codec(cb);

/* 确定性随机源（与 Python 端的实现逐位对应） */
function lcg(seed) {
  let s = seed >>> 0;
  return function () {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    return s / 4294967296;
  };
}

const SEED = 20261001;
const SAMPLE_KEYS = ["wo-de-mi-yao-2026", "密钥key-1", "a".repeat(64), "🔐emoji密钥"];
/* 测试文本必须全部落在码书覆盖范围内（否则会被跳过，导致往返不等） */
const TEXT = "中国剩余定理 CRT 30030 가나다 Русский タイ語 ①②③ ±∞ 你好，世界！";

const out = {
  codebookSize: cb.size(),
  text: TEXT,
  encodeCode: {},
  deriveKey: {},
  multi: {},
  aes: {}
};

for (let n = 1; n <= BDEF.TOTAL; n++) out.encodeCode[n] = BDEF.encodeCode(n);
for (const k of SAMPLE_KEYS) {
  const d = BDEF.deriveKey(k);
  out.deriveKey[k] = [d.a, d.b];
  out.multi[k] = new BDEF.Codec(cb, lcg(SEED)).encode(TEXT, k).text;
}

(async function () {
  const res = await codec.encryptFull(TEXT, "cross-check-key");
  out.aes.token = res.text;                 // Base64 字符串
  out.aes.missing = res.missing;
  // 同时给出 Python 端要解的多对多密文（含噪声组）
  out.multiForPython = out.multi["密钥key-1"];
  fs.writeFileSync(path.join(__dirname, "_js_out.json"),
                   JSON.stringify(out), "utf8");
  console.log("JS 端完成：码书 %d 条，已写出 tools/_js_out.json", cb.size());
})().catch(function (e) {
  console.error("JS 端失败：", e);
  process.exit(1);
});
