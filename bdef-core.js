/*!
 * BDEF 编码法 · 核心算法（JavaScript）
 * =====================================================================
 * 中国剩余定理字符编码：11 × 13 × 14 × 15 = 30030
 *
 * 本文件不依赖任何 DOM，浏览器（挂到 window.BDEF）与 Node.js（module.exports）
 * 均可使用，方便与 Python 端 bdef_core.py 做一致性验证。
 *
 * 三种模式：
 *   basic  纯编码，无密钥
 *   multi  密钥派生的模 30030 可逆线性变换 + 随机 IV + 链式混淆 + 噪声组
 *   aes    多对多编码后再叠加 AES-256-GCM（PBKDF2-SHA256 派生密钥）
 */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.BDEF = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /* ================= 常量 ================= */
  var MODS = [11, 13, 14, 15];
  var TOTAL = 30030;
  var SEP = "-";
  var NOISE = "~";
  var NOISE_RATE = 0.30;
  var AES_ITER = 100000;
  var SALT_LEN = 16;
  var IV_LEN = 12;
  var TAG_LEN = 16;

  /* ================= 数学 ================= */
  function gcd(x, y) { while (y) { var t = x % y; x = y; y = t; } return x; }

  /** 序号 n -> 4 位十六进制编码（四个余数依次拼接） */
  function encodeCode(n) {
    var s = "";
    for (var i = 0; i < MODS.length; i++) s += (n % MODS[i]).toString(16);
    return s;
  }

  /** 4 个十六进制字符 -> 四个余数，越界返回 null */
  function splitResidues(quad) {
    if (typeof quad !== "string" || quad.length !== 4) return null;
    var out = [];
    for (var i = 0; i < 4; i++) {
      var v = parseInt(quad.charAt(i), 16);
      if (Number.isNaN(v) || v >= MODS[i]) return null;
      out.push(v);
    }
    return out;
  }

  /** 中国剩余定理：由四个余数还原 0 … 30029 */
  function crt(r) {
    var x = r[0] % MODS[0];
    var mod = MODS[0];
    for (var i = 1; i < MODS.length; i++) {
      var n = MODS[i], guard = 0;
      while ((x % n) !== r[i]) {
        x += mod;
        if (++guard > n) return -1;
      }
      mod *= n;
    }
    return x;
  }

  /** 32 位 FNV-1a 哈希（按 UTF-16 码元迭代） */
  function fnv1a(str, seed) {
    var h = seed >>> 0;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h;
  }

  /** 由密钥字符串推导 (a, b)，a 与 30030 互质 */
  function deriveKey(keyStr) {
    var h1 = fnv1a(keyStr + "\u0001", 0x811c9dc5);
    var h2 = fnv1a(keyStr + "\u0002", 0xcbf29ce4);
    var a = h1 % TOTAL;
    if (a === 0) a = 1;
    var guard = 0;
    while (gcd(a, TOTAL) !== 1 && guard++ < TOTAL) {
      a = (a + 1) % TOTAL;
      if (a === 0) a = 1;
    }
    return { a: a, b: h2 % TOTAL };
  }

  /** 扩展欧几里得求模逆元 */
  function modInverse(a, m) {
    var oldR = ((a % m) + m) % m, r = m, oldS = 1, s = 0;
    while (r !== 0) {
      var q = Math.floor(oldR / r), t;
      t = oldR - q * r; oldR = r; r = t;
      t = oldS - q * s; oldS = s; s = t;
    }
    if (oldR !== 1) return null;
    return ((oldS % m) + m) % m;
  }

  /* ================= 码书 ================= */
  var PREFIX_RE = /^\s*(?:明文|密文|原文|口令|plain|text|cipher)\s*[:：]\s*/i;

  function Codebook(chars, groups) {
    this.chars = chars.slice();
    this.groups = groups || [];
    this._map = new Map();
    for (var i = 0; i < this.chars.length; i++) {
      if (!this._map.has(this.chars[i])) this._map.set(this.chars[i], i + 1);
    }
    this._cat = null;
  }

  Codebook.fromText = function (text, groups) {
    return new Codebook(Array.from(String(text || "")), groups);
  };

  /** 读取码书 txt（`编码<TAB>字符<TAB>...`，也兼容纯字符逐行） */
  Codebook.fromTxt = function (txt) {
    var table = {}, plain = [];
    String(txt).split(/\r?\n/).forEach(function (line) {
      if (!line.trim() || line.charAt(0) === "#") return;
      if (line.indexOf("\t") >= 0) {
        var parts = line.split("\t");
        var head = (parts[0] || "").trim();
        if (/^\d+$/.test(head) && parts[1]) { table[Number(head)] = Array.from(parts[1])[0]; return; }
      }
      var ch = line.trim();
      if (ch) plain.push(Array.from(ch)[0]);
    });
    var keys = Object.keys(table);
    if (keys.length) {
      var size = Math.max.apply(null, keys.map(Number));
      var arr = [];
      for (var i = 1; i <= size; i++) arr.push(table[i] || "\uFFFD");
      return new Codebook(arr, []);
    }
    return new Codebook(plain, []);
  };

  Codebook.prototype.size = function () { return this.chars.length; };
  Codebook.prototype.codeOf = function (ch) {
    var v = this._map.get(ch);
    return v === undefined ? null : v;
  };
  Codebook.prototype.charOf = function (n) {
    return (n >= 1 && n <= this.chars.length) ? this.chars[n - 1] : null;
  };
  /** 第 n 个字符所属类别（由分组信息推算） */
  Codebook.prototype.categoryOf = function (n) {
    if (!this._cat) {
      var arr = new Array(this.chars.length).fill("未知"), p = 0;
      for (var i = 0; i < this.groups.length; i++) {
        var name = this.groups[i][0], cnt = this.groups[i][1];
        for (var k = 0; k < cnt && p + k < arr.length; k++) arr[p + k] = name;
        p += cnt;
      }
      this._cat = arr;
    }
    return this._cat[n - 1] || "未知";
  };

  /* ================= 文本清洗 ================= */
  function cleanGroups(cipher) {
    var t = String(cipher == null ? "" : cipher).replace(PREFIX_RE, "");
    t = t.replace(/\s+/g, "").replace(/[\u2010-\u2015\u2212]/g, "-");
    t = t.replace(/^-+/, "").replace(/-+$/, "");
    if (!t) return [];
    return t.split(SEP).filter(function (g) { return g !== ""; });
  }

  function extractQuads(cipher) {
    var t = String(cipher == null ? "" : cipher).replace(PREFIX_RE, "");
    t = t.replace(/[\s\-]+/g, "").toLowerCase();
    if (!t) return [];
    if (t.length % 4 !== 0) {
      throw new Error("密文长度为 " + t.length + "，不是 4 的倍数，无法按 4 位分组");
    }
    var out = [];
    for (var i = 0; i < t.length; i += 4) out.push(t.substr(i, 4));
    return out;
  }

  function groupValue(group) {
    var r = splitResidues(group);
    if (r === null) throw new Error("分组 “" + group + "” 含非法余数或长度不为 4");
    var n = crt(r);
    if (n < 0) throw new Error("分组 “" + group + "” 无法还原");
    return n;
  }

  /* ================= Codec ================= */
  function Codec(codebook, rng) {
    this.cb = codebook;
    this.rng = rng || Math.random;
  }

  /* ---- 基础模式 ---- */
  Codec.prototype.encodeBasic = function (plain) {
    var groups = [], missing = [];
    for (var i = 0; i < plain.length; i++) {
      var code = this.cb.codeOf(plain.charAt(i));
      if (code === null) { missing.push(plain.charAt(i)); continue; }
      groups.push(encodeCode(code));
    }
    return { text: groups.join(SEP), missing: missing, groups: groups.length };
  };

  Codec.prototype.decodeBasic = function (cipher) {
    var quads = extractQuads(cipher), out = "";
    for (var i = 0; i < quads.length; i++) {
      var r = splitResidues(quads[i]);
      if (r === null) throw new Error("第 " + (i + 1) + " 组 “" + quads[i] + "” 不是合法编码（余数越界或含非法字符）");
      var n = crt(r);
      if (n < 0) throw new Error("第 " + (i + 1) + " 组 “" + quads[i] + "” 无法用中国剩余定理还原");
      if (n === 0) n = TOTAL;
      if (n > this.cb.size()) throw new Error("编码 " + n + " 超出码书范围（当前 " + this.cb.size() + " 条）");
      out += this.cb.chars[n - 1];
    }
    return out;
  };

  /* ---- 多对多模式 ---- */
  Codec.prototype.encode = function (plain, keyStr, noiseRate) {
    if (noiseRate === undefined) noiseRate = NOISE_RATE;
    var k = deriveKey(String(keyStr == null ? "" : keyStr));
    var iv = Math.floor(this.rng() * TOTAL);
    var groups = [encodeCode(iv)];
    var prev = iv, missing = [], dataGroups = 0;
    for (var i = 0; i < plain.length; i++) {
      var ch = plain.charAt(i);
      var code = this.cb.codeOf(ch);
      if (code === null) { missing.push(ch); continue; }
      var n = code % TOTAL;
      var chained = (n + prev) % TOTAL;
      var transformed = (k.a * chained + k.b) % TOTAL;
      prev = transformed;
      groups.push(encodeCode(transformed));
      dataGroups++;
      if (noiseRate > 0 && this.rng() < noiseRate) {
        groups.push(NOISE + encodeCode(Math.floor(this.rng() * TOTAL)));
      }
    }
    return { text: groups.join(SEP), missing: missing, groups: dataGroups };
  };

  Codec.prototype.decode = function (cipher, keyStr) {
    var k = deriveKey(String(keyStr == null ? "" : keyStr));
    var aInv = modInverse(k.a, TOTAL);
    if (aInv === null) throw new Error("密钥派生的参数不可逆，无法解密");

    var parts = cleanGroups(cipher);
    if (!parts.length) return "";

    var idx = 0;
    while (idx < parts.length && parts[idx].charAt(0) === NOISE) idx++;
    if (idx >= parts.length) throw new Error("密文缺少初始向量（IV）");
    var prev = groupValue(parts[idx]);
    idx++;

    var out = "";
    for (; idx < parts.length; idx++) {
      var g = parts[idx];
      if (g.charAt(0) === NOISE) continue;
      var t = groupValue(g);
      var chained = (((aInv * (t - k.b)) % TOTAL) + TOTAL) % TOTAL;
      var n = (chained - prev) % TOTAL;
      if (n < 0) n += TOTAL;
      prev = t;
      if (n === 0) n = TOTAL;
      if (n > this.cb.size()) throw new Error("编码 " + n + " 超出码书范围：密钥可能不正确");
      out += this.cb.chars[n - 1];
    }
    return out;
  };

  /* ---- AES 模式 ---- */
  var hasSubtle = !!(typeof globalThis !== "undefined" && globalThis.crypto &&
                     globalThis.crypto.subtle);

  function b64FromBytes(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }
  function bytesFromB64(b64) {
    var bin = atob(String(b64).replace(/\s+/g, ""));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function deriveAesKey(keyStr, salt, iterations) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey("raw", enc.encode(keyStr), "PBKDF2", false, ["deriveKey"])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: iterations || AES_ITER, hash: "SHA-256" },
          baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      });
  }

  function aesEncrypt(plainText, keyStr, iterations) {
    var enc = new TextEncoder();
    var salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    var iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    return deriveAesKey(keyStr, salt, iterations).then(function (key) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc.encode(plainText));
    }).then(function (buf) {
      var ct = new Uint8Array(buf);
      var out = new Uint8Array(SALT_LEN + IV_LEN + ct.length);
      out.set(salt, 0); out.set(iv, SALT_LEN); out.set(ct, SALT_LEN + IV_LEN);
      return b64FromBytes(out);
    });
  }

  function aesDecrypt(b64, keyStr, iterations) {
    var raw = bytesFromB64(b64);
    if (raw.length < SALT_LEN + IV_LEN + TAG_LEN) {
      return Promise.reject(new Error("密文长度不足，不是有效的 AES 封装数据"));
    }
    var salt = raw.slice(0, SALT_LEN);
    var iv = raw.slice(SALT_LEN, SALT_LEN + IV_LEN);
    var ct = raw.slice(SALT_LEN + IV_LEN);
    return deriveAesKey(keyStr, salt, iterations).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
    }).then(function (buf) {
      return new TextDecoder().decode(buf);
    });
  }

  Codec.prototype.encryptFull = function (plain, keyStr, iterations) {
    var inner = this.encode(plain, keyStr);
    if (!inner.text) return Promise.resolve(inner);
    return aesEncrypt(inner.text, keyStr, iterations).then(function (token) {
      return { text: token, missing: inner.missing, groups: inner.groups };
    });
  };

  Codec.prototype.decryptFull = function (token, keyStr, iterations) {
    var self = this;
    return aesDecrypt(String(token).trim(), keyStr, iterations).then(function (inner) {
      return self.decode(inner, keyStr);
    });
  };

  /** 密文分组统计 */
  Codec.prototype.stats = function (cipher, mode) {
    if (mode === "aes") {
      return { groups: 0, noise: 0, chars: String(cipher || "").replace(/\s+/g, "").length };
    }
    var groups = cleanGroups(cipher);
    var noise = 0;
    for (var i = 0; i < groups.length; i++) if (groups[i].charAt(0) === NOISE) noise++;
    var data = mode === "multi"
      ? Math.max(0, groups.length - noise - (groups.length ? 1 : 0))
      : groups.length;
    return { groups: data, noise: noise, chars: 0 };
  };

  return {
    MODS: MODS, TOTAL: TOTAL, SEP: SEP, NOISE: NOISE, NOISE_RATE: NOISE_RATE,
    AES_ITER: AES_ITER, SALT_LEN: SALT_LEN, IV_LEN: IV_LEN, TAG_LEN: TAG_LEN,
    gcd: gcd, encodeCode: encodeCode, splitResidues: splitResidues, crt: crt,
    fnv1a: fnv1a, deriveKey: deriveKey, modInverse: modInverse,
    cleanGroups: cleanGroups, extractQuads: extractQuads,
    Codebook: Codebook, Codec: Codec,
    aes: { hasSubtle: hasSubtle, encrypt: aesEncrypt, decrypt: aesDecrypt, deriveKey: deriveAesKey },
    /** 用全局变量里的码书建一个 Codec（浏览器场景一行搞定） */
    fromGlobals: function () {
      var g = globalThis;
      var text = typeof g.BDEF_CODEBOOK === "string" ? g.BDEF_CODEBOOK : "";
      var groups = Array.isArray(g.BDEF_CODEBOOK_GROUPS) ? g.BDEF_CODEBOOK_GROUPS : [];
      return new Codec(Codebook.fromText(text, groups));
    }
  };
});
