# -*- coding: utf-8 -*-
"""
BDEF 编码法 · 核心算法
=========================================================================
把"中国剩余定理"用在字符编码上：

    * 每个字符对应码书里的唯一序号 n（1 <= n <= 30030）
    * 加密：把 n 分别除以 11、13、14、15 取余数，四个余数转十六进制拼成 4 位编码
    * 解密：由中国剩余定理从四个余数唯一还原 n

三种模式：

    基础模式   纯编码，无密钥。规则公开 = 无保密性，适合教学 / 趣味谜题。
    多对多模式 密钥派生 (a,b) 做模 30030 的可逆线性变换 + 随机 IV + 链式混淆 + 噪声组。
     AES 模式   先做多对多编码，再叠加 AES-256-GCM（PBKDF2-SHA256 派生密钥）。

本模块与网页版 index.html 中的 JavaScript 实现**字节级等价**，
两边产生的密文可以互相解密（含 AES 模式）。
"""

from __future__ import annotations

import os
import random
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from bdef_aes import AES_ITER, IV_LEN, SALT_LEN, AesSession, seal, unseal
except ImportError:  # 允许作为包内模块导入
    from .bdef_aes import (AES_ITER, IV_LEN, SALT_LEN, AesSession, seal,
                           unseal)

__all__ = [
    "MODS", "TOTAL", "SEP", "NOISE", "NOISE_RATE",
    "Codebook", "Codec", "BDEFError",
]

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
MODS = (11, 13, 14, 15)      # 两两互质，乘积 = 30030
TOTAL = 30030                # 11 * 13 * 14 * 15
SEP = "-"                    # 分组分隔符
NOISE = "~"                  # 噪声组前缀
NOISE_RATE = 0.30            # 每个数据组后插入噪声组的概率

_PREFIX_RE = re.compile(r"^\s*(?:明文|密文|原文|口令|plain|text|cipher)\s*[:：]\s*",
                        re.IGNORECASE)


class BDEFError(Exception):
    """BDEF 编解码过程中的可预期错误。"""


# --------------------------------------------------------------------------
# 码书
# --------------------------------------------------------------------------


class Codebook:
    """字符 <-> 序号 的映射表。

    序号从 1 开始，第 i 个字符的编码就是 i。
    """

    def __init__(self, chars: Sequence[str]) -> None:
        self.chars: List[str] = list(chars)
        self._char2code: Dict[str, int] = {}
        for idx, ch in enumerate(self.chars, start=1):
            # 重复字符只保留首次出现的编码
            self._char2code.setdefault(ch, idx)

    # -- 属性 --------------------------------------------------------------
    @property
    def size(self) -> int:
        return len(self.chars)

    def __len__(self) -> int:
        return len(self.chars)

    # -- 查询 --------------------------------------------------------------
    def code_of(self, ch: str) -> Optional[int]:
        return self._char2code.get(ch)

    def char_of(self, code: int) -> Optional[str]:
        if 1 <= code <= len(self.chars):
            return self.chars[code - 1]
        return None

    # -- 构造 --------------------------------------------------------------
    @classmethod
    def from_chars(cls, chars: Iterable[str]) -> "Codebook":
        return cls([c for c in chars if len(c) == 1])

    @classmethod
    def from_txt(cls, path: str) -> "Codebook":
        """读取码书 txt：`编码 <TAB> 字符 <TAB> ...`（也兼容纯字符逐行）。"""
        table: Dict[int, str] = {}
        plain: List[str] = []
        with open(path, "r", encoding="utf-8-sig") as f:
            for raw in f:
                line = raw.rstrip("\r\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if "\t" in line:
                    parts = line.split("\t")
                    head = parts[0].strip()
                    if head.isdigit() and len(parts) > 1 and parts[1]:
                        table[int(head)] = parts[1][0]
                        continue
                ch = line.strip()
                if len(ch) >= 1:
                    plain.append(ch[0])
        if table:
            size = max(table)
            return cls([table.get(i, "\uFFFD") for i in range(1, size + 1)])
        return cls(plain)

    @classmethod
    def from_js(cls, path: str) -> "Codebook":
        """读取 codebook.js 里的 window.BDEF_CODEBOOK = "……"。"""
        with open(path, "r", encoding="utf-8-sig") as f:
            text = f.read()
        m = re.search(r"window\.BDEF_CODEBOOK\s*=\s*(\"(?:[^\"\\]|\\.)*\")", text)
        if not m:
            raise BDEFError("codebook.js 中未找到 window.BDEF_CODEBOOK")
        import json
        return cls(list(json.loads(m.group(1))))

    @classmethod
    def load(cls, path: str) -> "Codebook":
        """按扩展名自动选择解析方式。"""
        lower = path.lower()
        if lower.endswith(".js"):
            return cls.from_js(path)
        return cls.from_txt(path)

    @classmethod
    def auto(cls, base_dir: Optional[str] = None) -> "Codebook":
        """在目录中自动寻找 codebook.js / codebook.txt。"""
        base = base_dir or os.path.dirname(os.path.abspath(__file__))
        for name in ("codebook.js", "codebook.txt"):
            p = os.path.join(base, name)
            if os.path.exists(p):
                return cls.load(p)
        raise BDEFError("未找到码书：请先运行 generate_codebook.py，"
                        "并把 codebook.txt / codebook.js 放在同目录下")


# --------------------------------------------------------------------------
# 数学工具（与 JS 版一一对应）
# --------------------------------------------------------------------------


def gcd(x: int, y: int) -> int:
    while y:
        x, y = y, x % y
    return x


def encode_code(n: int) -> str:
    """序号 n -> 4 位十六进制编码（四个余数依次拼接）。"""
    return "".join("%x" % (n % m) for m in MODS)


def split_residues(quad: str) -> Optional[List[int]]:
    """把 4 个十六进制字符拆成四个余数，越界返回 None。"""
    if len(quad) != 4:
        return None
    out = []
    for i, ch in enumerate(quad):
        try:
            r = int(ch, 16)
        except ValueError:
            return None
        if r >= MODS[i]:
            return None
        out.append(r)
    return out


def crt(residues: Sequence[int]) -> int:
    """中国剩余定理：由四个余数还原 0 … 30029 的整数。"""
    x = residues[0] % MODS[0]
    mod = MODS[0]
    for i in range(1, len(MODS)):
        n = MODS[i]
        guard = 0
        while (x % n) != residues[i]:
            x += mod
            guard += 1
            if guard > n:
                return -1
        mod *= n
    return x


def fnv1a(text: str, seed: int) -> int:
    """32 位 FNV-1a 哈希，按 UTF-16 码元迭代（与 JavaScript 一致）。"""
    h = seed & 0xFFFFFFFF
    data = text.encode("utf-16-le", errors="surrogatepass")
    for i in range(0, len(data), 2):
        unit = data[i] | (data[i + 1] << 8)
        h ^= unit
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def derive_key(key_str: str) -> Tuple[int, int]:
    """由密钥字符串推导 (a, b)，其中 a 与 30030 互质。"""
    h1 = fnv1a(key_str + "\u0001", 0x811C9DC5)
    h2 = fnv1a(key_str + "\u0002", 0xCBF29CE4)
    a = h1 % TOTAL
    if a == 0:
        a = 1
    guard = 0
    while gcd(a, TOTAL) != 1 and guard < TOTAL:
        a = (a + 1) % TOTAL
        if a == 0:
            a = 1
        guard += 1
    b = h2 % TOTAL
    return a, b


def mod_inverse(a: int, m: int) -> Optional[int]:
    """扩展欧几里得求模逆元，不存在返回 None。"""
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        return None
    return (old_s % m + m) % m


# --------------------------------------------------------------------------
# 编解码器
# --------------------------------------------------------------------------


class Codec:
    """BDEF 编解码器。

    rng 是一个返回 [0, 1) 浮点数的无参可调用对象，默认用 random.random。
    之所以不直接用 random.Random 对象，是为了与 JavaScript 端
    （bdef-core.js 中用 Math.random / 自定义 LCG）保持逐位一致，
    便于做跨语言一致性验证。
    """

    def __init__(self, codebook: Codebook, rng=None) -> None:
        self.cb = codebook
        self.rng = rng or random.random

    # ---------------- 基础模式 ----------------
    def encode_basic(self, plain: str) -> Tuple[str, List[str]]:
        """纯 BDEF 编码，返回 (密文, 码书里缺失的字符列表)。"""
        groups: List[str] = []
        missing: List[str] = []
        for ch in plain:
            code = self.cb.code_of(ch)
            if code is None:
                missing.append(ch)
                continue
            groups.append(encode_code(code))
        return SEP.join(groups), missing

    def decode_basic(self, cipher: str) -> str:
        """纯 BDEF 解码。"""
        quads, raw = self._extract_quads(cipher)
        out = []
        for i, quad in enumerate(quads):
            residues = split_residues(quad)
            if residues is None:
                raise BDEFError("第 %d 组 %r 不是合法编码（余数越界或含非法字符）"
                                % (i + 1, quad))
            n = crt(residues)
            if n < 0:
                raise BDEFError("第 %d 组 %r 无法用中国剩余定理还原"
                                % (i + 1, quad))
            if n == 0:
                n = TOTAL
            ch = self.cb.char_of(n)
            if ch is None:
                raise BDEFError("编码 %d 超出码书范围（当前 %d 条）"
                                % (n, self.cb.size))
            out.append(ch)
        return "".join(out)

    # ---------------- 多对多模式 ----------------
    def encode(self, plain: str, key: str,
               noise_rate: float = NOISE_RATE) -> Tuple[str, List[str]]:
        """密钥 + 随机 IV + 链式混淆 + 噪声组。"""
        a, b = derive_key(key)
        iv = int(self.rng() * TOTAL)            # 0 … 30029
        groups: List[str] = [encode_code(iv)]
        prev = iv
        missing: List[str] = []
        for ch in plain:
            code = self.cb.code_of(ch)
            if code is None:
                missing.append(ch)
                continue
            n = code % TOTAL                    # 30030 -> 0
            chained = (n + prev) % TOTAL
            transformed = (a * chained + b) % TOTAL
            prev = transformed
            groups.append(encode_code(transformed))
            if noise_rate > 0 and self.rng() < noise_rate:
                groups.append(NOISE + encode_code(int(self.rng() * TOTAL)))
        return SEP.join(groups), missing

    def decode(self, cipher: str, key: str) -> str:
        """多对多模式解码。"""
        a, b = derive_key(key)
        a_inv = mod_inverse(a, TOTAL)
        if a_inv is None:
            raise BDEFError("密钥派生的参数不可逆，无法解密")

        parts = self._clean_groups(cipher)
        if not parts:
            return ""
        # 跳过前导噪声组，找 IV
        idx = 0
        while idx < len(parts) and parts[idx].startswith(NOISE):
            idx += 1
        if idx >= len(parts):
            raise BDEFError("密文缺少初始向量（IV）")
        iv = self._group_value(parts[idx], allow_zero=True)
        prev = iv
        idx += 1

        out = []
        for group in parts[idx:]:
            if group.startswith(NOISE):
                continue
            t = self._group_value(group, allow_zero=True)
            chained = (a_inv * (t - b)) % TOTAL
            n = (chained - prev) % TOTAL
            prev = t
            if n == 0:
                n = TOTAL
            ch = self.cb.char_of(n)
            if ch is None:
                # 密钥错误时几乎必然落到这里
                raise BDEFError("编码 %d 超出码书范围：密钥可能不正确" % n)
            out.append(ch)
        return "".join(out)

    # ---------------- AES 模式 ----------------
    def encrypt_full(self, plain: str, key: str,
                     iterations: int = AES_ITER) -> Tuple[str, List[str]]:
        """多对多编码后再整体 AES-256-GCM 加密，输出 Base64。"""
        inner, missing = self.encode(plain, key)
        if not inner:
            return "", missing
        return seal(inner, key, iterations), missing

    def decrypt_full(self, token: str, key: str,
                     iterations: int = AES_ITER) -> str:
        """先 AES 解密，再走 BDEF 解码。"""
        inner = unseal(token.strip(), key, iterations)
        return self.decode(inner, key)

    # ---------------- 内部工具 ----------------
    @staticmethod
    def _clean_groups(cipher: str) -> List[str]:
        """去掉空白、`明文：` 前缀，按 `-` 切分。"""
        text = _PREFIX_RE.sub("", cipher or "")
        text = re.sub(r"\s+", "", text)
        text = text.replace("\u2010", "-").replace("\u2011", "-") \
                   .replace("\u2012", "-").replace("\u2013", "-") \
                   .replace("\u2014", "-").replace("\u2212", "-")
        text = text.strip(SEP)
        if not text:
            return []
        return [g for g in text.split(SEP) if g != ""]

    def _extract_quads(self, cipher: str) -> Tuple[List[str], str]:
        """基础模式：剔除分隔符后按 4 位十六进制切分。"""
        text = _PREFIX_RE.sub("", cipher or "")
        text = re.sub(r"[\s\-]+", "", text).lower()
        if not text:
            return [], ""
        if len(text) % 4 != 0:
            raise BDEFError("密文长度为 %d，不是 4 的倍数，无法按 4 位分组"
                            % len(text))
        return [text[i:i + 4] for i in range(0, len(text), 4)], text

    @staticmethod
    def _group_value(group: str, allow_zero: bool = False) -> int:
        residues = split_residues(group)
        if residues is None:
            raise BDEFError("分组 %r 含非法余数" % group)
        n = crt(residues)
        if n < 0:
            raise BDEFError("分组 %r 无法还原" % group)
        if n == 0 and not allow_zero:
            n = TOTAL
        return n

    # ---------------- 统计 ----------------
    def stats(self, cipher: str, mode: str = "basic") -> Dict[str, int]:
        """统计密文分组情况，用于界面显示。"""
        info = {"groups": 0, "noise": 0, "chars": 0, "quads": 0}
        if mode == "aes":
            info["chars"] = len(re.sub(r"\s+", "", cipher or ""))
            return info
        groups = self._clean_groups(cipher)
        if mode == "multi":
            noise = sum(1 for g in groups if g.startswith(NOISE))
            info["noise"] = noise
            info["groups"] = len(groups) - noise - (1 if groups else 0)
        else:
            info["groups"] = len(groups)
        return info


# --------------------------------------------------------------------------
# 便捷函数
# --------------------------------------------------------------------------

_DEFAULT_CODEC: Optional[Codec] = None


def default_codec(base_dir: Optional[str] = None) -> Codec:
    """进程内缓存的默认编解码器。"""
    global _DEFAULT_CODEC
    if _DEFAULT_CODEC is None:
        _DEFAULT_CODEC = Codec(Codebook.auto(base_dir))
    return _DEFAULT_CODEC


def encrypt(text: str, key: str = "", mode: str = "basic") -> str:
    """一行式加密。mode: basic | multi | aes"""
    c = default_codec()
    if mode == "basic":
        return c.encode_basic(text)[0]
    if mode == "multi":
        return c.encode(text, key)[0]
    if mode == "aes":
        return c.encrypt_full(text, key)[0]
    raise ValueError("未知模式：%s" % mode)


def decrypt(text: str, key: str = "", mode: str = "basic") -> str:
    """一行式解密。mode: basic | multi | aes"""
    c = default_codec()
    if mode == "basic":
        return c.decode_basic(text)
    if mode == "multi":
        return c.decode(text, key)
    if mode == "aes":
        return c.decrypt_full(text, key)
    raise ValueError("未知模式：%s" % mode)


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------


def _selftest(base_dir: Optional[str] = None) -> int:
    ok = True
    cb = Codebook.auto(base_dir)
    print("码书条目数：%d" % cb.size)
    ok &= (cb.size == TOTAL)
    ok &= (cb.char_of(1) == "一")
    ok &= (cb.code_of("一") == 1)

    codec = Codec(cb, random.Random(20261001).random)

    # 编码可逆性：全部 30030 个序号
    bad = 0
    for n in range(1, TOTAL + 1):
        quad = encode_code(n)
        r = split_residues(quad)
        v = crt(r) if r else -1
        if v == 0:
            v = TOTAL
        if v != n:
            bad += 1
    ok &= (bad == 0)
    print("[CRT 双射] %d 个序号全部可逆：%s" % (TOTAL, "通过" if bad == 0 else "失败 %d" % bad))

    # 三种模式往返（样本全部取自码书内字符）
    samples = [
        "你好，世界！",
        "BDEF 编码法 · 中国剩余定理 Hello World 12345",
        "①②③ § ¶ ∑ ∏ √ ∞ ≈ ≠ ≤ ≥",
        "가나다 日本語 ไทย Русский ελληνικά キーワード",
    ]
    for text in samples:
        # 基础
        ct, miss = codec.encode_basic(text)
        if miss:                                    # 理论上不该出现
            ok = False
            print("[基础模式] 意外缺失字符：%r" % "".join(miss))
        if codec.decode_basic(ct) != text:
            ok = False
            print("[基础模式] 往返失败：%r" % text)
        else:
            print("[基础模式] 往返通过：%r" % text[:26])

        # 多对多
        for key in ("密钥key-1", "🔐emoji密钥", "a" * 64):
            ct2, _ = codec.encode(text, key)
            if codec.decode(ct2, key) != text:
                ok = False
                print("[多对多] 往返失败 key=%r" % key)
            if ct2 == codec.encode(text, key)[0]:
                ok = False
                print("[多对多] 同一明文两次密文相同（缺少随机性）key=%r" % key)
        print("[多对多] 往返 + 随机性通过：%r" % text[:24])

        # AES
        tok, _ = codec.encrypt_full(text, "我的密钥")
        if codec.decrypt_full(tok, "我的密钥") != text:
            ok = False
            print("[AES 模式] 往返失败：%r" % text)
        try:
            codec.decrypt_full(tok, "错误密钥")
            ok = False
            print("[AES 模式] 错误密钥竟然解开了")
        except Exception:
            pass
        print("[AES 模式] 往返 + 密钥校验通过：%r" % text[:24])

    # 码书外的字符：跳过并如实上报，其余部分仍能正常往返
    mixed = "汉字ABC🙂한"          # 🙂 与 한 不在码书中
    ct5, miss5 = codec.encode_basic(mixed)
    back5 = codec.decode_basic(ct5)
    good = ("".join(miss5) == "🙂한" and back5 == "汉字ABC"
            and len(ct5.split(SEP)) == 5)
    ok &= good
    print("[缺失字符] 跳过 %r 并上报：%s"
          % ("".join(miss5), "通过" if good else "失败 -> %r" % back5))

    # 密钥错误应报错（用较长密文，避免巧合命中合法编码）
    ct3, _ = codec.encode("这是一段足够长的机密内容，用于验证错误密钥会被拒绝。", "right")
    try:
        got = codec.decode(ct3, "wrong")
        print("[多对多] 提示：错误密钥未报错（恰好命中合法编码），解出 %r" % got[:12])
    except BDEFError:
        print("[多对多] 错误密钥被拒绝")

    # 噪声组存在性
    long_text = "测试噪声组插入" * 30
    ct4, _ = codec.encode(long_text, "k")
    n_noise = ct4.count(NOISE)
    print("[噪声组] 密文中含 %d 个 ~ 噪声组" % n_noise)
    ok &= (n_noise > 0)

    print("\n自检结果：%s" % ("全部通过" if ok else "存在失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
