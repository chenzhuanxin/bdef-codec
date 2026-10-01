# -*- coding: utf-8 -*-
"""
BDEF 编码法 · 纯标准库 AES-256-GCM / PBKDF2 实现
=========================================================================
本项目只依赖 Python 标准库，因此这里手写了一份 AES-256-GCM，
与浏览器 WebCrypto 的 `AES-GCM` 在字节层面完全一致：

    * 分组长度 16 字节，密钥 256 位（Nk=8，Nr=14）
    * 认证标签 tag 16 字节，附在密文之后（与 WebCrypto 输出一致）
    * 96 位（12 字节）IV，J0 = IV || 0x00000001
    * PBKDF2-HMAC-SHA256，默认 100000 次迭代，派生 32 字节密钥

自检：
    python bdef_aes.py          # 跑 NIST/GCM 官方向量 + 往返测试
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

__all__ = [
    "SALT_LEN", "IV_LEN", "TAG_LEN", "AES_ITER",
    "derive_key_pbkdf2", "aes_gcm_encrypt", "aes_gcm_decrypt",
    "seal", "unseal", "AesSession",
]

SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
AES_ITER = 100000

# --------------------------------------------------------------------------
# AES 基础表
# --------------------------------------------------------------------------

_SBOX_HEX = (
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
SBOX = bytes.fromhex(_SBOX_HEX)
assert len(SBOX) == 256, "S-box 长度错误"


def _xtime(a: int) -> int:
    """GF(2^8) 上乘 2。"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mix_column(col: "list[int]") -> "list[int]":
    a0, a1, a2, a3 = col
    t = a0 ^ a1 ^ a2 ^ a3
    return [
        a0 ^ t ^ _xtime(a0 ^ a1),
        a1 ^ t ^ _xtime(a1 ^ a2),
        a2 ^ t ^ _xtime(a2 ^ a3),
        a3 ^ t ^ _xtime(a3 ^ a0),
    ]


def _expand_key(key: bytes) -> "list[bytes]":
    """AES 密钥扩展，返回 4*(Nr+1) 个 4 字节轮密钥字。"""
    nk = len(key) // 4
    nr = nk + 6
    w = [bytearray(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = bytearray(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                    # RotWord
            for j in range(4):
                temp[j] = SBOX[temp[j]]                   # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            for j in range(4):
                temp[j] = SBOX[temp[j]]
        w.append(bytearray(w[i - nk][j] ^ temp[j] for j in range(4)))
    return [bytes(x) for x in w]


def _encrypt_block(block: bytes, key: bytes) -> bytes:
    """单个 16 字节分组的 AES 正向加密（状态按列优先存放）。"""
    w = _expand_key(key)
    nr = len(w) // 4 - 1
    s = bytearray(block)

    def add_round_key(rnd: int) -> None:
        base = 4 * rnd
        for c in range(4):
            wc = w[base + c]
            for r in range(4):
                s[4 * c + r] ^= wc[r]

    add_round_key(0)
    for rnd in range(1, nr + 1):
        for i in range(16):
            s[i] = SBOX[s[i]]                              # SubBytes
        # ShiftRows：第 r 行循环左移 r
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = s[4 * ((c + r) % 4) + r]
        s = t
        if rnd != nr:                                      # MixColumns
            for c in range(4):
                s[4 * c:4 * c + 4] = bytes(
                    _mix_column(list(s[4 * c:4 * c + 4])))
        add_round_key(rnd)
    return bytes(s)


# --------------------------------------------------------------------------
# GCM
# --------------------------------------------------------------------------

_R128 = 0xE1000000000000000000000000000000


def _gf128_mul(x: int, y: int) -> int:
    """GCM 的 GF(2^128) 乘法（位序为 GCM 约定的反序）。"""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R128
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if len(blk) < 16:
            blk = blk + b"\x00" * (16 - len(blk))
        y = _gf128_mul(y ^ int.from_bytes(blk, "big"), h)
    return y


def _inc32(x: int) -> int:
    return (x & ~0xFFFFFFFF) | ((x + 1) & 0xFFFFFFFF)


def _gctr(key: bytes, icb: int, data: bytes) -> bytes:
    out = bytearray()
    cb = icb
    for i in range(0, len(data), 16):
        ks = _encrypt_block(cb.to_bytes(16, "big"), key)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        cb = _inc32(cb)
    return bytes(out)


def _gcm_tag(key: bytes, j0: int, h: int, ct: bytes, aad: bytes) -> bytes:
    u = (16 - len(aad) % 16) % 16
    v = (16 - len(ct) % 16) % 16
    s = _ghash(h, aad + b"\x00" * u + ct + b"\x00" * v
               + (len(aad) * 8).to_bytes(8, "big")
               + (len(ct) * 8).to_bytes(8, "big"))
    return _gctr(key, j0, s.to_bytes(16, "big"))[:TAG_LEN]


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes,
                    aad: bytes = b"") -> bytes:
    """AES-GCM 加密，返回 密文||16字节标签（与 WebCrypto 一致）。"""
    if len(iv) != IV_LEN:
        raise ValueError("IV 必须为 12 字节")
    h = int.from_bytes(_encrypt_block(b"\x00" * 16, key), "big")
    j0 = int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
    ct = _gctr(key, _inc32(j0), plaintext)
    return ct + _gcm_tag(key, j0, h, ct, aad)


def aes_gcm_decrypt(key: bytes, iv: bytes, data: bytes,
                    aad: bytes = b"") -> bytes:
    """AES-GCM 解密 + 验签，失败抛 ValueError。"""
    if len(iv) != IV_LEN:
        raise ValueError("IV 必须为 12 字节")
    if len(data) < TAG_LEN:
        raise ValueError("密文长度不足")
    ct, tag = data[:-TAG_LEN], data[-TAG_LEN:]
    h = int.from_bytes(_encrypt_block(b"\x00" * 16, key), "big")
    j0 = int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
    if not secrets.compare_digest(tag, _gcm_tag(key, j0, h, ct, aad)):
        raise ValueError("认证标签校验失败：密钥错误或密文被篡改")
    return _gctr(key, _inc32(j0), ct)


# --------------------------------------------------------------------------
# 密钥派生与封装
# --------------------------------------------------------------------------


def derive_key_pbkdf2(password: str, salt: bytes,
                      iterations: int = AES_ITER) -> bytes:
    """PBKDF2-HMAC-SHA256 派生 32 字节 AES-256 密钥。"""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, iterations, dklen=32)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.strip())


def seal(plaintext: str, password: str, iterations: int = AES_ITER) -> str:
    """单条数据整体封装：Base64( 盐16B || IV12B || 密文 || 标签16B )。"""
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key_pbkdf2(password, salt, iterations)
    ct = aes_gcm_encrypt(key, iv, plaintext.encode("utf-8"))
    return _b64e(salt + iv + ct)


def unseal(token: str, password: str, iterations: int = AES_ITER) -> str:
    """解开 seal() 产生的 Base64 字符串。"""
    raw = _b64d(token)
    if len(raw) < SALT_LEN + IV_LEN + TAG_LEN:
        raise ValueError("密文长度不足，不是有效的 AES 封装数据")
    salt, iv, ct = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN + IV_LEN], raw[SALT_LEN + IV_LEN:]
    key = derive_key_pbkdf2(password, salt, iterations)
    return aes_gcm_decrypt(key, iv, ct).decode("utf-8")


class AesSession:
    """批量加密会话：只做一次 PBKDF2，之后每条数据只用随机 IV。

    单条输出格式：Base64( IV12B || 密文 || 标签16B )，盐由调用方另行保存。
    适合 Excel 这类"一个文件成千上万个单元格"的场景。
    """

    def __init__(self, password: str, salt: "bytes | None" = None,
                 iterations: int = AES_ITER) -> None:
        self.iterations = iterations
        self.salt = salt if salt is not None else os.urandom(SALT_LEN)
        self.key = derive_key_pbkdf2(password, self.salt, iterations)

    @property
    def salt_b64(self) -> str:
        return _b64e(self.salt)

    def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(IV_LEN)
        return _b64e(iv + aes_gcm_encrypt(self.key, iv,
                                          plaintext.encode("utf-8")))

    def decrypt(self, token: str) -> str:
        raw = _b64d(token)
        if len(raw) < IV_LEN + TAG_LEN:
            raise ValueError("密文长度不足")
        iv, ct = raw[:IV_LEN], raw[IV_LEN:]
        return aes_gcm_decrypt(self.key, iv, ct).decode("utf-8")

    @staticmethod
    def salt_from_b64(salt_b64: str) -> bytes:
        return _b64d(salt_b64)


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------


def _selftest() -> int:
    ok = True

    # --- NIST / GCM 规范 测试用例 ---
    vectors = [
        # (key_hex, iv_hex, pt_hex, ct_hex, tag_hex)
        ("0" * 64, "0" * 24, "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
        ("0" * 64, "0" * 24, "0" * 32,
         "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"),
        ("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721"
         "c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
         "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
         "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
         "b094dac5d93471bdec1a502270e3cc6c"),
    ]
    for idx, (kh, ih, ph, ch, th) in enumerate(vectors, 1):
        key, iv, pt = bytes.fromhex(kh), bytes.fromhex(ih), bytes.fromhex(ph)
        out = aes_gcm_encrypt(key, iv, pt)
        ct, tag = out[:-TAG_LEN].hex(), out[-TAG_LEN:].hex()
        good = (ct == ch and tag == th)
        ok &= good
        print("[GCM 向量 %d] %s" % (idx, "通过" if good else "失败"))
        if not good:
            print("   期望 ct=%s tag=%s" % (ch, th))
            print("   实际 ct=%s tag=%s" % (ct, tag))
        if aes_gcm_decrypt(key, iv, out) != pt:
            ok = False
            print("   [GCM 向量 %d] 解密往返失败" % idx)

    # --- 篡改检测 ---
    key = os.urandom(32)
    iv = os.urandom(IV_LEN)
    ct = bytearray(aes_gcm_encrypt(key, iv, b"hello bdef"))
    ct[0] ^= 0x01
    try:
        aes_gcm_decrypt(key, iv, bytes(ct))
        ok = False
        print("[篡改检测] 失败：篡改后仍然通过校验")
    except ValueError:
        print("[篡改检测] 通过：篡改被识别")

    # --- seal / unseal 往返 ---
    text = "BDEF 编码法 · 中文/English/符号 ★ 123"
    token = seal(text, "我的密钥123")
    back = unseal(token, "我的密钥123")
    good = back == text
    ok &= good
    print("[seal/unseal] %s" % ("通过" if good else "失败"))

    # --- 错误密钥必须失败 ---
    try:
        unseal(token, "错误密钥")
        ok = False
        print("[错误密钥] 失败：用错密钥竟然解开了")
    except ValueError:
        print("[错误密钥] 通过：拒绝解密")

    # --- AesSession 批量 ---
    s = AesSession("pw")
    t1, t2 = s.encrypt("同一段明文"), s.encrypt("同一段明文")
    good = (t1 != t2) and s.decrypt(t1) == "同一段明文" and s.decrypt(t2) == "同一段明文"
    ok &= good
    print("[AesSession] %s（同一明文两次密文不同）" % ("通过" if good else "失败"))

    print("\n自检结果：%s" % ("全部通过" if ok else "存在失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
