# -*- coding: utf-8 -*-
"""
一致性交叉验证 · Python 端
=========================================================================
配合 tools/cross_check.js 使用，验证 Python 实现与网页版 JavaScript 实现
在字节层面完全一致：

    1. 编码表      30030 个序号的四位编码逐一对齐
    2. 密钥派生    同一密钥得到的 (a, b) 完全一致
    3. 多对多密文  同一确定性随机源下产生的密文逐字符相同（含噪声组）
    4. AES 互通    JS 加密的密文能被 Python 解开，Python 加密的密文能被 JS 解开
    5. 反查        用 Python 解 JS 的多对多密文

用法：
    node tools/cross_check.js          # 先跑 JS 端
    python tools/cross_check.py        # 再跑 Python 端做比对
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bdef_core import (MODS, TOTAL, Codebook, Codec, derive_key,  # noqa: E402
                       encode_code)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JS_OUT = os.path.join(HERE, "_js_out.json")
PY_OUT = os.path.join(HERE, "_py_out.json")
SEED = 20261001


def js_lcg(seed: int):
    """与 cross_check.js 中的 lcg 逐位对应。"""
    state = seed & 0xFFFFFFFF

    def rng() -> float:
        nonlocal state
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        return state / 4294967296.0

    return rng


def main() -> int:
    if not os.path.exists(JS_OUT):
        print("未找到 %s，正在自动运行 JS 端……" % JS_OUT)
        try:
            subprocess.run(["node", os.path.join(HERE, "cross_check.js")],
                           cwd=ROOT, check=True)
        except Exception as e:                       # noqa: BLE001
            print("无法运行 node：%s" % e)
            print("请先手动执行： node tools/cross_check.js")
            return 2

    with open(JS_OUT, "r", encoding="utf-8") as f:
        js = json.load(f)

    ok = True

    # ---- 1. 编码表 ----
    bad = 0
    for n in range(1, TOTAL + 1):
        if js["encodeCode"][str(n)] != encode_code(n):
            bad += 1
    ok &= (bad == 0)
    print("[1] 编码表 30030 条对齐：%s" % ("通过" if bad == 0 else "失败 %d 条" % bad))

    # ---- 2. 密钥派生 ----
    bad = 0
    for key, ab in js["deriveKey"].items():
        mine = derive_key(key)
        if [mine[0], mine[1]] != ab:
            bad += 1
            print("    密钥 %r 不一致：JS=%s Python=%s" % (key, ab, mine))
    ok &= (bad == 0)
    print("[2] 密钥派生 %d 组对齐：%s"
          % (len(js["deriveKey"]), "通过" if bad == 0 else "失败"))

    # ---- 3. 多对多密文（确定性随机源） ----
    cb = Codebook.auto(ROOT)
    text = js["text"]
    bad = 0
    for key, cipher in js["multi"].items():
        mine = Codec(cb, js_lcg(SEED)).encode(text, key)[0]
        if mine != cipher:
            bad += 1
            print("    密钥 %r 密文不一致" % key)
            print("      JS    : %s" % cipher[:80])
            print("      Python: %s" % mine[:80])
        # 顺便用 Python 解开 JS 的密文
        if Codec(cb).decode(cipher, key) != text:
            bad += 1
            print("    密钥 %r 无法用 Python 解开 JS 密文" % key)
    ok &= (bad == 0)
    print("[3] 多对多密文逐字符一致 + Python 可解 JS 密文：%s"
          % ("通过" if bad == 0 else "失败"))

    # ---- 4. AES 互通 ----
    codec = Codec(cb)
    js_token = js["aes"]["token"]
    try:
        got = codec.decrypt_full(js_token, "cross-check-key")
        good = (got == text)
        ok &= good
        print("[4a] Python 解开 JS 的 AES 密文：%s" % ("通过" if good else "失败"))
    except Exception as e:                          # noqa: BLE001
        ok = False
        print("[4a] Python 解开 JS 的 AES 密文：失败 -> %s" % e)

    # ---- 5. 生成 Python 端产物，供 JS 端反向验证 ----
    py_token = codec.encrypt_full(text, "cross-check-key")[0]
    py_out = {
        "aes": {"token": py_token},
        "aesPlaintext": text,
        "aesKey": "cross-check-key",
        "multi": {k: Codec(cb, js_lcg(SEED)).encode(text, k)[0]
                  for k in js["deriveKey"]},
        "decodeJsMulti": codec.decode(js["multiForPython"], "密钥key-1"),
    }
    with open(PY_OUT, "w", encoding="utf-8") as f:
        json.dump(py_out, f, ensure_ascii=False)
    print("[4b] 已写出 Python 的 AES 密文，等待 JS 端反向验证 -> %s"
          % os.path.basename(PY_OUT))

    # ---- 6. Python 解 JS 多对多密文 ----
    good = (py_out["decodeJsMulti"] == text)
    ok &= good
    print("[5] Python 解开 JS 的多对多密文：%s" % ("通过" if good else "失败"))

    # ---- 7. 调用 JS 反向验证 ----
    verify_js = os.path.join(HERE, "cross_check_verify.js")
    if os.path.exists(verify_js):
        try:
            r = subprocess.run(["node", verify_js], cwd=ROOT, check=True,
                               capture_output=True, text=True, encoding="utf-8")
            print(r.stdout.strip())
            ok &= ("全部通过" in r.stdout)
        except Exception as e:                      # noqa: BLE001
            ok = False
            print("[7] JS 反向验证失败：%s" % e)

    print("\n交叉验证结果：%s" % ("全部通过 ✅  两套实现字节级一致"
                                  if ok else "存在不一致 ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
