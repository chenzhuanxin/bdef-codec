# -*- coding: utf-8 -*-
"""
BDEF 编码法 · 图形化加解密面板
=========================================================================
一个开箱即用的桌面小工具：粘进去文字，点一下按钮就完成加密 / 解密。
支持三种模式，与网页版 index.html、Excel 工具 bdef_excel.py 完全互通。

    basic   基础编码   纯中国剩余定理编码，无密钥（仅教学演示）
    multi   多对多     密钥 + 随机 IV + 链式混淆 + 噪声组
    aes     AES 叠加   BDEF 编码后叠加 AES-256-GCM（推荐）

纯标准库实现：tkinter + hashlib，不需要 pip 安装任何东西。

用法：
    python bdef_panel.py            # 打开图形界面
    python bdef_panel.py --check    # 只跑核心自检，不开界面
"""

from __future__ import annotations

import os
import secrets
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bdef_theme as T                                        # noqa: E402
from bdef_core import (NOISE, SEP, TOTAL, Codebook, Codec,     # noqa: E402
                       BDEFError)

APP_TITLE = "BDEF 加解密面板"
MODE_NAMES = {"basic": "基础编码", "multi": "多对多", "aes": "AES 叠加"}

SAMPLE_TEXT = (
    "中国剩余定理（Chinese Remainder Theorem）是一门古老的数学方法：\n"
    "只要模数两两互质，一组余数就能唯一确定一个整数。\n"
    "BDEF 编码法正是借用了这一点，把 11 × 13 × 14 × 15 = 30030 当成字符池。"
)


class BdefPanel(tk.Tk):
    """主窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        T.init(self)
        T.center_window(self, 980, 780, 900, 680)
        self.configure(bg=T.BG)

        # ---- 载入码书 ----
        self.codebook_error = None
        try:
            self.codebook = Codebook.auto(os.path.dirname(os.path.abspath(__file__)))
        except Exception as exc:                              # noqa: BLE001
            self.codebook = Codebook([])
            self.codebook_error = str(exc)
        self.codec = Codec(self.codebook)

        self.mode = tk.StringVar(value="basic")
        self.key = tk.StringVar()
        self.status_plain = tk.StringVar(value="0 字")
        self.status_cipher = tk.StringVar(value="0 组")
        self._busy = False

        self._build_header()
        self._build_controls()
        self._build_tabs()
        self._build_status()

        self._sync_mode()
        self._bind_shortcuts()
        if self.codebook_error:
            self._status("码书载入失败：" + self.codebook_error, "err")
            messagebox.showerror(APP_TITLE,
                                 "码书载入失败：\n%s\n\n"
                                 "请先运行 python generate_codebook.py 生成码书。"
                                 % self.codebook_error)
        else:
            self._status("码书已载入 %d 条 · 就绪" % len(self.codebook), "ok")

    # ==================================================================
    # 界面构建
    # ==================================================================

    def _build_header(self) -> None:
        head = tk.Frame(self, bg=T.BG)
        head.pack(fill="x", padx=24, pady=(20, 12))
        left = tk.Frame(head, bg=T.BG)
        left.pack(side="left", anchor="w")
        tk.Label(left, text="BDEF 加解密面板", bg=T.BG, fg=T.TEXT,
                 font=T.font(18, True)).pack(anchor="w")
        tk.Label(left, text="中国剩余定理字符编码 · 11 × 13 × 14 × 15 = 30030",
                 bg=T.BG, fg=T.TEXT_MUTED, font=T.font(9)).pack(anchor="w",
                                                                 pady=(3, 0))
        self.pill_book = tk.Label(head, text="", bg=T.OK_LIGHT, fg="#0f766e",
                                  font=T.font(9, True), padx=12, pady=5)
        self.pill_book.pack(side="right", anchor="e")

    def _build_controls(self) -> None:
        card = T.Card(self)
        card.pack(fill="x", padx=24, pady=(0, 12))
        body = card.body

        # ---- 模式 ----
        tk.Label(body, text="编码模式", bg=T.SURFACE, fg=T.TEXT_MUTED,
                 font=T.font(9, True)).pack(anchor="w")
        self.seg = T.Segmented(body, [
            ("basic", "基础编码", "无密钥 · 仅演示"),
            ("multi", "多对多", "密钥 · IV · 噪声"),
            ("aes", "AES 叠加", "AES-256-GCM 推荐"),
        ], command=lambda _v: self._sync_mode())
        self.seg.pack(fill="x", pady=(8, 12))

        # ---- 密钥 ----
        row = tk.Frame(body, bg=T.SURFACE)
        row.pack(fill="x")
        tk.Label(row, text="密钥", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(10, True)).pack(side="left", padx=(0, 10))
        box, self.key_entry, self.eye_btn = T.password_entry(row, self.key)
        box.pack(side="left", fill="x", expand=True)
        self.key_btn = T.flat_button(row, "随机密钥", self._random_key)
        self.key_btn.pack(side="left", padx=(10, 0))

        self.mode_hint = tk.Label(body, text="", bg=T.SURFACE, fg=T.TEXT_MUTED,
                                  font=T.font(9), justify="left", anchor="w",
                                  wraplength=860)
        self.mode_hint.pack(fill="x", pady=(10, 0))

    def _build_tabs(self) -> None:
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=24)

        self.tab_enc = tk.Frame(self.nb, bg=T.SURFACE)
        self.tab_dec = tk.Frame(self.nb, bg=T.SURFACE)
        self.tab_look = tk.Frame(self.nb, bg=T.SURFACE)
        self.nb.add(self.tab_enc, text="  🔒 加密  ")
        self.nb.add(self.tab_dec, text="  🔓 解密  ")
        self.nb.add(self.tab_look, text="  🔍 码书速查  ")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_lookup_tab()

    # ---------------- 加密页 ----------------
    def _build_encrypt_tab(self) -> None:
        p = tk.Frame(self.tab_enc, bg=T.SURFACE)
        p.pack(fill="both", expand=True, padx=20, pady=16)

        top = tk.Frame(p, bg=T.SURFACE)
        top.pack(fill="x")
        tk.Label(top, text="明文", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(11, True)).pack(side="left")
        tk.Label(top, textvariable=self.status_plain, bg=T.SURFACE,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        self.txt_plain = T.make_text(p, height=9)
        self.txt_plain.pack(fill="both", expand=True, pady=(6, 8))
        self.txt_plain.bind("<KeyRelease>", lambda e: self._refresh_counts())

        bar = tk.Frame(p, bg=T.SURFACE)
        bar.pack(fill="x")
        T.flat_button(bar, "示例文本", self._fill_sample, kind="ghost").pack(side="left")
        T.flat_button(bar, "清空", lambda: self._clear(self.txt_plain),
                      kind="ghost").pack(side="left", padx=(8, 0))
        T.flat_button(bar, "粘贴", lambda: self._paste(self.txt_plain),
                      kind="ghost").pack(side="left", padx=(8, 0))
        self.btn_enc = T.flat_button(bar, "加密 →", self._do_encrypt, kind="primary")
        self.btn_enc.pack(side="right")

        mid = tk.Frame(p, bg=T.SURFACE)
        mid.pack(fill="x", pady=(14, 0))
        tk.Label(mid, text="密文", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(11, True)).pack(side="left")
        tk.Label(mid, textvariable=self.status_cipher, bg=T.SURFACE,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        self.txt_enc_out = T.make_text(p, height=9, mono_font=True)
        self.txt_enc_out.pack(fill="both", expand=True, pady=(6, 8))

        bar2 = tk.Frame(p, bg=T.SURFACE)
        bar2.pack(fill="x")
        T.flat_button(bar2, "复制密文",
                      lambda: self._copy(self.txt_enc_out.get("1.0", "end").strip(),
                                         "密文")).pack(side="left")
        T.flat_button(bar2, "保存到文件", lambda: self._save(self.txt_enc_out),
                      kind="ghost").pack(side="left", padx=(8, 0))
        T.flat_button(bar2, "送入解密页 →", self._send_to_decrypt,
                      kind="ghost").pack(side="right")

    # ---------------- 解密页 ----------------
    def _build_decrypt_tab(self) -> None:
        p = tk.Frame(self.tab_dec, bg=T.SURFACE)
        p.pack(fill="both", expand=True, padx=20, pady=16)

        top = tk.Frame(p, bg=T.SURFACE)
        top.pack(fill="x")
        tk.Label(top, text="密文", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(11, True)).pack(side="left")
        tk.Label(top, textvariable=self.status_cipher, bg=T.SURFACE,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        self.txt_dec_in = T.make_text(p, height=9, mono_font=True)
        self.txt_dec_in.pack(fill="both", expand=True, pady=(6, 8))
        self.txt_dec_in.bind("<KeyRelease>", lambda e: self._refresh_counts())

        bar = tk.Frame(p, bg=T.SURFACE)
        bar.pack(fill="x")
        T.flat_button(bar, "清空", lambda: self._clear(self.txt_dec_in),
                      kind="ghost").pack(side="left")
        T.flat_button(bar, "粘贴", lambda: self._paste(self.txt_dec_in),
                      kind="ghost").pack(side="left", padx=(8, 0))
        self.btn_dec = T.flat_button(bar, "← 解密", self._do_decrypt, kind="primary")
        self.btn_dec.pack(side="right")

        mid = tk.Frame(p, bg=T.SURFACE)
        mid.pack(fill="x", pady=(14, 0))
        tk.Label(mid, text="明文", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(11, True)).pack(side="left")

        self.txt_dec_out = T.make_text(p, height=9)
        self.txt_dec_out.pack(fill="both", expand=True, pady=(6, 8))

        bar2 = tk.Frame(p, bg=T.SURFACE)
        bar2.pack(fill="x")
        T.flat_button(bar2, "复制明文",
                      lambda: self._copy(self.txt_dec_out.get("1.0", "end").strip(),
                                         "明文")).pack(side="left")
        T.flat_button(bar2, "保存到文件", lambda: self._save(self.txt_dec_out),
                      kind="ghost").pack(side="left", padx=(8, 0))
        T.flat_button(bar2, "← 送回加密页", self._send_to_encrypt,
                      kind="ghost").pack(side="right")

    # ---------------- 速查页 ----------------
    def _build_lookup_tab(self) -> None:
        p = tk.Frame(self.tab_look, bg=T.SURFACE)
        p.pack(fill="both", expand=True, padx=20, pady=16)

        tk.Label(p, text="在码书里反查字符与编码", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(11, True)).pack(anchor="w")
        tk.Label(p, text="码书总量 %d 条：输入字符可知它的序号与四位码，输入序号可知对应字符。"
                         % len(self.codebook),
                 bg=T.SURFACE, fg=T.TEXT_MUTED, font=T.font(9)).pack(anchor="w",
                                                                     pady=(3, 14))

        row = tk.Frame(p, bg=T.SURFACE)
        row.pack(fill="x")
        tk.Label(row, text="字符", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(10, True), width=6, anchor="w").pack(side="left")
        self.lk_char = tk.Entry(row, bd=0, relief="flat", bg=T.SURFACE_ALT,
                                fg=T.TEXT, font=T.mono(11), width=12,
                                insertbackground=T.BRAND, highlightthickness=1,
                                highlightbackground=T.BORDER,
                                highlightcolor=T.BORDER_FOCUS)
        self.lk_char.pack(side="left", ipady=6)
        self.lk_char.bind("<KeyRelease>", lambda e: self._lookup_char())

        tk.Label(row, text="    编码", bg=T.SURFACE, fg=T.TEXT,
                 font=T.font(10, True)).pack(side="left")
        self.lk_code = tk.Entry(row, bd=0, relief="flat", bg=T.SURFACE_ALT,
                                fg=T.TEXT, font=T.mono(11), width=12,
                                insertbackground=T.BRAND, highlightthickness=1,
                                highlightbackground=T.BORDER,
                                highlightcolor=T.BORDER_FOCUS)
        self.lk_code.pack(side="left", ipady=6, padx=(8, 0))
        self.lk_code.bind("<KeyRelease>", lambda e: self._lookup_code())

        self.lk_result = tk.Label(p, text="", bg=T.SURFACE_ALT, fg=T.TEXT,
                                  font=T.font(10), justify="left", anchor="nw",
                                  padx=16, pady=14, wraplength=820)
        self.lk_result.pack(fill="both", expand=True, pady=(16, 0))
        self._show_lookup_placeholder()

    def _build_status(self) -> None:
        wrap = tk.Frame(self, bg=T.BG)
        wrap.pack(fill="x", padx=24, pady=(10, 16))
        self.status = T.StatusBar(wrap)
        self.status.pack(fill="x")
        tk.Label(wrap, text="快捷键：Ctrl + Enter 执行 · Tab 切换加密/解密页",
                 bg=T.BG, fg=T.TEXT_FAINT, font=T.font(8)).pack(anchor="w",
                                                                pady=(5, 0))

    # ==================================================================
    # 行为
    # ==================================================================

    def _status(self, text: str, kind: str = "info") -> None:
        self.status.set(text, kind)

    def _sync_mode(self) -> None:
        value = self.seg.get()
        self.mode.set(value)
        need = value != "basic"
        self.key_entry.configure(state="normal" if need else "disabled")
        self.eye_btn.configure(state="normal" if need else "disabled")
        self.key_btn.configure(state="normal" if need else "disabled")

        hints = {
            "basic": "基础编码：每个字符查出 1~30030 的序号，按 11 / 13 / 14 / 15 取四个余数拼成 4 位十六进制码。"
                     "规则公开、没有密钥 —— 只适合教学和趣味谜题，不能用来保护真实数据。",
            "multi": "多对多：密钥经 FNV-1a 派生出 (a, b)，对序号做模 30030 的可逆线性变换，再叠加随机 IV、"
                     "链式依赖和 ~ 噪声组，所以同一段明文每次密文都不同。属于混淆，不是密码学加密。",
            "aes":   "AES 叠加：先做多对多编码，再用 AES-256-GCM 整体加密（PBKDF2-SHA256 迭代 10 万次，"
                     "随机盐 16 字节 + IV 12 字节，输出 Base64）。这是唯一具备实际保密能力的模式。",
        }
        self.mode_hint.configure(text=hints[value])
        self.pill_book.configure(
            text="码书 %d 条" % len(self.codebook),
            bg=T.OK_LIGHT if len(self.codebook) == TOTAL else T.WARN_LIGHT,
            fg="#0f766e" if len(self.codebook) == TOTAL else T.WARN)

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-Return>", lambda e: self._run_current_tab())
        self.bind("<Command-Return>", lambda e: self._run_current_tab())

    def _run_current_tab(self) -> None:
        if self.nb.index(self.nb.select()) == 1:
            self._do_decrypt()
        else:
            self._do_encrypt()

    # ---------------- 计数 ----------------
    def _refresh_counts(self) -> None:
        plain = self.txt_plain.get("1.0", "end").strip()
        self.status_plain.set("%d 字" % len("".join(plain.split())))
        cipher = self.txt_dec_in.get("1.0", "end").strip() or \
            self.txt_enc_out.get("1.0", "end").strip()
        st = self.codec.stats(cipher, self.mode.get())
        if self.mode.get() == "aes":
            self.status_cipher.set("%d 位" % st["chars"] if st["chars"] else "0 位")
        else:
            text = "%d 组" % st["groups"]
            if st["noise"]:
                text += " · %d 噪声" % st["noise"]
            self.status_cipher.set(text)

    # ---------------- 小工具 ----------------
    @staticmethod
    def _clear(widget: tk.Text) -> None:
        widget.delete("1.0", "end")

    def _copy(self, text: str, label: str) -> None:
        if not text:
            self._status("没有可复制的内容", "warn")
            return
        if T.copy_to_clipboard(self, text):
            self._status("%s已复制到剪贴板" % label, "ok")
        else:
            self._status("复制失败，请手动选择后复制", "err")

    def _paste(self, widget: tk.Text) -> None:
        try:
            text = self.clipboard_get()
        except tk.TclError:
            self._status("剪贴板是空的", "warn")
            return
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        self._refresh_counts()

    def _save(self, widget: tk.Text) -> None:
        text = widget.get("1.0", "end").strip()
        if not text:
            self._status("没有可保存的内容", "warn")
            return
        path = filedialog.asksaveasfilename(
            title="保存为文本文件", defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            self._status("已保存到 %s" % path, "ok")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, "保存失败：%s" % exc, parent=self)

    def _fill_sample(self) -> None:
        self._clear(self.txt_plain)
        self.txt_plain.insert("1.0", SAMPLE_TEXT)
        self._refresh_counts()

    def _random_key(self) -> None:
        self.key.set(secrets.token_hex(12))
        self.key_entry.configure(show="")
        self._status("已生成随机密钥，请务必保存好", "ok")

    def _send_to_decrypt(self) -> None:
        text = self.txt_enc_out.get("1.0", "end").strip()
        if not text:
            self._status("还没有加密结果", "warn")
            return
        self._clear(self.txt_dec_in)
        self.txt_dec_in.insert("1.0", text)
        self.nb.select(1)
        self._refresh_counts()
        self._status("已送入解密页，可直接点解密验证", "ok")

    def _send_to_encrypt(self) -> None:
        text = self.txt_dec_out.get("1.0", "end").strip()
        if not text:
            self._status("还没有解密结果", "warn")
            return
        self._clear(self.txt_plain)
        self.txt_plain.insert("1.0", text)
        self.nb.select(0)
        self._refresh_counts()

    # ---------------- 核心操作 ----------------
    def _key_value(self) -> "str | None":
        if self.mode.get() == "basic":
            return ""
        value = self.key.get().strip()
        if not value:
            messagebox.showwarning(APP_TITLE,
                                   "%s模式必须填写密钥。" % MODE_NAMES[self.mode.get()],
                                   parent=self)
            self.key_entry.focus_set()
            self._status("缺少密钥", "warn")
            return None
        return value

    def _busy_on(self) -> None:
        self._busy = True
        self.configure(cursor="watch")
        self.btn_enc.configure(state="disabled")
        self.btn_dec.configure(state="disabled")
        self.update_idletasks()

    def _busy_off(self) -> None:
        self._busy = False
        self.configure(cursor="")
        self.btn_enc.configure(state="normal")
        self.btn_dec.configure(state="normal")

    def _do_encrypt(self) -> None:
        if self._busy:
            return
        plain = self.txt_plain.get("1.0", "end").rstrip("\n")
        if not plain:
            self._status("请先输入要加密的明文", "warn")
            self.txt_plain.focus_set()
            return
        key = self._key_value()
        if key is None:
            return

        self._busy_on()
        try:
            if self.mode.get() == "basic":
                out, missing = self.codec.encode_basic(plain)
            elif self.mode.get() == "multi":
                out, missing = self.codec.encode(plain, key)
            else:
                out, missing = self.codec.encrypt_full(plain, key)
        except Exception as exc:                              # noqa: BLE001
            self._busy_off()
            messagebox.showerror(APP_TITLE, "加密失败：\n%s" % exc, parent=self)
            self._status("加密失败：%s" % exc, "err")
            return
        finally:
            self._busy_off()

        self._clear(self.txt_enc_out)
        self.txt_enc_out.insert("1.0", out)
        self._refresh_counts()
        self._report_missing(missing, "加密完成")

    def _do_decrypt(self) -> None:
        if self._busy:
            return
        cipher = self.txt_dec_in.get("1.0", "end").strip()
        if not cipher:
            self._status("请先粘贴密文", "warn")
            self.txt_dec_in.focus_set()
            return
        key = self._key_value()
        if key is None:
            return

        self._busy_on()
        try:
            if self.mode.get() == "basic":
                out = self.codec.decode_basic(cipher)
            elif self.mode.get() == "multi":
                out = self.codec.decode(cipher, key)
            else:
                out = self.codec.decrypt_full(cipher, key)
        except BDEFError as exc:
            self._busy_off()
            self._status("解密失败：%s" % exc, "err")
            messagebox.showerror(APP_TITLE, "解密失败：\n%s" % exc, parent=self)
            return
        except Exception as exc:                              # noqa: BLE001
            self._busy_off()
            msg = str(exc)
            if self.mode.get() == "aes":
                msg += "\n\nAES 校验失败通常意味着密钥不正确，或者密文被改动过。"
            messagebox.showerror(APP_TITLE, "解密失败：\n%s" % msg, parent=self)
            self._status("解密失败：%s" % exc, "err")
            return
        finally:
            self._busy_off()

        self._clear(self.txt_dec_out)
        self.txt_dec_out.insert("1.0", out)
        self._status("解密完成", "ok")

    def _report_missing(self, missing, prefix: str) -> None:
        if missing:
            uniq = sorted(set(missing))
            self._status("%s，但有 %d 种字符不在码书中被跳过：%s"
                         % (prefix, len(uniq), " ".join(uniq[:12])), "warn")
        else:
            self._status("%s · 共 %d 组" % (prefix,
                                          len(self.txt_enc_out.get("1.0", "end")
                                              .strip().split(SEP))
                                          if self.mode.get() != "aes" else 0), "ok")

    # ---------------- 速查 ----------------
    def _show_lookup_placeholder(self) -> None:
        self.lk_result.configure(
            text="在上面任意一个输入框里输入内容即可查询。\n\n"
                 "例如：字符「你」→ 编码 353；编码 1 → 字符「一」。",
            fg=T.TEXT_MUTED)

    def _lookup_char(self) -> None:
        raw = self.lk_char.get()
        if not raw:
            self._show_lookup_placeholder()
            return
        ch = raw[0]
        code = self.codebook.code_of(ch)
        if code is None:
            self.lk_result.configure(
                text="字符「%s」不在码书中。\n\n码书覆盖：全部 CJK 统一汉字（含繁体）、"
                     "英拉字母与数字、日文假名、中英标点、数学与装饰符号、"
                     "希腊/西里尔字母、泰文与部分韩文。" % ch, fg=T.ERR)
            return
        utf8 = " ".join("%02X" % b for b in ch.encode("utf-8"))
        four = "".join("%x" % (code % m) for m in (11, 13, 14, 15))
        self.lk_result.configure(
            text=("字符：%s\n编码：%d      四位码：%s\n"
                  "Unicode：U+%04X\nUTF-8：%s" % (ch, code, four, ord(ch), utf8)),
            fg=T.TEXT)

    def _lookup_code(self) -> None:
        raw = self.lk_code.get().strip()
        if not raw:
            self._show_lookup_placeholder()
            return
        if not raw.isdigit():
            self.lk_result.configure(text="编码必须是 1 ~ %d 之间的整数。" % TOTAL,
                                     fg=T.ERR)
            return
        n = int(raw)
        ch = self.codebook.char_of(n)
        if ch is None:
            self.lk_result.configure(text="编码 %d 超出码书范围（1 ~ %d）。"
                                          % (n, len(self.codebook)), fg=T.ERR)
            return
        utf8 = " ".join("%02X" % b for b in ch.encode("utf-8"))
        four = "".join("%x" % (n % m) for m in (11, 13, 14, 15))
        self.lk_result.configure(
            text=("编码：%d      四位码：%s\n字符：%s\n"
                  "Unicode：U+%04X\nUTF-8：%s" % (n, four, ch, ord(ch), utf8)),
            fg=T.TEXT)


# ==========================================================================
# 入口
# ==========================================================================


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" in argv:
        from bdef_core import _selftest
        return _selftest()
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    app = BdefPanel()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
