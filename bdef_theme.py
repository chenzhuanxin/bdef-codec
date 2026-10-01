# -*- coding: utf-8 -*-
"""
BDEF 编码法 · 图形界面统一主题
=========================================================================
给 bdef_panel.py 与 bdef_excel.py 提供一致的视觉风格（浅色现代扁平化）。
只依赖标准库 tkinter，无需任何第三方包。
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk
from typing import Callable, List, Optional

# --------------------------------------------------------------------------
# 配色
# --------------------------------------------------------------------------
BG = "#eef2fb"          # 页面底色
SURFACE = "#ffffff"     # 卡片
SURFACE_ALT = "#f7f9fd"  # 输入框底色
SURFACE_SUNK = "#eaeefb"  # 分段控件底槽
BORDER = "#dbe2f0"
BORDER_FOCUS = "#4f46e5"
TEXT = "#141a33"
TEXT_MUTED = "#6b7590"
TEXT_FAINT = "#9aa3ba"
BRAND = "#4f46e5"
BRAND_HOVER = "#4338ca"
BRAND_LIGHT = "#eef0ff"
BRAND_TEXT = "#3730a3"
OK = "#0d9488"
OK_LIGHT = "#e6f7f4"
WARN = "#b45309"
WARN_LIGHT = "#fef4e5"
ERR = "#c2410c"
ERR_LIGHT = "#fdeee7"
DISABLED = "#c3cadd"

# --------------------------------------------------------------------------
# 字体
# --------------------------------------------------------------------------
_PREFERRED_UI = ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                 "Hiragino Sans GB", "Segoe UI", "Helvetica")
_PREFERRED_MONO = ("Cascadia Mono", "Consolas", "JetBrains Mono",
                   "DejaVu Sans Mono", "Courier New")


def _pick(candidates) -> str:
    try:
        available = set(tkfont.families())
    except Exception:                                # noqa: BLE001
        return candidates[-1]
    for name in candidates:
        if name in available:
            return name
    return candidates[-1]


_UI_FAMILY: Optional[str] = None
_MONO_FAMILY: Optional[str] = None


def ui_family() -> str:
    global _UI_FAMILY
    if _UI_FAMILY is None:
        _UI_FAMILY = _pick(_PREFERRED_UI)
    return _UI_FAMILY


def mono_family() -> str:
    global _MONO_FAMILY
    if _MONO_FAMILY is None:
        _MONO_FAMILY = _pick(_PREFERRED_MONO)
    return _MONO_FAMILY


def font(size: int = 10, bold: bool = False) -> tuple:
    return (ui_family(), size, "bold") if bold else (ui_family(), size)


def mono(size: int = 10, bold: bool = False) -> tuple:
    return (mono_family(), size, "bold") if bold else (mono_family(), size)


# --------------------------------------------------------------------------
# 初始化
# --------------------------------------------------------------------------


def init(root: tk.Misc) -> ttk.Style:
    """设置全局外观，返回 ttk.Style。"""
    try:
        root.configure(bg=BG)
    except tk.TclError:
        pass

    style = ttk.Style(root)
    for theme in ("clam", "alt", "default"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    style.configure(".", background=BG, foreground=TEXT, font=font(10))
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=SURFACE)
    style.configure("TLabel", background=BG, foreground=TEXT, font=font(10))
    style.configure("Card.TLabel", background=SURFACE, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED,
                    font=font(9))
    style.configure("CardMuted.TLabel", background=SURFACE,
                    foreground=TEXT_MUTED, font=font(9))
    style.configure("Title.TLabel", background=BG, foreground=TEXT,
                    font=font(17, True))
    style.configure("CardTitle.TLabel", background=SURFACE, foreground=TEXT,
                    font=font(12, True))
    style.configure("Section.TLabel", background=SURFACE, foreground=TEXT_MUTED,
                    font=font(9, True))

    style.configure("TEntry", fieldbackground=SURFACE_ALT, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    insertcolor=BRAND, padding=6)
    style.map("TEntry",
              fieldbackground=[("disabled", "#f2f4fa"), ("focus", SURFACE)],
              bordercolor=[("focus", BORDER_FOCUS)])

    style.configure("TCombobox", fieldbackground=SURFACE_ALT, background=SURFACE,
                    foreground=TEXT, arrowcolor=BRAND, bordercolor=BORDER,
                    padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", SURFACE_ALT)],
              bordercolor=[("focus", BORDER_FOCUS)])

    style.configure("TButton", background=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, focusthickness=0, padding=(12, 7),
                    font=font(10), relief="flat")
    style.map("TButton",
              background=[("active", SURFACE_ALT), ("disabled", "#f2f4fa")],
              foreground=[("disabled", TEXT_FAINT)])

    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
    style.configure("TNotebook.Tab", background=SURFACE_SUNK,
                    foreground=TEXT_MUTED, padding=(18, 9), font=font(10),
                    borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", SURFACE)],
              foreground=[("selected", BRAND)])

    style.configure("TCheckbutton", background=SURFACE, foreground=TEXT,
                    focuscolor=SURFACE, font=font(10))
    style.map("TCheckbutton", background=[("active", SURFACE)],
              foreground=[("disabled", TEXT_FAINT)])

    style.configure("TProgressbar", background=BRAND, troughcolor=SURFACE_SUNK,
                    bordercolor=SURFACE_SUNK, lightcolor=BRAND,
                    darkcolor=BRAND, thickness=8)

    style.configure("TSeparator", background=BORDER)
    return style


def center_window(win: tk.Misc, width: int, height: int,
                  min_w: int = 0, min_h: int = 0) -> None:
    """把窗口放到屏幕中央并设置最小尺寸。"""
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, (sw - width) // 2)
    y = max(0, (sh - height) // 3)
    win.geometry("%dx%d+%d+%d" % (width, height, x, y))
    if min_w or min_h:
        win.minsize(min_w or width, min_h or height)


# --------------------------------------------------------------------------
# 常用小部件
# --------------------------------------------------------------------------


class Card(tk.Frame):
    """白色圆角感卡片（用 1px 边框模拟）。"""

    def __init__(self, master, padding=(18, 16), **kw):
        super().__init__(master, bg=BORDER, bd=0, **kw)
        self.inner = tk.Frame(self, bg=SURFACE)
        self.inner.pack(fill="both", expand=True, padx=1, pady=1)
        self.body = tk.Frame(self.inner, bg=SURFACE)
        self.body.pack(fill="both", expand=True,
                       padx=padding[0], pady=padding[1])


class Segmented(tk.Frame):
    """分段选择控件（用于模式切换）。"""

    def __init__(self, master, options: List[tuple], command: Optional[Callable] = None,
                 **kw):
        """options: [(value, 主标题, 副标题), ...]"""
        super().__init__(master, bg=SURFACE_SUNK, highlightthickness=1,
                         highlightbackground=BORDER, bd=0, **kw)
        self.options = options
        self.command = command
        self.value = options[0][0]
        self._cells = {}

        holder = tk.Frame(self, bg=SURFACE_SUNK)
        holder.pack(fill="x", padx=5, pady=5)
        for i, (val, title, sub) in enumerate(options):
            cell = tk.Frame(holder, bg=SURFACE_SUNK, cursor="hand2")
            cell.grid(row=0, column=i, sticky="nsew", padx=2)
            holder.columnconfigure(i, weight=1)
            t = tk.Label(cell, text=title, bg=SURFACE_SUNK, fg=TEXT_MUTED,
                         font=font(10, True), cursor="hand2")
            t.pack(pady=(7, 0))
            s = tk.Label(cell, text=sub, bg=SURFACE_SUNK, fg=TEXT_FAINT,
                         font=font(8), cursor="hand2")
            s.pack(pady=(0, 7))
            for w in (cell, t, s):
                w.bind("<Button-1>", lambda e, v=val: self.select(v))
            self._cells[val] = (cell, t, s)
        self._paint()

    def select(self, value: str, notify: bool = True) -> None:
        if value == self.value:
            return
        self.value = value
        self._paint()
        if notify and self.command:
            self.command(value)

    def get(self) -> str:
        return self.value

    def _paint(self) -> None:
        for val, (cell, t, s) in self._cells.items():
            on = (val == self.value)
            bg = SURFACE if on else SURFACE_SUNK
            cell.configure(bg=bg)
            t.configure(bg=bg, fg=BRAND if on else TEXT_MUTED)
            s.configure(bg=bg, fg=BRAND_TEXT if on else TEXT_FAINT)


class StatusBar(tk.Frame):
    """底部状态条，支持普通 / 成功 / 警告 / 错误四种色调。"""

    def __init__(self, master, **kw):
        super().__init__(master, bg=BG, **kw)
        self._label = tk.Label(self, text="就绪", bg=BG, fg=TEXT_MUTED,
                               font=font(9), anchor="w", justify="left")
        self._label.pack(side="left", fill="x", expand=True)

    def set(self, text: str, kind: str = "info") -> None:
        colors = {"info": (TEXT_MUTED, BG), "ok": ("#0f766e", OK_LIGHT),
                  "warn": (WARN, WARN_LIGHT), "err": (ERR, ERR_LIGHT)}
        fg, bg = colors.get(kind, colors["info"])
        self._label.configure(text=text, fg=fg, bg=bg)
        self.configure(bg=bg)


def make_text(master, height: int = 10, mono_font: bool = False,
              wrap: str = "word", state: str = "normal") -> tk.Text:
    """统一样式的多行文本框。"""
    txt = tk.Text(master, height=height, wrap=wrap, bd=0, relief="flat",
                  bg=SURFACE_ALT, fg=TEXT, insertbackground=BRAND,
                  selectbackground="#c7d2fe", selectforeground=TEXT,
                  font=mono(10) if mono_font else font(10),
                  padx=11, pady=10, highlightthickness=1,
                  highlightbackground=BORDER, highlightcolor=BORDER_FOCUS,
                  state=state)
    txt.bind("<FocusIn>", lambda e: txt.configure(highlightbackground=BORDER_FOCUS))
    txt.bind("<FocusOut>", lambda e: txt.configure(highlightbackground=BORDER))
    return txt


def flat_button(master, text: str, command, kind: str = "default",
                width: Optional[int] = None) -> tk.Button:
    """扁平化按钮，kind: default | primary | ghost | danger"""
    if kind == "primary":
        bg, fg, abg = BRAND, "#ffffff", BRAND_HOVER
    elif kind == "ghost":
        bg, fg, abg = SURFACE, TEXT_MUTED, SURFACE_ALT
    elif kind == "danger":
        bg, fg, abg = SURFACE, ERR, ERR_LIGHT
    else:
        bg, fg, abg = SURFACE, TEXT, SURFACE_ALT
    btn = tk.Button(master, text=text, command=command, bg=bg, fg=fg,
                    activebackground=abg,
                    activeforeground="#ffffff" if kind == "primary" else fg,
                    font=font(10, kind == "primary"), bd=0, relief="flat",
                    cursor="hand2", padx=14, pady=7,
                    highlightthickness=1,
                    highlightbackground=BORDER if kind != "primary" else BRAND,
                    disabledforeground=TEXT_FAINT)
    if width:
        btn.configure(width=width)
    return btn


def password_entry(master, textvariable, width: int = 30) -> tuple:
    """带"显示/隐藏"按钮的密码输入框，返回 (容器, Entry, 切换按钮)。"""
    box = tk.Frame(master, bg=SURFACE)
    entry = tk.Entry(box, textvariable=textvariable, show="●", width=width,
                     bd=0, relief="flat", bg=SURFACE_ALT, fg=TEXT,
                     insertbackground=BRAND, font=mono(10),
                     highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=BORDER_FOCUS)
    entry.pack(side="left", fill="x", expand=True, ipady=6)
    state = {"show": False}

    def toggle():
        state["show"] = not state["show"]
        entry.configure(show="" if state["show"] else "●")
        btn.configure(text="🙈" if state["show"] else "👁")

    btn = tk.Button(box, text="👁", command=toggle, bg=SURFACE_ALT,
                    fg=TEXT_MUTED, activebackground=SURFACE,
                    activeforeground=TEXT, bd=0, relief="flat", cursor="hand2",
                    font=font(10), padx=7, highlightthickness=1,
                    highlightbackground=BORDER)
    btn.pack(side="left", padx=(6, 0))
    return box, entry, btn


def copy_to_clipboard(root: tk.Misc, text: str) -> bool:
    """复制到系统剪贴板（跨平台）。"""
    if not text:
        return False
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()                                  # 某些平台需要
        return True
    except tk.TclError:
        return False


IS_WINDOWS = sys.platform.startswith("win")
