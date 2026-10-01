# -*- coding: utf-8 -*-
"""
BDEF 编码法 · Excel 数据加解密工具
=========================================================================
把整张工作表里的单元格内容批量加密 / 解密，支持三种模式：

    basic   纯 BDEF 编码（无密钥）
    multi   密钥 + 随机 IV + 链式混淆 + 噪声组
    aes     多对多编码后叠加 AES-256-GCM（PBKDF2-SHA256 派生密钥）

设计要点：
    * 只处理"有值"的单元格；公式、空单元格、合并单元格的从属格自动跳过。
    * 处理过的单元格统一设为文本格式，避免 Excel 把密文当数字或公式。
    * AES 模式会在工作簿里插入一张 _BDEF_META 表保存盐值与参数，
      解密时只要提供同一密钥即可，无需手工传盐。
    * 批量场景下 PBKDF2 只算一次（AesSession），性能可接受。

用法：
    python bdef_excel.py                                  # 打开图形界面
    python bdef_excel.py template -o BDEF_excel_template.xlsx
    python bdef_excel.py encrypt -i 原始.xlsx -o 加密后.xlsx -k 密钥 -m multi
    python bdef_excel.py decrypt -i 加密后.xlsx -o 还原.xlsx -k 密钥 -m multi

依赖：openpyxl（pip install openpyxl）
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bdef_aes import AES_ITER, AesSession                     # noqa: E402
from bdef_core import Codebook, Codec                          # noqa: E402

META_SHEET = "_BDEF_META"
META_TAG = "BDEF-EXCEL/1.0"
TOOL_NAME = "BDEF Excel 加解密工具"
MODE_NAMES = {"basic": "基础编码", "multi": "多对多", "aes": "AES 叠加"}

_NUM_RE = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?$")
MAX_SAFE_DIGITS = 15      # 超过 15 位的整数转成 float 会丢精度（身份证 / 长卡号）


class ExcelError(Exception):
    """可预期的业务错误。"""


# ==========================================================================
# 单元格值规范化
# ==========================================================================


def cell_to_text(value) -> str:
    """把单元格值规范成要加密的字符串。"""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return repr(value)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat(sep=" ") if isinstance(value, _dt.datetime) else value.isoformat()
    return str(value)


def text_to_cell(text: str, restore_number: bool):
    """解密后决定写回什么类型。

    只有"安全"的纯数字才会被还原成数值：
      * 不能有前导零（"007" 原本就是文本，不该变成 7）
      * 整数部分不超过 15 位（再长就会超出 float 精度，
        身份证号、银行卡号这类必须原样保留为文本）
    """
    if not restore_number or not _NUM_RE.match(text):
        return text
    int_part = text.lstrip("-").split(".")[0]
    if len(int_part) > MAX_SAFE_DIGITS:
        return text
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


# ==========================================================================
# 核心处理
# ==========================================================================


def _load_openpyxl():
    try:
        import openpyxl                                     # noqa: F401
        return openpyxl
    except ImportError as exc:                              # noqa: BLE001
        raise ExcelError("未安装 openpyxl。请执行：pip install openpyxl") from exc


def read_meta(path: str) -> "dict | None":
    """读取工作簿里的 BDEF 元信息（若有）。"""
    openpyxl = _load_openpyxl()
    try:
        wb = openpyxl.load_workbook(path, read_only=True, data_only=False)
    except Exception:                                       # noqa: BLE001
        return None
    try:
        if META_SHEET not in wb.sheetnames:
            return None
        ws = wb[META_SHEET]
        raw = ws["A1"].value
        if not isinstance(raw, str) or not raw.startswith(META_TAG):
            return None
        body = raw[len(META_TAG):].strip()
        return json.loads(body) if body else {}
    except Exception:                                       # noqa: BLE001
        return None
    finally:
        wb.close()


def process_workbook(src: str, dst: str, key: str, mode: str, decrypt: bool,
                     sheet: "str | None" = None, skip_header: bool = True,
                     columns: "list[int] | None" = None,
                     restore_number: bool = True,
                     progress=None, log=None) -> dict:
    """核心处理入口。

    返回统计字典：{"sheets": [...], "cells": n, "skipped": n, "meta": {...}}
    """
    openpyxl = _load_openpyxl()
    from openpyxl.cell.cell import MergedCell
    from openpyxl.utils import get_column_letter

    if not os.path.exists(src):
        raise ExcelError("找不到输入文件：%s" % src)
    if not src.lower().endswith((".xlsx", ".xlsm")):
        raise ExcelError("只支持 .xlsx / .xlsm 文件（openpyxl 不支持旧版 .xls）。")
    if not decrypt and mode != "basic" and not key:
        raise ExcelError("%s模式必须提供密钥。" % MODE_NAMES.get(mode, mode))

    def emit(msg):
        if log:
            log(msg)

    emit("载入 %s ……" % os.path.basename(src))
    wb = openpyxl.load_workbook(src)

    # ---- 准备 AES 会话 ----
    session = None
    meta_out = None
    if mode == "aes":
        if decrypt:
            meta = read_meta(src)
            if not meta or not meta.get("salt"):
                raise ExcelError(
                    "这个工作簿里没有找到 AES 元信息（_BDEF_META）表。\n"
                    "AES 模式解密需要原文加密时写入的盐值，请确认文件正确，"
                    "或改用与加密时相同的模式。")
            session = AesSession(key, AesSession.salt_from_b64(meta["salt"]),
                                 int(meta.get("iterations", AES_ITER)))
            emit("已读取 AES 元信息：迭代 %d 次，盐 %s…"
                 % (session.iterations, meta["salt"][:12]))
        else:
            session = AesSession(key, iterations=AES_ITER)
            meta_out = {
                "tool": TOOL_NAME,
                "version": "1.0",
                "mode": "aes",
                "iterations": session.iterations,
                "salt": session.salt_b64,
                "created": _dt.datetime.now().isoformat(timespec="seconds"),
            }
            emit("已生成随机盐值用于 PBKDF2 派生 AES 密钥")

    # ---- 选定工作表 ----
    if sheet:
        if sheet not in wb.sheetnames:
            raise ExcelError("工作簿里没有名为 %r 的工作表" % sheet)
        targets = [wb[sheet]]
    else:
        targets = [wb[n] for n in wb.sheetnames if n != META_SHEET]

    codec = Codec(Codebook.auto(os.path.dirname(os.path.abspath(__file__))))

    # ---- 逐表处理 ----
    total_cells = 0
    skipped = 0
    missing_chars = set()
    touched_columns = {}
    sheet_stats = []

    for ws in targets:
        emit("处理工作表：%s" % ws.title)
        n_done = 0
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell, MergedCell):
                    continue
                if columns and cell.column not in columns:
                    continue
                if skip_header and cell.row == 1:
                    continue
                value = cell.value
                if value is None or (isinstance(value, str) and value == ""):
                    continue
                if isinstance(value, str) and value.startswith("="):
                    skipped += 1
                    continue

                text = cell_to_text(value)
                try:
                    if decrypt:
                        if mode == "basic":
                            out = codec.decode_basic(text)
                        elif mode == "multi":
                            out = codec.decode(text, key)
                        else:
                            out = codec.decode(session.decrypt(text), key)
                        cell.value = text_to_cell(out, restore_number)
                    else:
                        miss = []
                        if mode == "basic":
                            out, miss = codec.encode_basic(text)
                        elif mode == "multi":
                            out, miss = codec.encode(text, key)
                        else:
                            inner, miss = codec.encode(text, key)
                            out = session.encrypt(inner)
                        missing_chars.update(miss)
                        cell.value = out
                except Exception as exc:                    # noqa: BLE001
                    raise ExcelError(
                        "单元格 %s!%s%d 处理失败：%s"
                        % (ws.title, get_column_letter(cell.column),
                           cell.row, exc)) from exc

                cell.number_format = "@"                     # 强制文本
                total_cells += 1
                n_done += 1
                touched_columns.setdefault(ws.title, set()).add(cell.column)
                if progress and total_cells % 200 == 0:
                    progress(total_cells, 0)

        sheet_stats.append({"title": ws.title, "cells": n_done})
        emit("  %s：处理 %d 个单元格" % (ws.title, n_done))

    # ---- 列宽微调（让密文可见）----
    for title, cols in touched_columns.items():
        ws = wb[title]
        width = 18 if decrypt else 38
        for idx in cols:
            letter = get_column_letter(idx)
            cur = ws.column_dimensions.get(letter)
            if cur is None or not cur.width:
                ws.column_dimensions[letter].width = width

    # ---- 元信息表 ----
    if not decrypt and meta_out:
        if META_SHEET in wb.sheetnames:
            del wb[META_SHEET]
        mws = wb.create_sheet(META_SHEET)
        mws["A1"] = META_TAG + " " + json.dumps(meta_out, ensure_ascii=False)
        mws["A2"] = "← 这张表由 %s 自动生成，记录 AES 参数，请勿删除或修改。" % TOOL_NAME
        mws["A1"].number_format = "@"
        mws["A2"].number_format = "@"
        mws.column_dimensions["A"].width = 90
        emit("已写入 AES 元信息表 %s" % META_SHEET)
    elif decrypt and meta_out is None and META_SHEET in wb.sheetnames:
        pass

    # ---- AES 解密后可顺手清掉元信息表 ----
    if decrypt and META_SHEET in wb.sheetnames:
        del wb[META_SHEET]
        emit("已移除元信息表 %s" % META_SHEET)

    out_dir = os.path.dirname(os.path.abspath(dst))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    try:
        wb.save(dst)
    except PermissionError as exc:
        raise ExcelError("无法写入 %s\n请先关闭正在占用该文件的 Excel 窗口。"
                         % dst) from exc
    finally:
        wb.close()

    emit("已保存：%s" % dst)
    return {
        "sheets": sheet_stats,
        "cells": total_cells,
        "skipped": skipped,
        "missing": sorted(missing_chars),
        "output": dst,
    }


# ==========================================================================
# 生成 Excel 模板
# ==========================================================================

TEMPLATE_ROWS = [
    ["张伟", "13800001234", "420106199001011234", "湖北省武汉市洪山区珞喻路 1037 号", "技术部 · 高级工程师"],
    ["李娜", "13900002345", "310104199203155678", "上海市徐汇区漕溪北路 18 号 1203 室", "市场部 · 品牌经理"],
    ["王强", "13700003456", "440305198807209012", "广东省深圳市南山区科技园南区 R2-B 栋", "研发部 · 架构师"],
    ["陈静", "13600004567", "110108199512033456", "北京市海淀区中关村南大街 5 号", "财务部 · 主管会计"],
    ["刘洋", "13500005678", "510107199408217890", "四川省成都市武侯区天府大道中段 199 号", "销售部 · 大区经理"],
    ["赵敏", "13400006789", "330102199107284321", "浙江省杭州市西湖区文三路 90 号", "产品部 · 产品总监"],
]

TEMPLATE_HEADERS = ["姓名", "手机号", "身份证号", "家庭住址", "部门 / 职位"]


def build_template(path: str) -> str:
    """生成一份可用的 Excel 模板（含示例数据与使用说明）。"""
    openpyxl = _load_openpyxl()
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()

    # ---- 说明页 ----
    ws0 = wb.active
    ws0.title = "使用说明"
    guide = [
        [TOOL_NAME + " · 使用说明"],
        [""],
        ["1. 把这份模板另存为你自己的数据文件，替换掉示例内容（保留第 1 行表头）。"],
        ["2. 打开工具：python bdef_excel.py（图形界面），或用命令行模式。"],
        ["3. 选择输入文件与本工具，填写密钥（AES / 多对多模式必填），点“加密”。"],
        ["4. 加密后会生成一个新的 xlsx，单元格内容变成 BDEF 密文，可以安全外发。"],
        ["5. 别人拿到文件后，用同样的工具、同样的密钥和模式，点“解密”即可还原。"],
        [""],
        ["三种模式："],
        ["  · 基础编码：无密钥，任何人都能解。仅用于教学演示。不要用它保护真实数据。"],
        ["  · 多对多 ：需要密钥。属于混淆，比基础编码安全，但不是密码学加密。"],
        ["  · AES 叠加：需要密钥。BDEF 编码后再套 AES-256-GCM，具备实际保密能力，推荐使用。"],
        [""],
        ["注意："],
        ["  · 公式、空单元格、合并单元格的从属格会被自动跳过。"],
        ["  · 密钥一旦丢失，多对多 / AES 模式的数据无法恢复。"],
        ["  · AES 模式会在工作簿里新增一张 _BDEF_META 表保存盐值，请勿删除。"],
        ["  · 解密时如果勾选“还原数字”，纯数字内容会重新变回数值类型。"],
    ]
    for r in guide:
        ws0.append(r)
    ws0["A1"].font = Font(bold=True, size=15, color="4F46E5")
    for r in range(3, ws0.max_row + 1):
        ws0.cell(row=r, column=1).alignment = Alignment(vertical="center")
    ws0.column_dimensions["A"].width = 96

    # ---- 数据页 ----
    ws = wb.create_sheet("员工信息")
    ws.append(TEMPLATE_HEADERS)
    for row in TEMPLATE_ROWS:
        ws.append(row)

    head_font = Font(bold=True, color="FFFFFF", size=11)
    head_fill = PatternFill("solid", fgColor="4F46E5")
    thin = Side(style="thin", color="DBE2F0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    for col in range(1, len(TEMPLATE_HEADERS) + 1):
        c = ws.cell(row=1, column=col)
        c.font = head_font
        c.fill = head_fill
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = border
    ws.row_dimensions[1].height = 26

    for r in range(2, ws.max_row + 1):
        for col in range(1, len(TEMPLATE_HEADERS) + 1):
            cell = ws.cell(row=r, column=col)
            cell.border = border
            cell.alignment = Alignment(vertical="center")
            cell.number_format = "@"          # 手机号 / 身份证号保持文本

    for col, width in zip(range(1, 6), (12, 16, 24, 40, 24)):
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.freeze_panes = "A2"

    wb.save(path)
    return path


# ==========================================================================
# 图形界面
# ==========================================================================


def run_gui() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    import bdef_theme as T

    root = tk.Tk()
    root.title(TOOL_NAME)
    T.init(root)
    T.center_window(root, 900, 700, 860, 640)
    root.configure(bg=T.BG)

    state = {
        "running": False,
        "in_file": tk.StringVar(),
        "out_file": tk.StringVar(),
        "key": tk.StringVar(),
        "mode": tk.StringVar(value="aes"),
        "sheet": tk.StringVar(value="（全部工作表）"),
        "skip_header": tk.BooleanVar(value=True),
        "restore_number": tk.BooleanVar(value=True),
    }

    # ---------------- 顶部标题 ----------------
    header = tk.Frame(root, bg=T.BG)
    header.pack(fill="x", padx=22, pady=(18, 12))
    tk.Label(header, text="BDEF · Excel 加解密", bg=T.BG, fg=T.TEXT,
             font=T.font(17, True)).pack(anchor="w")
    tk.Label(header, text="批量处理 xlsx 单元格内容的三种编码模式 · 与网页版和 Python 面板完全互通",
             bg=T.BG, fg=T.TEXT_MUTED, font=T.font(9)).pack(anchor="w", pady=(2, 0))

    body = tk.Frame(root, bg=T.BG)
    body.pack(fill="both", expand=True, padx=22)

    # ---------------- 模式卡片 ----------------
    card1 = T.Card(body)
    card1.pack(fill="x", pady=(0, 12))
    inner = card1.body
    tk.Label(inner, text="编码模式", bg=T.SURFACE, fg=T.TEXT_MUTED,
             font=T.font(9, True)).pack(anchor="w")
    seg = T.Segmented(inner, [
        ("basic", "基础编码", "无密钥 · 仅演示"),
        ("multi", "多对多", "密钥 · IV · 噪声"),
        ("aes", "AES 叠加", "AES-256-GCM 推荐"),
    ], command=lambda v: _sync())
    seg.pack(fill="x", pady=(8, 10))

    key_row = tk.Frame(inner, bg=T.SURFACE)
    key_row.pack(fill="x")
    tk.Label(key_row, text="密钥", bg=T.SURFACE, fg=T.TEXT,
             font=T.font(10, True)).pack(side="left", padx=(0, 10))
    box, key_entry, _btn = T.password_entry(key_row, state["key"])
    box.pack(side="left", fill="x", expand=True)

    def _random_key():
        import secrets
        state["key"].set(secrets.token_hex(12))
        key_entry.configure(show="")

    key_btn = T.flat_button(key_row, "随机密钥", _random_key)
    key_btn.pack(side="left", padx=(10, 0))

    # ---------------- 文件卡片 ----------------
    card2 = T.Card(body)
    card2.pack(fill="both", expand=True, pady=(0, 12))
    inner2 = card2.body

    def file_row(parent, label, var, is_out):
        row = tk.Frame(parent, bg=T.SURFACE)
        row.pack(fill="x", pady=5)
        tk.Label(row, text=label, bg=T.SURFACE, fg=T.TEXT, font=T.font(10, True),
                 width=8, anchor="w").pack(side="left")
        ent = tk.Entry(row, textvariable=var, bd=0, relief="flat",
                       bg=T.SURFACE_ALT, fg=T.TEXT, font=T.font(9),
                       insertbackground=T.BRAND, highlightthickness=1,
                       highlightbackground=T.BORDER,
                       highlightcolor=T.BORDER_FOCUS)
        ent.pack(side="left", fill="x", expand=True, ipady=6)

        def pick():
            if is_out:
                p = filedialog.asksaveasfilename(
                    title="选择输出文件", defaultextension=".xlsx",
                    filetypes=[("Excel 工作簿", "*.xlsx")])
            else:
                p = filedialog.askopenfilename(
                    title="选择输入文件",
                    filetypes=[("Excel 工作簿", "*.xlsx *.xlsm")])
            if p:
                var.set(os.path.normpath(p))
                if not is_out:
                    _on_pick_input(p)
                else:
                    _sync()
        T.flat_button(row, "浏览…", pick).pack(side="left", padx=(8, 0))
        return ent

    file_row(inner2, "输入文件", state["in_file"], False)
    file_row(inner2, "输出文件", state["out_file"], True)

    opt = tk.Frame(inner2, bg=T.SURFACE)
    opt.pack(fill="x", pady=(8, 4))
    tk.Label(opt, text="选项", bg=T.SURFACE, fg=T.TEXT, font=T.font(10, True),
             width=8, anchor="w").pack(side="left")
    ttk.Checkbutton(opt, text="跳过首行表头", variable=state["skip_header"]) \
        .pack(side="left", padx=(0, 16))
    ttk.Checkbutton(opt, text="解密后把纯数字还原为数值",
                    variable=state["restore_number"]).pack(side="left", padx=(0, 16))
    tk.Label(opt, text="工作表", bg=T.SURFACE, fg=T.TEXT_MUTED,
             font=T.font(9)).pack(side="left", padx=(8, 6))
    sheet_box = ttk.Combobox(opt, textvariable=state["sheet"], width=18,
                             state="readonly", values=["（全部工作表）"])
    sheet_box.pack(side="left")

    # ---------------- 操作 + 日志 ----------------
    card3 = T.Card(body)
    card3.pack(fill="both", expand=True)
    inner3 = card3.body

    bar = tk.Frame(inner3, bg=T.SURFACE)
    bar.pack(fill="x")
    btn_enc = T.flat_button(bar, "🔒 加密", lambda: _run(False), kind="primary")
    btn_enc.pack(side="left", padx=(0, 10))
    btn_dec = T.flat_button(bar, "🔓 解密", lambda: _run(True))
    btn_dec.pack(side="left", padx=(0, 10))
    btn_tpl = T.flat_button(bar, "📄 生成模板", _make_template, kind="ghost")
    btn_tpl.pack(side="left", padx=(0, 10))
    btn_open = T.flat_button(bar, "📂 打开输出位置", _open_out, kind="ghost")
    btn_open.pack(side="left")

    prog = ttk.Progressbar(inner3, mode="indeterminate")
    prog.pack(fill="x", pady=(12, 8))

    log = T.make_text(inner3, height=9, mono_font=True, state="disabled")
    log.pack(fill="both", expand=True)

    status = T.StatusBar(inner3)
    status.pack(fill="x", pady=(8, 0))

    # ---------------- 逻辑 ----------------
    def _log(msg):
        log.configure(state="normal")
        log.insert("end", msg + "\n")
        log.see("end")
        log.configure(state="disabled")
        root.update_idletasks()

    def _sync(*_):
        need_key = seg.get() != "basic"
        key_entry.configure(state="normal" if need_key else "disabled")
        key_btn.configure(state="normal" if need_key else "disabled")
        src = state["in_file"].get().strip()
        dst = state["out_file"].get().strip()
        if src and not dst:
            base, ext = os.path.splitext(src)
            tag = "dec" if _guess_decrypt(src) else "enc"
            state["out_file"].set("%s_%s%s" % (base, tag, ext or ".xlsx"))
        elif src and dst:
            pass

    def _guess_decrypt(path):
        """根据文件里的元信息猜这是加密文件还是原始文件。"""
        meta = read_meta(path)
        return bool(meta)

    def _on_pick_input(path):
        meta = read_meta(path)
        names = ["（全部工作表）"]
        try:
            openpyxl = _load_openpyxl()
            wb = openpyxl.load_workbook(path, read_only=True)
            names += [n for n in wb.sheetnames if n != META_SHEET]
            wb.close()
        except Exception:                                   # noqa: BLE001
            pass
        sheet_box.configure(values=names)
        if state["sheet"].get() not in names:
            state["sheet"].set("（全部工作表）")

        if meta and meta.get("mode") in MODE_NAMES:
            seg.select(meta["mode"])
            _log("检测到这是 %s 加密的工作簿（%s）"
                 % (MODE_NAMES[meta["mode"]], meta.get("created", "未知时间")))
            base, ext = os.path.splitext(path)
            state["out_file"].set(base + "_dec" + (ext or ".xlsx"))
        else:
            base, ext = os.path.splitext(path)
            state["out_file"].set(base + "_enc" + (ext or ".xlsx"))
        _sync()

    def _set_running(on):
        state["running"] = on
        for b in (btn_enc, btn_dec, btn_tpl):
            b.configure(state="disabled" if on else "normal")
        if on:
            prog.start(12)
        else:
            prog.stop()

    def _run(decrypt):
        if state["running"]:
            return
        src = state["in_file"].get().strip()
        dst = state["out_file"].get().strip()
        mode = seg.get()
        key = state["key"].get()
        if not src:
            messagebox.showwarning(TOOL_NAME, "请先选择输入文件。", parent=root)
            return
        if not dst:
            messagebox.showwarning(TOOL_NAME, "请先指定输出文件。", parent=root)
            return
        if os.path.abspath(src) == os.path.abspath(dst):
            messagebox.showwarning(TOOL_NAME, "输出文件不能与输入文件相同，请换个路径。",
                                   parent=root)
            return
        if not decrypt and mode != "basic" and not key:
            messagebox.showwarning(TOOL_NAME, "%s模式必须填写密钥。" % MODE_NAMES[mode],
                                   parent=root)
            return

        sheet = state["sheet"].get()
        sheet = None if sheet.startswith("（") else sheet
        _set_running(True)
        _log("─" * 62)
        _log("%s · 模式 %s · %s" % ("解密" if decrypt else "加密",
                                    MODE_NAMES[mode], os.path.basename(src)))
        status.set("处理中……", "info")

        try:
            result = process_workbook(
                src, dst, key, mode, decrypt,
                sheet=sheet, skip_header=state["skip_header"].get(),
                restore_number=state["restore_number"].get(),
                progress=lambda done, _total: status.set("已处理 %d 个单元格……" % done),
                log=_log)
        except ExcelError as exc:
            _set_running(False)
            status.set("失败", "err")
            _log("✗ " + str(exc))
            messagebox.showerror(TOOL_NAME, str(exc), parent=root)
            return
        except Exception as exc:                            # noqa: BLE001
            _set_running(False)
            status.set("发生未预期的错误", "err")
            _log(traceback.format_exc())
            messagebox.showerror(TOOL_NAME, "发生未预期的错误：\n%s" % exc, parent=root)
            return

        _set_running(False)
        if result["missing"]:
            status.set("完成，但有 %d 个字符不在码书中被跳过" % len(result["missing"]),
                       "warn")
            _log("⚠ 以下字符不在码书中，已被跳过：%s"
                 % " ".join(result["missing"]))
        else:
            status.set("完成：共处理 %d 个单元格，已保存到 %s"
                       % (result["cells"], os.path.basename(dst)), "ok")
        if result["skipped"]:
            _log("（另有 %d 个公式单元格被跳过）" % result["skipped"])
        messagebox.showinfo(TOOL_NAME,
                            "处理完成。\n\n工作表：%s\n单元格：%d 个\n输出：%s"
                            % ("、".join(s["title"] for s in result["sheets"]),
                               result["cells"], dst),
                            parent=root)

    def _make_template():
        p = filedialog.asksaveasfilename(
            title="保存 Excel 模板", defaultextension=".xlsx",
            initialfile="BDEF_excel_template.xlsx",
            filetypes=[("Excel 工作簿", "*.xlsx")])
        if not p:
            return
        try:
            build_template(p)
            _log("已生成模板：%s" % p)
            status.set("模板已生成：%s" % p, "ok")
            messagebox.showinfo(TOOL_NAME, "模板已生成：\n%s" % p, parent=root)
        except Exception as exc:                            # noqa: BLE001
            messagebox.showerror(TOOL_NAME, "生成模板失败：%s" % exc, parent=root)

    def _open_out():
        dst = state["out_file"].get().strip() or state["in_file"].get().strip()
        if not dst:
            messagebox.showinfo(TOOL_NAME, "还没有输出文件。", parent=root)
            return
        folder = os.path.dirname(os.path.abspath(dst))
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)                        # noqa: S606
            elif sys.platform == "darwin":
                os.system('open "%s"' % folder)             # noqa: S605
            else:
                os.system('xdg-open "%s"' % folder)         # noqa: S605
        except Exception as exc:                            # noqa: BLE001
            messagebox.showerror(TOOL_NAME, "无法打开目录：%s" % exc, parent=root)

    _sync()
    _log("就绪。请选择要处理的 Excel 文件。")
    _log("提示：三种模式必须与加密时保持一致，否则无法解密。")
    status.set("就绪", "info")
    root.mainloop()
    return 0


# ==========================================================================
# 自检
# ==========================================================================


def _selftest() -> int:
    """用临时文件跑一遍三种模式的 Excel 往返，验证数据无损。"""
    import tempfile

    openpyxl = _load_openpyxl()
    ok = True
    tmp = tempfile.mkdtemp(prefix="bdef_excel_selftest_")
    src = os.path.join(tmp, "src.xlsx")
    build_template(src)

    def snapshot(path):
        wb = openpyxl.load_workbook(path)
        data = {}
        for ws in wb.worksheets:
            if ws.title == META_SHEET:
                continue
            for row in ws.iter_rows():
                for c in row:
                    if c.value is not None:
                        data[(ws.title, c.coordinate)] = str(c.value)
        wb.close()
        return data

    original = snapshot(src)
    print("基准文件：%d 个非空单元格" % len(original))

    cases = [("basic", "", "基础编码"), ("multi", "kk-123", "多对多"),
             ("aes", "kk-123", "AES 叠加")]
    for mode, key, name in cases:
        enc = os.path.join(tmp, "enc_%s.xlsx" % mode)
        dec = os.path.join(tmp, "dec_%s.xlsx" % mode)
        process_workbook(src, enc, key, mode, False)
        process_workbook(enc, dec, key, mode, True)
        got = snapshot(dec)
        diff = [k for k in original if original.get(k) != got.get(k)]
        ok &= (not diff)
        print("[%s] 往返：%s" % (name, "通过" if not diff else "失败 -> %s" % diff[:5]))

    # 错误密钥必须失败
    wrong = os.path.join(tmp, "wrong.xlsx")
    try:
        process_workbook(os.path.join(tmp, "enc_aes.xlsx"), wrong,
                         "wrong-key", "aes", True)
        ok = False
        print("[AES 错误密钥] 失败：竟然解密成功了")
    except Exception as exc:                                # noqa: BLE001
        print("[AES 错误密钥] 通过：被拒绝（%s）" % str(exc)[:44])

    # 长数字必须保持文本，不能变浮点
    long_num = "420106199001011234"
    got = text_to_cell(long_num, True)
    good = (got == long_num and isinstance(got, str))
    ok &= good
    print("[长数字保护] %s（18 位身份证号仍为文本）" % ("通过" if good else "失败"))
    print("[前导零保护] %s" % ("通过" if text_to_cell("007", True) == "007"
                               else "失败"))
    print("[普通数字还原] %s" % ("通过" if text_to_cell("12345", True) == 12345
                                 else "失败"))
    print("\n自检结果：%s" % ("全部通过" if ok else "存在失败"))
    print("（临时文件目录：%s）" % tmp)
    return 0 if ok else 1


# ==========================================================================
# 命令行
# ==========================================================================


def cli(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="bdef_excel.py",
        description="BDEF 编码法 · Excel 数据加解密工具")
    sub = parser.add_subparsers(dest="cmd")

    p_tpl = sub.add_parser("template", help="生成 Excel 模板")
    p_tpl.add_argument("-o", "--output", default="BDEF_excel_template.xlsx")

    sub.add_parser("selftest", help="跑一遍三种模式的往返自检")

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help="%s数据" % ("加密" if name == "encrypt" else "解密"))
        p.add_argument("-i", "--input", required=True)
        p.add_argument("-o", "--output", required=True)
        p.add_argument("-k", "--key", default="")
        p.add_argument("-m", "--mode", default="aes", choices=list(MODE_NAMES))
        p.add_argument("-s", "--sheet", default=None)
        p.add_argument("--no-skip-header", action="store_true",
                       help="不跳过首行表头（默认跳过）")
        p.add_argument("--no-restore-number", action="store_true",
                       help="解密后不把纯数字还原为数值")
        p.add_argument("-c", "--columns", default=None,
                       help="只处理指定列，如 B,C,D 或 2,3,4")

    args = parser.parse_args(argv)

    if args.cmd is None:
        return run_gui()

    if args.cmd == "template":
        path = build_template(args.output)
        print("模板已生成：%s" % path)
        return 0

    if args.cmd == "selftest":
        return _selftest()

    columns = None
    if getattr(args, "columns", None):
        from openpyxl.utils import column_index_from_string
        columns = []
        for part in args.columns.split(","):
            part = part.strip()
            if not part:
                continue
            columns.append(int(part) if part.isdigit()
                           else column_index_from_string(part.upper()))

    try:
        result = process_workbook(
            args.input, args.output, args.key, args.mode,
            args.cmd == "decrypt", sheet=args.sheet,
            skip_header=not args.no_skip_header,
            columns=columns,
            restore_number=not args.no_restore_number,
            log=lambda m: print("  " + m))
    except ExcelError as exc:
        print("错误：%s" % exc, file=sys.stderr)
        return 1

    print("\n完成：处理 %d 个单元格，跳过 %d 个公式单元格。"
          % (result["cells"], result["skipped"]))
    if result["missing"]:
        print("注意：以下字符不在码书中，已被跳过：%s"
              % " ".join(result["missing"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
