# -*- coding: utf-8 -*-
"""
端口占用监控器 (Port Monitor)
=============================
一个用于查看本机端口占用情况的桌面小工具（Windows / macOS / Linux）。

功能:
  * 列出所有 TCP/UDP 连接: 端口、状态、PID、进程名、可执行文件路径
  * 即时搜索过滤 (支持端口号 / 进程名 / PID / 地址)
  * 一键"仅显示监听(LISTENING)端口"
  * 自动刷新 (默认间隔 3 秒, 可开关)
  * 点击表头排序
  * 结束占用进程、打开进程所在目录、导出 CSV
  * 可视化仪表盘 (连接状态分布 / Top 进程 / Top 端口 / 连接数趋势)
  * 数据来源优先使用 psutil (更快更全), 未安装时自动回退到 netstat + tasklist

用法:
  python port_monitor.py             # 启动图形界面
  python port_monitor.py --cli       # 命令行模式, 打印全部端口表
  python port_monitor.py --cli 8080  # 命令行模式, 只看与 8080 相关的连接
"""

import csv
import io
import os
import queue
import re
import subprocess
import sys
import threading
import time

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    psutil = None
    HAS_PSUTIL = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
if getattr(sys, "frozen", False):  # PyInstaller 打包后: __file__ 指向临时目录, 日志写到 exe 所在目录
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 数据采集层
# ---------------------------------------------------------------------------

def _decode(raw: bytes) -> str:
    """按常见编码顺序尝试解码命令输出 (Windows 中文系统控制台多为 GBK)。"""
    for enc in ("gbk", "utf-8"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def split_host_port(addr: str):
    """把 '0.0.0.0:8080' / '[::]:443' / '[fe80::1]:80' 拆成 (主机, 端口)。"""
    if addr.startswith("["):
        i = addr.rfind("]:")
        if i != -1:
            try:
                return addr[1:i], int(addr[i + 2:])
            except ValueError:
                return addr, 0
    if addr.count(":") == 1:
        host, port = addr.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return addr, 0
    return addr, 0


def _netstat_rows():
    """回退方案: netstat -ano + tasklist, 不依赖任何第三方库。"""
    out = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW,
    )
    text = _decode(out.stdout)

    pidmap = {}
    try:
        tl = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW,
        ).stdout
        for row in csv.reader(io.StringIO(_decode(tl))):
            if len(row) >= 2 and row[1].strip().isdigit():
                pidmap[int(row[1].strip())] = row[0].strip()
    except Exception:
        pass

    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        local = parts[1]
        foreign = parts[2]
        if proto == "TCP":
            state = parts[3] if len(parts) > 3 else ""
            pid = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
        else:
            state = ""
            pid = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
        host, port = split_host_port(local)
        rows.append(dict(
            proto=proto, local=host, port=port, foreign=foreign,
            state=state, pid=pid, name=pidmap.get(pid, ""), path="",
        ))
    return rows


def _psutil_rows():
    """优先方案: psutil.net_connections()。"""
    import socket as _sock
    rows = []
    for c in psutil.net_connections(kind="all"):
        if not c.laddr:
            continue
        try:
            proto = "TCP" if c.type == _sock.SOCK_STREAM else "UDP"
        except Exception:
            proto = "?"
        host, port = c.laddr.ip, c.laddr.port
        foreign = "{}:{}".format(c.raddr.ip, c.raddr.port) if c.raddr else "*"
        state = c.status or ""
        pid = c.pid or 0
        name, path = "", ""
        if pid:
            try:
                p = psutil.Process(pid)
                name = p.name() or ""
                try:
                    path = p.exe() or ""
                except Exception:
                    path = ""
            except Exception:
                name = "(未知/已退出)"
        elif pid == 0:
            name = "System"
        rows.append(dict(
            proto=proto, local=host, port=port, foreign=foreign,
            state=state, pid=pid, name=name, path=path,
        ))

    # 去掉重复条目 (如 UDP 同时以 inet/inet6 出现)
    seen, out = set(), []
    for r in rows:
        key = (r["proto"], r["local"], r["port"], r["foreign"], r["state"], r["pid"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def collect():
    """返回 (rows, source)。rows 为 dict 列表, 始终保证有数据返回。"""
    if HAS_PSUTIL:
        try:
            rows = _psutil_rows()
            if rows:
                return rows, "psutil"
        except Exception:
            pass
    return _netstat_rows(), "netstat"


# ---------------------------------------------------------------------------
# 图形界面
# ---------------------------------------------------------------------------

# --- 主题色板 (现代化暗色) ---
BG      = "#0b1220"   # 窗口背景
BG2     = "#101c33"   # 表体背景 (偶数行)
BG_ODD  = "#0d182c"   # 表格奇数行
CARD    = "#131f36"   # 卡片/图表背景
HEAD_BG = "#1c2a44"   # 表头/面板背景
BORDER  = "#263652"   # 边框
FG      = "#e8eef8"   # 前景
MUTED   = "#8fa3bd"   # 次要文字
ACCENT  = "#38bdf8"   # 主强调 (天蓝)
ACCENT2 = "#818cf8"   # 次强调 (靛蓝)
GREEN   = "#34d399"   # 成功/监听
SEL_BG  = "#2563eb"   # 选中行

COLUMNS = ("协议", "本地地址", "端口", "外部地址", "状态", "PID", "进程名", "路径")
SORT_KEY = {
    "协议":     lambda r: r["proto"],
    "本地地址": lambda r: r["local"],
    "端口":     lambda r: r["port"],
    "外部地址": lambda r: r["foreign"],
    "状态":     lambda r: r["state"],
    "PID":      lambda r: r["pid"],
    "进程名":   lambda r: r["name"].lower(),
    "路径":     lambda r: r["path"].lower(),
}
WIDTHS = (60, 130, 70, 150, 100, 70, 160, 300)

STATE_TAG = {
    "LISTENING":  "listen",
    "ESTABLISHED": "established",
    "TIME_WAIT":  "timewait",
    "CLOSE_WAIT": "closewait",
    "SYN_SENT":   "syn",
}


def row_tag(r):
    if r["proto"] == "UDP":
        return "udp"
    if r["state"] in STATE_TAG:
        return STATE_TAG[r["state"]]
    return "other"


# --- 可视化配色 ---
STATE_COLORS = (
    ("LISTENING", "#4ade80"),
    ("ESTABLISHED", "#60a5fa"),
    ("TIME_WAIT", "#94a3b8"),
    ("CLOSE_WAIT", "#fbbf24"),
    ("SYN_SENT", "#fb923c"),
    ("UDP", "#c084fc"),
    ("其他", "#f87171"),
)
BAR_COLORS = ("#38bdf8", "#34d399", "#fbbf24", "#fb923c", "#a78bfa",
              "#60a5fa", "#f87171", "#22d3ee", "#a3e635", "#f472b6")


def _blend(c1, c2, t):
    """在两种 #rrggbb 颜色之间按比例 t (0~1) 插值。"""
    def ch(c):
        return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))
    a, b = ch(c1), ch(c2)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


class PortMonitorApp:
    def __init__(self, root):
        self.root = root
        root.title("端口占用监控器 · Port Monitor")
        root.geometry("1180x680")
        root.minsize(960, 560)
        root.configure(bg=BG)

        try:  # 窗口图标 (开发环境直接使用同目录 ico)
            _ico = os.path.join(APP_DIR, "port_monitor.ico")
            if os.path.exists(_ico):
                root.iconbitmap(_ico)
        except Exception:
            pass

        self.all_rows = []
        self.samples = []      # 趋势采样: [(HH:MM:SS, 连接总数), ...]
        self.sort_col = "端口"
        self.sort_rev = False
        self._clicked = False
        self._busy = False
        self._q = queue.Queue()
        self.source = "?"
        self._status_kind = "warn"
        self._hdr_status_id = None
        self._dash_timer = None
        self._hdr_timer = None

        self._build_style()
        self._build_header()
        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()

        # 事件
        root.bind("<Control-f>", lambda e: self.search_entry.focus_set())
        root.bind("<F5>", lambda e: self.start_refresh())
        root.bind("<Escape>", lambda e: self.search_var.set(""))
        root.bind("<Control-d>", lambda e: self.notebook.select(self.tab_dash))

        # 定时器
        self.root.after(80, self._poll)
        self.root.after(3000, self._auto_tick)

        self.start_refresh()

    # ---------- 界面构建 ----------

    def _build_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG,
                        font=("Microsoft YaHei UI", 10))
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("ChartTitle.TLabel", foreground="#c6d5ec",
                        font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("TSeparator", background=BORDER)

        # 普通按钮
        style.configure("TButton", background=HEAD_BG, foreground=FG,
                        bordercolor=HEAD_BG, focusthickness=0,
                        font=("Microsoft YaHei UI", 9), padding=(12, 6))
        style.map("TButton",
                  background=[("active", "#2c3f63"), ("disabled", "#182238")],
                  foreground=[("disabled", MUTED)])
        # 主按钮 (刷新)
        style.configure("Accent.TButton", background=ACCENT, foreground="#0b1220",
                        bordercolor=ACCENT, focusthickness=0,
                        font=("Microsoft YaHei UI", 9, "bold"), padding=(14, 6))
        style.map("Accent.TButton",
                  background=[("active", "#7dd3fc"), ("disabled", "#1e3a52")],
                  foreground=[("disabled", "#3b5a78")])
        # 危险按钮 (结束进程)
        style.configure("Danger.TButton", background="#dc2626", foreground="#ffffff",
                        bordercolor="#dc2626", focusthickness=0,
                        font=("Microsoft YaHei UI", 9, "bold"), padding=(12, 6))
        style.map("Danger.TButton",
                  background=[("active", "#ef4444"), ("disabled", "#3c1d22")],
                  foreground=[("disabled", "#96646b")])
        # 切换开关 (按钮式复选)
        style.layout("Toggle.TCheckbutton", [
            ("Button.button", {"children": [
                ("Button.focus", {"children": [
                    ("Button.label", {"side": "left", "expand": True})]})]})])
        style.configure("Toggle.TCheckbutton", background=HEAD_BG,
                        foreground="#9fb3cd", bordercolor=BORDER, padding=(10, 5),
                        font=("Microsoft YaHei UI", 9))
        style.map("Toggle.TCheckbutton",
                  background=[("selected", ACCENT), ("active", "#2c3f63")],
                  foreground=[("selected", "#0b1220"), ("active", FG)])
        # 搜索框
        style.configure("Search.TEntry", fieldbackground="#0d1830", foreground=FG,
                        bordercolor=BORDER, insertcolor=FG, padding=5)
        # 表格
        style.configure("Treeview", background=BG2, fieldbackground=BG2,
                        foreground=FG, borderwidth=0, rowheight=30,
                        font=("Microsoft YaHei UI", 9))
        style.map("Treeview",
                  background=[("selected", SEL_BG)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background=HEAD_BG, foreground="#c3d2ea",
                        relief="flat", padding=(10, 8),
                        font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", "#2c3f63")])
        # 选项卡
        style.configure("TNotebook", background=BG, borderwidth=0,
                        tabmargins=(8, 6, 8, 0))
        style.configure("TNotebook.Tab", background=HEAD_BG, foreground="#9fb3cd",
                        padding=(18, 8), borderwidth=0,
                        font=("Microsoft YaHei UI", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT), ("active", "#2c3f63")],
                  foreground=[("selected", "#0b1220")])

    def _build_header(self):
        """顶部标题栏: 渐变背景 + 图标 + 标题 + 数据来源徽章 + 状态灯。"""
        self.header = tk.Canvas(self.root, height=64, bg=HEAD_BG,
                                highlightthickness=0, bd=0)
        self.header.pack(fill="x")
        self.header.bind("<Configure>",
                         lambda e: self._schedule_header_draw())

    def _schedule_header_draw(self):
        if getattr(self, "_hdr_timer", None):
            self.root.after_cancel(self._hdr_timer)
        self._hdr_timer = self.root.after(80, self._draw_header)

    def _draw_header(self):
        cv = self.header
        w, h = cv.winfo_width(), cv.winfo_height()
        cv.delete("hdr")
        cv.delete("grad")
        if w < 80 or h < 40:
            return
        # 水平渐变
        n = max(8, min(72, w // 5))
        for i in range(n):
            t = i / (n - 1)
            x0 = int(w * i / n)
            cv.create_rectangle(x0, 0, int(w * (i + 1) / n) + 1, h,
                                fill=_blend("#1a2b4a", "#0d1830", t),
                                outline="", tags="grad")
        # 左侧强调条
        cv.create_rectangle(0, 0, 4, h, fill=ACCENT, outline="", tags="hdr")
        # Logo + 标题
        self._draw_logo(cv, 31, h / 2, 30)
        cv.create_text(62, h / 2 - 10, anchor="w", text="端口占用监控器",
                       fill=FG, font=("Microsoft YaHei UI", 14, "bold"), tags="hdr")
        cv.create_text(62, h / 2 + 13, anchor="w",
                       text="Port Monitor · 本机 TCP/UDP 端口实时监控",
                       fill=MUTED, font=("Microsoft YaHei UI", 9), tags="hdr")
        # 数据来源徽章
        src = ("psutil" if self.source == "psutil"
               else ("netstat" if self.source == "netstat" else "…"))
        pw = 62
        px0, py0 = w - pw - 14, h / 2 - 11
        self._round_rect(cv, px0, py0, px0 + pw, py0 + 22, 11,
                         fill="#0b1220", outline=BORDER, width=1, tags="hdr")
        cv.create_text(px0 + pw / 2, py0 + 11, text=src, fill=ACCENT,
                       font=("Microsoft YaHei UI", 9, "bold"), tags="hdr")
        # 状态灯 + 状态文字
        tx = px0 - 34
        kind = getattr(self, "_status_kind", "ok")
        dot = {"ok": GREEN, "warn": "#fbbf24", "err": "#f87171"}.get(kind, GREEN)
        cv.create_oval(tx - 12, h / 2 - 4, tx - 4, h / 2 + 4, fill=dot,
                       outline="", tags="hdr")
        self._hdr_status_id = cv.create_text(
            tx - 18, h / 2, anchor="e",
            text=self.status_var.get() if hasattr(self, "status_var") else "",
            fill="#b9c9e2", font=("Microsoft YaHei UI", 9), tags="hdr")

    def _update_header_status(self):
        if getattr(self, "_hdr_status_id", None) is None:
            return
        try:
            self.header.itemconfigure(
                self._hdr_status_id,
                text=self.status_var.get() if hasattr(self, "status_var") else "")
        except tk.TclError:
            pass

    def _draw_logo(self, cv, cx, cy, s=30):
        """圆角方块 + 网络节点图形。"""
        x0, y0 = cx - s / 2, cy - s / 2
        self._round_rect(cv, x0, y0, x0 + s, y0 + s, s * 0.26,
                         fill=ACCENT, outline="", tags="hdr")
        pts = ((cx - 5.5, cy + 4.5), (cx + 2, cy - 5.5), (cx + 5.5, cy + 5))
        for (ax, ay), (bx, by) in ((pts[0], pts[1]), (pts[0], pts[2]),
                                   (pts[1], pts[2])):
            cv.create_line(ax, ay, bx, by, fill="#0b1220", width=1.6, tags="hdr")
        for x, y in pts:
            cv.create_oval(x - 2.6, y - 2.6, x + 2.6, y + 2.6,
                           fill="#0b1220", outline="", tags="hdr")

    def _round_rect(self, cv, x0, y0, x1, y1, r, **kw):
        """用平滑多边形绘制圆角矩形。"""
        r = max(0.0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
        pts = [(x0 + r, y0), (x1 - r, y0), (x1, y0 + r), (x1, y1 - r),
               (x1 - r, y1), (x0 + r, y1), (x0, y1 - r), (x0, y0 + r)]
        return cv.create_polygon(pts, smooth=True, **kw)

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(12, 10, 12, 8))
        bar.pack(fill="x")

        # 搜索组
        ttk.Label(bar, text="搜索:", style="Muted.TLabel").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._render())
        self.search_entry = ttk.Entry(bar, textvariable=self.search_var, width=24,
                                      style="Search.TEntry")
        self.search_entry.pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=10, pady=2)

        # 过滤组
        self.listen_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="仅监听端口", variable=self.listen_var,
                        style="Toggle.TCheckbutton",
                        command=self._render).pack(side="left", padx=(0, 4))
        self.auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="自动刷新", variable=self.auto_var,
                        style="Toggle.TCheckbutton").pack(side="left", padx=(0, 4))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=10, pady=2)

        # 操作组
        self.refresh_btn = ttk.Button(bar, text="刷新 (F5)", style="Accent.TButton",
                                      command=self.start_refresh)
        self.refresh_btn.pack(side="left", padx=(0, 4))
        self.kill_btn = ttk.Button(bar, text="结束进程", style="Danger.TButton",
                                   command=self.kill_selected, state="disabled")
        self.kill_btn.pack(side="left", padx=(0, 4))
        self.open_btn = ttk.Button(bar, text="打开目录", command=self.open_dir,
                                   state="disabled")
        self.open_btn.pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="导出 CSV", command=self.export_csv).pack(side="left")

        ttk.Label(bar, text="右键行查看更多操作", style="Muted.TLabel").pack(side="right")

    def _build_table(self, parent):
        wrap = ttk.Frame(parent, padding=(12, 4, 12, 4))
        wrap.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(wrap, columns=COLUMNS, show="headings",
                                 selectmode="extended")
        for i, (name, w) in enumerate(zip(COLUMNS, WIDTHS), 1):
            self.tree.heading("#%d" % i, text=name,
                              command=lambda c=name: self._sort_by(c))
            self.tree.column("#%d" % i, width=w, anchor="w" if i != 3 else "center",
                             stretch=(i == len(COLUMNS)))

        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        for tag, color in (("listen", "#4ade80"), ("established", "#60a5fa"),
                           ("timewait", "#94a3b8"), ("closewait", "#fbbf24"),
                           ("syn", "#fb923c"), ("udp", "#c084fc"),
                           ("other", "#f87171")):
            self.tree.tag_configure(tag, foreground=color)
        self.tree.tag_configure("even", background=BG2)
        self.tree.tag_configure("odd", background=BG_ODD)
        self.tree.tag_configure("empty", foreground="#5d6f8c")

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    # ---------- 可视化仪表盘 (纯 Canvas 自绘, 无第三方绘图库) ----------

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_list = ttk.Frame(self.notebook)
        self.tab_dash = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_list, text=" 端口列表 ")
        self.notebook.add(self.tab_dash, text=" 可视化仪表盘 ")

        self._build_table(self.tab_list)
        self._build_dashboard(self.tab_dash)
        self.notebook.bind("<<NotebookTabChanged>>",
                           lambda e: self._draw_dashboard())

    def _build_dashboard(self, parent):
        cards = tk.Frame(parent, bg=BG)
        cards.pack(fill="x", padx=12, pady=(10, 2))
        self._card_vars = {}
        specs = (("conn", "连接总数", ACCENT), ("listen", "监听端口", GREEN),
                 ("ports", "占用端口", ACCENT2), ("src", "数据来源", "#fbbf24"))
        for key, label, color in specs:
            card = tk.Frame(cards, bg=CARD, highlightthickness=1,
                            highlightbackground=BORDER)
            card.pack(side="left", padx=(0, 10), fill="x", expand=True)
            tk.Frame(card, bg=color, width=4).pack(side="left", fill="y")
            inner = tk.Frame(card, bg=CARD)
            inner.pack(side="left", fill="both", expand=True, padx=12, pady=8)
            tk.Label(inner, text=label, bg=CARD, fg=MUTED,
                     font=("Microsoft YaHei UI", 9)).pack(anchor="w")
            var = tk.StringVar(value="—")
            tk.Label(inner, textvariable=var, bg=CARD, fg=color,
                     font=("Microsoft YaHei UI", 20, "bold")).pack(anchor="w")
            self._card_vars[key] = var

        grid = ttk.Frame(parent, padding=(8, 2, 8, 8))
        grid.pack(fill="both", expand=True)
        for c in range(2):
            grid.columnconfigure(c, weight=1, uniform="dash")
            grid.rowconfigure(c, weight=1, uniform="dash")

        self.cv_state = self._chart_panel(grid, 0, 0, "连接状态分布")
        self.cv_proc = self._chart_panel(grid, 0, 1, "Top 进程连接数")
        self.cv_port = self._chart_panel(grid, 1, 0, "Top 端口连接数")
        self.cv_trend = self._chart_panel(grid, 1, 1, "连接数趋势 (每次刷新采样)")

    def _chart_panel(self, parent, r, c, title):
        box = ttk.Frame(parent, padding=(0, 4))
        box.grid(row=r, column=c, sticky="nsew", padx=5, pady=5)
        ttk.Label(box, text=title, style="ChartTitle.TLabel").pack(anchor="w")
        cv = tk.Canvas(box, bg=CARD, highlightthickness=0, bd=0)
        cv.pack(fill="both", expand=True)
        cv.bind("<Configure>", lambda e: self._schedule_dashboard_draw())
        return cv

    def _schedule_dashboard_draw(self):
        if getattr(self, "_dash_timer", None):
            self.root.after_cancel(self._dash_timer)
        self._dash_timer = self.root.after(120, self._draw_dashboard)

    def _draw_dashboard(self):
        rows = self.all_rows
        total = len(rows)
        listening = sum(1 for r in rows
                        if r["state"] == "LISTENING" or r["proto"] == "UDP")
        ports = {r["port"] for r in rows}
        self._card_vars["conn"].set(str(total))
        self._card_vars["listen"].set(str(listening))
        self._card_vars["ports"].set(str(len(ports)))
        self._card_vars["src"].set("psutil" if self.source == "psutil" else "netstat")

        for cv in (self.cv_state, self.cv_proc, self.cv_port, self.cv_trend):
            cv.delete("all")
        self._draw_state_donut(self.cv_state, rows)
        self._draw_top_bars(self.cv_proc, rows,
                            key=lambda r: r["name"] or ("PID %s" % r["pid"]))
        self._draw_top_bars(self.cv_port, rows, key=lambda r: str(r["port"]))
        self._draw_trend(self.cv_trend)

    def _center_text(self, cv, text):
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 40 or h < 40:
            return
        cv.create_text(w / 2, h / 2, text=text, fill=MUTED,
                       font=("Microsoft YaHei UI", 10), justify="center")

    def _draw_state_donut(self, cv, rows):
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 60 or h < 60:
            return
        counts = dict.fromkeys((k for k, _ in STATE_COLORS), 0)
        for r in rows:
            if r["proto"] == "UDP":
                counts["UDP"] += 1
            else:
                st = r["state"] or "其他"
                counts[st if st in counts else "其他"] += 1
        total = sum(counts.values())
        items = [(k, counts[k], c) for k, c in STATE_COLORS if counts[k] > 0]
        if total == 0:
            self._center_text(cv, "暂无数据")
            return
        r = min(w * 0.26, h * 0.38)
        cx, cy = w * 0.24, h * 0.52
        cv.create_oval(cx - r - 5, cy - r - 5, cx + r + 5, cy + r + 5,
                       outline="#24344f", width=1.5)
        start = 90.0
        for _, value, color in items:
            extent = -360.0 * value / total
            cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=start,
                          extent=extent, style=tk.PIESLICE, fill=color,
                          outline=CARD, width=2)
            start += extent
        hr = r * 0.60
        cv.create_oval(cx - hr, cy - hr, cx + hr, cy + hr, fill=CARD, outline=CARD)
        cv.create_text(cx, cy - 8, text=str(total), fill=FG,
                       font=("Microsoft YaHei UI", 16, "bold"))
        cv.create_text(cx, cy + 14, text="连接总数", fill=MUTED,
                       font=("Microsoft YaHei UI", 9))
        # 图例
        lx, ly = w * 0.52, h * 0.12
        step = min(22, (h - 40) / max(len(items), 1))
        for i, (label, value, color) in enumerate(items):
            yy = ly + i * step
            self._round_rect(cv, lx, yy, lx + 11, yy + 11, 3, fill=color, outline="")
            cv.create_text(lx + 19, yy + 6, anchor="w", fill=FG,
                           text="%s %d (%.0f%%)" % (label, value,
                                                     100.0 * value / total),
                           font=("Microsoft YaHei UI", 9))

    def _draw_top_bars(self, cv, rows, key):
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 60 or h < 60:
            return
        counts = {}
        for r in rows:
            k = key(r)
            counts[k] = counts.get(k, 0) + 1
        items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        if not items:
            self._center_text(cv, "暂无数据")
            return
        maxv = max(v for _, v in items) or 1
        pad_l, pad_r, pad_t, pad_b = 10, 36, 12, 10
        name_w = min(w * 0.34, 150)
        n = len(items)
        bh = max(8, min(20, (h - pad_t - pad_b) / n - 5))
        gap = max(3.0, bh * 0.45)
        track_x1 = w - pad_r
        for i, (name, value) in enumerate(items):
            y = pad_t + i * (bh + gap)
            bar_x0 = pad_l + name_w
            # 轨道
            self._round_rect(cv, bar_x0, y, track_x1, y + bh, bh / 2,
                             fill="#1a2842", outline="")
            # 数据条 (胶囊形)
            color = BAR_COLORS[i % len(BAR_COLORS)]
            bar_w = (track_x1 - bar_x0) * value / maxv
            if bar_w >= bh * 1.2:
                self._round_rect(cv, bar_x0, y, bar_x0 + bar_w, y + bh, bh / 2,
                                 fill=color, outline="")
            else:
                cv.create_rectangle(bar_x0, y, bar_x0 + max(bar_w, 3), y + bh,
                                    fill=color, outline="")
            label = name if len(name) <= 12 else name[:11] + "…"
            cv.create_text(pad_l, y + bh / 2, anchor="w", fill=FG,
                           text=label, font=("Microsoft YaHei UI", 9))
            cv.create_text(w - pad_r + 6, y + bh / 2, anchor="w", fill=MUTED,
                           text=str(value), font=("Microsoft YaHei UI", 9))

    def _draw_trend(self, cv):
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 60 or h < 60:
            return
        samples = self.samples
        if len(samples) < 2:
            self._center_text(cv, "暂无趋势数据\n开启「自动刷新」后逐次累积")
            return
        pad_l, pad_r, pad_t, pad_b = 42, 14, 16, 26
        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b
        vals = [s[1] for s in samples]
        vmin, vmax = min(vals), max(vals)
        if vmax == vmin:
            vmax = vmin + 1

        def X(i):
            return pad_l + plot_w * i / (len(samples) - 1)

        def Y(v):
            return pad_t + plot_h * (1 - (v - vmin) / (vmax - vmin))

        for g in range(4):
            gy = pad_t + plot_h * g / 3
            cv.create_line(pad_l, gy, w - pad_r, gy, fill="#233352")
            cv.create_text(pad_l - 6, gy, anchor="e", fill=MUTED,
                           text=str(round(vmax - (vmax - vmin) * g / 3)),
                           font=("Microsoft YaHei UI", 8))
        pts = [(X(i), Y(v)) for i, v in enumerate(vals)]
        cv.create_polygon(pts + [(X(len(samples) - 1), pad_t + plot_h),
                                 (pad_l, pad_t + plot_h)],
                          fill=ACCENT2, stipple="gray50", outline="")
        cv.create_line(pts, fill=ACCENT, width=2)
        for x, y in pts:
            cv.create_oval(x - 2.5, y - 2.5, x + 2.5, y + 2.5,
                           fill=ACCENT, outline=CARD, width=1)
        cv.create_text(pad_l, h - 8, anchor="w", text=samples[0][0], fill=MUTED,
                       font=("Microsoft YaHei UI", 8))
        cv.create_text(w - pad_r, h - 8, anchor="e", text=samples[-1][0],
                       fill=MUTED, font=("Microsoft YaHei UI", 8))

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", side="bottom")
        tk.Frame(bar, bg=BORDER, height=1).pack(fill="x")
        row = tk.Frame(bar, bg=BG)
        row.pack(fill="x", padx=12, pady=(7, 8))
        self.status_dot = tk.Canvas(row, width=10, height=10, bg=BG,
                                    highlightthickness=0, bd=0)
        self.status_dot.pack(side="left")
        self.status_var = tk.StringVar(value="正在扫描端口…")
        tk.Label(row, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(side="left", padx=(7, 0))
        tk.Label(row, text="双击复制地址 · Ctrl+D 切换视图 · F5 刷新",
                 bg=BG, fg="#5d6f8c",
                 font=("Microsoft YaHei UI", 9)).pack(side="right")

    def _set_status(self, text, kind="ok"):
        self.status_var.set(text)
        self._status_kind = kind
        dot = {"ok": GREEN, "warn": "#fbbf24", "err": "#f87171"}.get(kind, GREEN)
        try:
            self.status_dot.delete("all")
            self.status_dot.create_oval(2, 2, 8, 8, fill=dot, outline="")
        except tk.TclError:
            pass
        self._update_header_status()

    # ---------- 刷新流程 (后台线程采集, 避免界面卡顿) ----------

    def start_refresh(self):
        if self._busy:
            return
        self._busy = True
        self._set_status("正在扫描端口…", "warn")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            rows, source = collect()
            self._q.put(("done", rows, source, None))
        except Exception as e:  # noqa: BLE001
            self._q.put(("done", [], "?", str(e)))

    def _poll(self):
        try:
            msg = self._q.get_nowait()
        except queue.Empty:
            self.root.after(80, self._poll)
            return
        if msg[0] == "done":
            self._busy = False
            rows, source, err = msg[1], msg[2], msg[3]
            if err:
                self._set_status("扫描失败", "err")
                messagebox.showerror("扫描失败", "获取端口信息失败:\n%s" % err)
            else:
                self.source = source
                self.all_rows = rows
                self._render()
                self._update_status("已刷新")
                self.samples.append((time.strftime("%H:%M:%S"), len(rows)))
                if len(self.samples) > 120:
                    self.samples = self.samples[-120:]
                self._draw_dashboard()
        self.root.after(80, self._poll)

    def _auto_tick(self):
        if self.auto_var.get():
            self.start_refresh()
        self.root.after(3000, self._auto_tick)

    # ---------- 过滤 / 排序 / 渲染 ----------

    def _visible_rows(self):
        q = self.search_var.get().strip().lower()
        only_listen = self.listen_var.get()
        rows = []
        for r in self.all_rows:
            if only_listen and not (r["state"] == "LISTENING" or r["proto"] == "UDP"):
                continue
            if q:
                if q.isdigit():
                    if not (str(r["port"]).startswith(q) or str(r["pid"]).startswith(q)):
                        continue
                else:
                    hay = "{} {} {} {} {} {}".format(
                        r["local"], r["port"], r["foreign"], r["state"],
                        r["pid"], r["name"]).lower()
                    if q not in hay:
                        continue
            rows.append(r)
        return rows

    def _sort_by(self, name):
        if self.sort_col == name and self._clicked:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = name, False
            self._clicked = True
        self._render()

    def _render(self):
        rows = self._visible_rows()
        key = SORT_KEY.get(self.sort_col, lambda r: r["port"])
        rows.sort(key=key, reverse=self.sort_rev)

        for i, name in enumerate(COLUMNS, 1):
            if name == self.sort_col:
                arrow = " ▲" if not self.sort_rev else " ▼"
            else:
                arrow = ""
            self.tree.heading("#%d" % i, text=name + arrow)

        self.tree.delete(*self.tree.get_children())
        if not rows:
            self.tree.insert("", "end", values=("", "", "—", "", "", "",
                                                "未找到符合条件的连接", ""),
                             tags=("even", "empty"))
            return
        for i, r in enumerate(rows):
            bg = "even" if i % 2 == 0 else "odd"
            self.tree.insert("", "end", values=(
                r["proto"], r["local"], r["port"], r["foreign"],
                r["state"], r["pid"], r["name"], r["path"]),
                tags=(bg, row_tag(r)))
        self._on_select()

    def _on_select(self, event=None):
        has = bool(self._selected_rows())
        self.kill_btn.state(["!disabled"] if has else ["disabled"])
        self.open_btn.state(["!disabled"] if has else ["disabled"])

    def _update_status(self, prefix="已刷新"):
        rows = self._visible_rows()
        listening = sum(1 for r in rows if r["state"] == "LISTENING" or r["proto"] == "UDP")
        ports = {r["port"] for r in rows}
        when = time.strftime("%H:%M:%S")
        self._set_status("%s · 显示 %d 条 · 监听 %d · 占用端口 %d  |  来源: %s · %s"
                         % (prefix, len(rows), listening, len(ports),
                            self.source, when), "ok")

    # ---------- 交互 ----------

    def _selected_rows(self):
        out = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals and vals[6] != "未找到符合条件的连接":
                out.append(dict(zip(COLUMNS, vals)))
        return out

    def _on_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        vals = self.tree.item(iid, "values")
        if not vals or vals[2] == "—":
            return
        text = "{}:{}".format(vals[1], vals[2])
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("已复制 %s 到剪贴板" % text)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        vals = self.tree.item(iid, "values")
        if not vals or vals[2] == "—":
            return
        menu = tk.Menu(self.root, tearoff=0, bg=BG2, fg=FG,
                       activebackground=SEL_BG, activeforeground="#ffffff")
        menu.add_command(label="复制地址 %s:%s" % (vals[1], vals[2]),
                         command=lambda: self._copy_row(vals))
        menu.add_command(label="只显示该进程 (PID %s)" % vals[5],
                         command=lambda: self.search_var.set(str(vals[5])))
        menu.add_separator()
        menu.add_command(label="结束进程 %s" % vals[5], command=self.kill_selected)
        menu.add_command(label="打开所在目录", command=self.open_dir)
        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    def _copy_row(self, vals):
        self.root.clipboard_clear()
        self.root.clipboard_append("{} {}:{} {} {} {} {}".format(
            vals[0], vals[1], vals[2], vals[4], vals[5], vals[6], vals[3]))
        self.status_var.set("已复制连接信息")

    def kill_selected(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("结束进程", "请先选中要结束的进程对应的行。")
            return
        names = ", ".join("%s(PID %s)" % (r["进程名"] or "未知", r["PID"]) for r in rows)
        if not messagebox.askyesno("结束进程",
                                   "确定要强制结束以下进程吗?\n\n%s\n\n该操作不可撤销!" % names):
            return
        for r in rows:
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(r["PID"])],
                               capture_output=True, timeout=15,
                               creationflags=CREATE_NO_WINDOW)
            except Exception:
                pass
        self.start_refresh()

    def open_dir(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("打开目录", "请先选中一行。")
            return
        path = rows[0].get("路径") or ""
        if not path or not os.path.exists(path):
            messagebox.showwarning("打开目录",
                                   "无法获取可执行文件路径。\n(当前数据来源为 netstat, 不包含路径信息)")
            return
        try:
            os.startfile(os.path.dirname(path))  # noqa: S606  (仅 Windows)
        except Exception as e:
            messagebox.showerror("打开目录", str(e))

    def export_csv(self):
        rows = self._visible_rows()
        if not rows:
            messagebox.showinfo("导出", "当前没有可导出的数据。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")],
            initialfile="端口占用_%s.csv" % time.strftime("%Y%m%d_%H%M%S"))
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(COLUMNS)
                for r in rows:
                    w.writerow([r[c] for c in COLUMNS])
        except Exception as e:
            messagebox.showerror("导出失败", str(e))
            return
        messagebox.showinfo("导出成功", "已导出 %d 条记录到:\n%s" % (len(rows), path))


# ---------------------------------------------------------------------------
# 命令行模式
# ---------------------------------------------------------------------------

def main_cli(filters):
    try:  # 避免管道/重定向时中文乱码
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    rows, source = collect()
    if filters:
        q = filters[0].strip().lower()
        if q.isdigit():
            rows = [r for r in rows
                    if str(r["port"]).startswith(q) or str(r["pid"]).startswith(q)]
        else:
            rows = [r for r in rows if q in "{} {} {} {} {} {}".format(
                r["local"], r["port"], r["foreign"], r["state"],
                r["pid"], r["name"]).lower()]
    rows.sort(key=lambda r: (r["proto"], r["port"]))

    header = "{:<4}{:<22}{:>7}  {:<22}{:<12}{:>7}  {:<26}{}".format(
        "协议", "本地地址", "端口", "外部地址", "状态", "PID", "进程名", "路径")
    print(header)
    print("-" * len(header))
    for r in rows:
        print("{:<4}{:<22}{:>7}  {:<22}{:<12}{:>7}  {:<26}{}".format(
            r["proto"], r["local"], r["port"], r["foreign"],
            r["state"], r["pid"], r["name"][:26], r["path"]))
    listening = sum(1 for r in rows if r["state"] == "LISTENING" or r["proto"] == "UDP")
    print("\n共 %d 条连接 · 监听端口 %d 个 (数据来源: %s)" % (len(rows), listening, source))


def main():
    args = [a for a in sys.argv[1:]]
    if "--cli" in args or "-c" in args:
        rest = [a for a in args if a not in ("--cli", "-c")]
        main_cli(rest)
        return

    if os.name == "nt":
        try:  # 高分屏适配
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # noqa: F841
        except Exception:
            pass

    root = None
    try:
        root = tk.Tk()
        PortMonitorApp(root)
    except Exception:
        # pythonw 运行时错误不可见, 记录到日志文件便于排查
        try:
            with open(os.path.join(APP_DIR, "port_monitor.log"), "a",
                      encoding="utf-8") as f:
                import traceback
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S]\n"))
                f.write(traceback.format_exc())
                f.write("\n")
        except Exception:
            pass
        raise
    if root:
        root.mainloop()


if __name__ == "__main__":
    main()
