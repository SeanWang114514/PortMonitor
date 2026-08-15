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
  * 数据来源优先使用 psutil (更快更全), 未安装时自动回退到 netstat + tasklist

用法:
  python port_monitor.py             # 启动图形界面
  python port_monitor.py --cli       # 命令行模式, 打印全部端口表
  python port_monitor.py --cli 8080  # 命令行模式, 只看与 8080 相关的连接
"""

import csv
import io
import math
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

BG      = "#0f172a"   # 窗口背景
BG2     = "#1e293b"   # 表体背景
HEAD_BG = "#334155"   # 表头背景
FG      = "#e2e8f0"   # 前景
MUTED   = "#94a3b8"
ACCENT  = "#38bdf8"
SEL_BG  = "#2563eb"

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
WIDTHS = (60, 130, 70, 150, 100, 70, 160, 320)

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
BAR_COLORS = ("#38bdf8", "#4ade80", "#fbbf24", "#fb923c", "#c084fc",
              "#60a5fa", "#f87171", "#22d3ee", "#a3e635", "#f472b6")


class PortMonitorApp:
    def __init__(self, root):
        self.root = root
        root.title("端口占用监控器 · Port Monitor")
        root.geometry("1180x660")
        root.minsize(900, 480)
        root.configure(bg=BG)

        self.all_rows = []
        self.samples = []      # 趋势采样: [(HH:MM:SS, 连接总数), ...]
        self.sort_col = "端口"
        self.sort_rev = False
        self._clicked = False
        self._busy = False
        self._q = queue.Queue()
        self.source = "?"

        self._build_style()
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
        style.configure("TButton", background=HEAD_BG, foreground=FG,
                        bordercolor=HEAD_BG, focusthickness=0,
                        font=("Microsoft YaHei UI", 9))
        style.map("TButton",
                  background=[("active", "#475569"), ("disabled", BG2)],
                  foreground=[("disabled", MUTED)])
        style.configure("TCheckbutton", background=BG, foreground=FG,
                        font=("Microsoft YaHei UI", 9))
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("Treeview",
                        background=BG2, fieldbackground=BG2,
                        foreground=FG, borderwidth=0, rowheight=26,
                        font=("Microsoft YaHei UI", 9))
        style.map("Treeview",
                  background=[("selected", SEL_BG)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading",
                        background=HEAD_BG, foreground=FG,
                        relief="flat", padding=(8, 7),
                        font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", "#475569")])
        style.configure("TEntry", fieldbackground=BG2, foreground=FG,
                        bordercolor=HEAD_BG, insertcolor=FG)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=HEAD_BG, foreground=FG,
                        padding=(16, 6), font=("Microsoft YaHei UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "#0f172a")])

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(10, 8, 10, 6))
        bar.pack(fill="x")

        ttk.Label(bar, text="搜索:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._render())
        self.search_entry = ttk.Entry(bar, textvariable=self.search_var, width=26)
        self.search_entry.pack(side="left", padx=(4, 6))

        self.listen_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="仅监听端口", variable=self.listen_var,
                        command=self._render).pack(side="left", padx=4)

        self.auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="自动刷新", variable=self.auto_var).pack(side="left", padx=4)

        ttk.Button(bar, text="刷新 (F5)", command=self.start_refresh).pack(side="left", padx=4)

        self.kill_btn = ttk.Button(bar, text="结束进程", command=self.kill_selected)
        self.kill_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="打开目录", command=self.open_dir).pack(side="left", padx=4)
        ttk.Button(bar, text="导出 CSV", command=self.export_csv).pack(side="left", padx=4)

        ttk.Label(bar, text="提示: 双击复制地址 · Ctrl+D 可视化 · 右键更多操作",
                  style="Muted.TLabel").pack(side="right")

    def _build_table(self, parent):
        wrap = ttk.Frame(parent, padding=(10, 0, 10, 0))
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
                           ("other", "#f87171"), ("empty", "#64748b")):
            self.tree.tag_configure(tag, foreground=color)

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)

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
        cards = ttk.Frame(parent, padding=(10, 8, 10, 2))
        cards.pack(fill="x")
        self._card_vars = {}
        for key, label in (("conn", "连接总数"), ("listen", "监听端口"),
                           ("ports", "占用端口"), ("src", "数据来源")):
            box = ttk.Frame(cards, padding=(10, 6))
            box.pack(side="left", padx=(0, 10), fill="x", expand=True)
            ttk.Label(box, text=label, style="Muted.TLabel").pack(anchor="w")
            var = tk.StringVar(value="—")
            ttk.Label(box, textvariable=var,
                      font=("Microsoft YaHei UI", 15, "bold"),
                      foreground=ACCENT).pack(anchor="w")
            self._card_vars[key] = var

        grid = ttk.Frame(parent, padding=(10, 2, 10, 10))
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
        box.grid(row=r, column=c, sticky="nsew", padx=4, pady=4)
        ttk.Label(box, text=title, style="Muted.TLabel").pack(anchor="w")
        cv = tk.Canvas(box, bg=BG2, highlightthickness=0, bd=0)
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
        r = min(w * 0.28, h * 0.40)
        cx, cy = w * 0.24, h * 0.52
        start = 90.0
        for _, value, color in items:
            extent = -360.0 * value / total
            cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=start,
                          extent=extent, style=tk.PIESLICE, fill=color,
                          outline=BG2, width=2)
            start += extent
        hr = r * 0.62
        cv.create_oval(cx - hr, cy - hr, cx + hr, cy + hr, fill=BG2, outline=BG2)
        cv.create_text(cx, cy - 6, text=str(total), fill=FG,
                       font=("Microsoft YaHei UI", 14, "bold"))
        cv.create_text(cx, cy + 14, text="连接总数", fill=MUTED,
                       font=("Microsoft YaHei UI", 8))
        # 图例
        lx, ly = w * 0.54, h * 0.14
        step = min(20, (h - 30) / max(len(items), 1))
        for i, (label, value, color) in enumerate(items):
            yy = ly + i * step
            cv.create_rectangle(lx, yy, lx + 12, yy + 12, fill=color, outline="")
            cv.create_text(lx + 20, yy + 6, anchor="w", fill=FG,
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
        pad_l, pad_r, pad_t, pad_b = 10, 34, 12, 8
        name_w = min(w * 0.34, 150)
        n = len(items)
        bh = max(6, min(20, (h - pad_t - pad_b) / n - 4))
        gap = max(2.0, bh * 0.35)
        for i, (name, value) in enumerate(items):
            y = pad_t + i * (bh + gap)
            bar_x0 = pad_l + name_w
            bar_w = (w - pad_r - bar_x0) * value / maxv
            color = BAR_COLORS[i % len(BAR_COLORS)]
            cv.create_rectangle(bar_x0, y, bar_x0 + max(bar_w, 2), y + bh,
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
            cv.create_line(pad_l, gy, w - pad_r, gy, fill=HEAD_BG)
            cv.create_text(pad_l - 6, gy, anchor="e", fill=MUTED,
                           text=str(round(vmax - (vmax - vmin) * g / 3)),
                           font=("Microsoft YaHei UI", 8))
        pts = [(X(i), Y(v)) for i, v in enumerate(vals)]
        cv.create_polygon(pts + [(X(len(samples) - 1), pad_t + plot_h),
                                 (pad_l, pad_t + plot_h)],
                          fill=ACCENT, stipple="gray50", outline="")
        cv.create_line(pts, fill=ACCENT, width=2)
        for x, y in pts:
            cv.create_oval(x - 2, y - 2, x + 2, y + 2, fill=ACCENT, outline="")
        cv.create_text(pad_l, h - 8, anchor="w", text=samples[0][0], fill=MUTED,
                       font=("Microsoft YaHei UI", 8))
        cv.create_text(w - pad_r, h - 8, anchor="e", text=samples[-1][0],
                       fill=MUTED, font=("Microsoft YaHei UI", 8))

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(10, 6))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="正在扫描端口…")
        ttk.Label(bar, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")

    # ---------- 刷新流程 (后台线程采集, 避免界面卡顿) ----------

    def start_refresh(self):
        if self._busy:
            return
        self._busy = True
        self.status_var.set("正在扫描端口…")
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
            self.tree.insert("", "end", values=("", "", "—", "", "", "", "未找到符合条件的连接", ""),
                             tags=("empty",))
            return
        for r in rows:
            self.tree.insert("", "end", values=(
                r["proto"], r["local"], r["port"], r["foreign"],
                r["state"], r["pid"], r["name"], r["path"]), tags=(row_tag(r),))

    def _update_status(self, prefix="已刷新"):
        rows = self._visible_rows()
        listening = sum(1 for r in rows if r["state"] == "LISTENING" or r["proto"] == "UDP")
        ports = {r["port"] for r in rows}
        when = time.strftime("%H:%M:%S")
        self.status_var.set(
            "%s · 显示 %d 条连接 · 监听端口 %d 个 · 占用端口 %d 个  |  来源: %s · 上次刷新 %s"
            % (prefix, len(rows), listening, len(ports), self.source, when))

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
