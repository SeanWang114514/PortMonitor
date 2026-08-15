# -*- coding: utf-8 -*-
"""生成 port_monitor.ico (256x256, 纯标准库, 超采样抗锯齿, PNG-in-ICO 格式)。

图案: 深色圆角底 + 天蓝色连接环 + 3x3 端口针脚点阵 (中心为琥珀色指示灯)。
"""
import math
import struct
import zlib

N = 256        # 输出尺寸
SS = 4         # 每个输出像素的超采样倍数 (有效分辨率 1024x1024)

# --- 颜色 ---
BG        = (15, 23, 42, 255)      # #0f172a
RING      = (56, 189, 248, 255)    # #38bdf8
PIN       = (34, 197, 94, 255)     # #22c55e
PIN_ALT   = (251, 191, 36, 255)    # #fbbf24 琥珀色
BG_SHADOW = (2, 6, 23, 255)        # #020617 底部微阴影


def inside_rounded_rect(x, y, x0, y0, x1, y1, r):
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def inside_circle(x, y, cx, cy, r):
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def inside_ring(x, y, cx, cy, r_in, r_out):
    d2 = (x - cx) ** 2 + (y - cy) ** 2
    return r_in * r_in <= d2 <= r_out * r_out


def pixel_color(x, y):
    """按绘制顺序返回 (r,g,b,a)。"""
    # 底部阴影 (圆角矩形, 向右下偏移)
    if inside_rounded_rect(x - 14, y - 10, 16, 16, N * SS - 16, N * SS - 16, 190):
        return BG_SHADOW
    # 主圆角底
    if inside_rounded_rect(x, y, 16, 16, N * SS - 16, N * SS - 16, 190):
        # 天蓝连接环
        if inside_ring(x, y, N * SS / 2, N * SS / 2 - 6, 300, 356):
            return RING
        # 针脚点阵
        for dx in (-160, 0, 160):
            for dy in (-160, 0, 160):
                if inside_circle(x, y, N * SS / 2 + dx, N * SS / 2 - 6 + dy, 52):
                    return PIN_ALT if (dx == 0 and dy == 0) else PIN
        return BG
    return (0, 0, 0, 0)


def render():
    rows = []
    for j in range(N):
        row = bytearray()
        for i in range(N):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    cr, cg, cb, ca = pixel_color(i * SS + sx, j * SS + sy)
                    r += cr; g += cg; b += cb; a += ca
            n = SS * SS
            row += bytes((r // n, g // n, b // n, a // n))
        rows.append(bytes(row))
    return rows


def png_bytes(width, height, rows):
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico_bytes(png):
    # 单张 256x256 (宽/高字段用 0 表示 256)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png), 22)
    return struct.pack("<HHH", 0, 1, 1) + entry + png


def main():
    rows = render()
    png = png_bytes(N, N, rows)
    ico = ico_bytes(png)
    with open("port_monitor.ico", "wb") as f:
        f.write(ico)
    # 自检: 头部与内嵌 PNG 魔数
    assert ico[:4] == b"\x00\x00\x01\x00", "ICO header broken"
    assert ico[22:26] == b"\x89PNG", "embedded PNG broken"
    print("port_monitor.ico written: %d bytes, %dx%d" % (len(ico), N, N))


if __name__ == "__main__":
    main()
