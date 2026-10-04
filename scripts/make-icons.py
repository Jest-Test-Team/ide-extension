"""Renders the 128x128 Marketplace icons (pure Python, no image libraries). Run: python3 scripts/make-icons.py"""
import math, struct, zlib

S = 128
SS = 4  # supersampling factor

def png(path, px):
    raw = b''.join(b'\x00' + bytes(sum((list(p) for p in row), [])) for row in px)
    def chunk(t, d):
        c = struct.pack('>I', len(d)) + t + d
        return c + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    data = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', S, S, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')
    open(path, 'wb').write(data)

def rounded_rect(x0, y0, x1, y1, r):
    def f(x, y):
        if not (x0 <= x <= x1 and y0 <= y <= y1): return False
        cx = min(max(x, x0 + r), x1 - r); cy = min(max(y, y0 + r), y1 - r)
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r
    return f

def circle(cx, cy, r):
    return lambda x, y: (x - cx) ** 2 + (y - cy) ** 2 <= r * r

def ring(cx, cy, r, w):
    return lambda x, y: (r - w) ** 2 <= (x - cx) ** 2 + (y - cy) ** 2 <= r * r

def poly(pts):
    def f(x, y):
        inside = False
        j = len(pts) - 1
        for i in range(len(pts)):
            xi, yi = pts[i]; xj, yj = pts[j]
            if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
                inside = not inside
            j = i
        return inside
    return f

def rect(x0, y0, x1, y1):
    return lambda x, y: x0 <= x <= x1 and y0 <= y <= y1

def line(x0, y0, x1, y1, w):
    def f(x, y):
        dx, dy = x1 - x0, y1 - y0
        t = max(0, min(1, ((x - x0) * dx + (y - y0) * dy) / (dx * dx + dy * dy)))
        return (x - x0 - t * dx) ** 2 + (y - y0 - t * dy) ** 2 <= (w / 2) ** 2
    return f

def render(layers):
    px = []
    for y in range(S):
        row = []
        for x in range(S):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(SS):
                for sx in range(SS):
                    fx, fy = x + (sx + .5) / SS, y + (sy + .5) / SS
                    col = (0, 0, 0, 0)
                    for shape, c in layers:
                        if shape(fx, fy):
                            col = c
                    a = col[3] / 255
                    for k in range(3): acc[k] += col[k] * a
                    acc[3] += a
            n = SS * SS
            alpha = acc[3] / n
            row.append(tuple(int(round(acc[k] / acc[3])) if acc[3] else 0 for k in range(3)) + (int(round(alpha * 255)),))
        px.append(row)
    return px

BG = rounded_rect(4, 4, 124, 124, 22)
W = (245, 247, 250, 255)

def endpoint():
    shield = poly([(64, 20), (100, 32), (98, 70), (64, 108), (30, 70), (28, 32)])
    inner = poly([(64, 28), (92, 38), (90, 68), (64, 99), (38, 68), (36, 38)])
    blue = (21, 64, 120, 255)
    return [(BG, blue), (shield, W), (inner, blue),
            (line(64, 46, 50, 70, 4), W), (line(64, 46, 78, 70, 4), W), (line(78, 70, 78, 84, 4), W),
            (circle(64, 46, 7), W), (circle(50, 72, 6), W), (circle(78, 70, 6), W), (circle(78, 86, 5), (255, 176, 59, 255))]

def julia():
    purple = (58, 36, 96, 255)
    flame = poly([(64, 18), (82, 46), (92, 72), (86, 94), (64, 108), (42, 94), (36, 72), (46, 50), (54, 62), (58, 40)])
    core = poly([(64, 56), (74, 74), (72, 92), (64, 98), (56, 92), (54, 76)])
    bars = [(rect(24, 104 - h, 32, 108), W) for h in ()]
    return [(BG, purple), (flame, (255, 140, 66, 255)), (core, (255, 214, 102, 255))] + bars

def hw():
    green = (18, 84, 72, 255)
    layers = [(BG, green), (rounded_rect(36, 36, 92, 92, 6), W), (rounded_rect(46, 46, 82, 82, 3), green), (rounded_rect(54, 54, 74, 74, 2), (102, 224, 179, 255))]
    for i in range(4):
        p = 44 + i * 13
        layers += [(rect(p - 2, 20, p + 2, 36), W), (rect(p - 2, 92, p + 2, 108), W), (rect(20, p - 2, 36, p + 2), W), (rect(92, p - 2, 108, p + 2), W)]
    return layers

def pack():
    grey = (44, 52, 64, 255)
    return [(BG, grey),
            (rounded_rect(22, 22, 62, 62, 8), (77, 144, 230, 255)), (rounded_rect(66, 22, 106, 62, 8), (255, 140, 66, 255)),
            (rounded_rect(22, 66, 62, 106, 8), (102, 224, 179, 255)), (rounded_rect(66, 66, 106, 106, 8), W)]

for name, fn in [('endpoint-security', endpoint), ('julia-profiler', julia), ('hw-security', hw), ('security-pack', pack)]:
    png(f'extensions/{name}/icon.png', render(fn()))
    print('wrote', name)
