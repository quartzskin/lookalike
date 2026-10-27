"""Tiny QR writer for tests (byte mode, versions 1-6, one mask of your choice)."""
import struct
import zlib

BLOCKS = {
    1: {"L": (7, [19]), "M": (10, [16]), "Q": (13, [13]), "H": (17, [9])},
    2: {"L": (10, [34]), "M": (16, [28]), "Q": (22, [22]), "H": (28, [16])},
    3: {"L": (15, [55]), "M": (26, [44]), "Q": (18, [17] * 2), "H": (22, [13] * 2)},
    4: {"L": (20, [80]), "M": (18, [32] * 2), "Q": (26, [24] * 2), "H": (16, [9] * 4)},
    5: {"L": (26, [108]), "M": (24, [43] * 2), "Q": (18, [15] * 2 + [16] * 2), "H": (22, [11] * 2 + [12] * 2)},
    6: {"L": (18, [68] * 2), "M": (16, [27] * 4), "Q": (24, [19] * 4), "H": (28, [15] * 4)},
}
ECL_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}


def gf_tables():
    exp, log, x = [0] * 512, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 256:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


EXP, LOG = gf_tables()


def gmul(a, b):
    return 0 if not a or not b else EXP[LOG[a] + LOG[b]]


def rs_ecc(data, n):
    gen = [1]
    for i in range(n):
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= gmul(c, EXP[i])
        gen = nxt
    rem = [0] * n
    for b in data:
        f = b ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(n):
            rem[j] ^= gmul(gen[j + 1], f)
    return rem


MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def build(text, ecl="L", mask=0, version=None, corrupt=0):
    payload = text.encode("utf-8")
    for v in range(1, 7):
        ecc, sizes = BLOCKS[v][ecl]
        if 4 + 8 + 8 * len(payload) <= 8 * sum(sizes):
            break
    else:
        raise ValueError("too long")
    if version:
        v = version
        ecc, sizes = BLOCKS[v][ecl]
    bits = "0100" + format(len(payload), "08b") + "".join(format(b, "08b") for b in payload)
    cap = 8 * sum(sizes)
    bits += "0" * min(4, cap - len(bits))
    bits += "0" * (-len(bits) % 8)
    data = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    while len(data) < sum(sizes):
        data.append(pad[(len(data) - len(bits) // 8) % 2])
    blocks, pos = [], 0
    for s in sizes:
        blocks.append(data[pos:pos + s])
        pos += s
    eccs = [rs_ecc(b, ecc) for b in blocks]
    cw = []
    for i in range(max(sizes)):
        cw += [b[i] for b in blocks if i < len(b)]
    for i in range(ecc):
        cw += [e[i] for e in eccs]
    for i in range(corrupt):
        cw[i] ^= 0x55
    n = 17 + 4 * v
    m = [[False] * n for _ in range(n)]
    fn = [[False] * n for _ in range(n)]

    def put(x, y, val):
        m[y][x] = val
        fn[y][x] = True

    for cx, cy in ((0, 0), (n - 7, 0), (0, n - 7)):
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                x, y = cx + dx, cy + dy
                if 0 <= x < n and 0 <= y < n:
                    ring = max(abs(dx - 3), abs(dy - 3))
                    put(x, y, ring in (0, 1, 3) and 0 <= dx < 7 and 0 <= dy < 7 and ring != 2)
    for i in range(8, n - 8):
        put(i, 6, i % 2 == 0)
        put(6, i, i % 2 == 0)
    if v >= 2:
        a = {2: 18, 3: 22, 4: 26, 5: 30, 6: 34}[v]
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                put(a + dx, a + dy, max(abs(dx), abs(dy)) != 1)
    data_bits = (ECL_BITS[ecl] << 3) | mask
    rem = data_bits
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    fmt = ((data_bits << 10) | rem) ^ 0x5412
    bit = lambda i: bool((fmt >> i) & 1)
    for i in range(6):
        put(8, i, bit(i))
    put(8, 7, bit(6))
    put(8, 8, bit(7))
    put(7, 8, bit(8))
    for i in range(9, 15):
        put(14 - i, 8, bit(i))
    for i in range(8):
        put(n - 1 - i, 8, bit(i))
    for i in range(8, 15):
        put(8, n - 15 + i, bit(i))
    put(8, n - 8, True)
    allbits = "".join(format(c, "08b") for c in cw)
    k, right = 0, n - 1
    while right >= 1:
        if right == 6:
            right = 5
        up = ((right + 1) & 2) == 0
        for vert in range(n):
            for j in range(2):
                x, y = right - j, (n - 1 - vert if up else vert)
                if not fn[y][x]:
                    b = k < len(allbits) and allbits[k] == "1"
                    k += 1
                    m[y][x] = b != MASKS[mask](x, y)
        right -= 2
    return m


def png(matrix, scale=4, quiet=4, color_type=0):
    n = len(matrix)
    side = (n + 2 * quiet) * scale
    rows = []
    for y in range(side):
        my = y // scale - quiet
        row = bytearray()
        for x in range(side):
            mx = x // scale - quiet
            dark = 0 <= mx < n and 0 <= my < n and matrix[my][mx]
            row += (b"\x00\x00\x00" if dark else b"\xff\xff\xff") if color_type == 2 else (b"\x00" if dark else b"\xff")
        rows.append(b"\x00" + bytes(row))
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    ihdr = struct.pack(">IIBBBBB", side, side, 8, color_type, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b"")
