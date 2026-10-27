"""Minimal QR reader: clean, axis-aligned PNG screenshots, versions 1-6, no error correction."""
import struct
import zlib


class QRError(ValueError):
    pass


# version -> {ecl bits: (ecc codewords per block, [data codewords of each block])}
_BLOCKS = {
    1: {1: (7, [19]), 0: (10, [16]), 3: (13, [13]), 2: (17, [9])},
    2: {1: (10, [34]), 0: (16, [28]), 3: (22, [22]), 2: (28, [16])},
    3: {1: (15, [55]), 0: (26, [44]), 3: (18, [17] * 2), 2: (22, [13] * 2)},
    4: {1: (20, [80]), 0: (18, [32] * 2), 3: (26, [24] * 2), 2: (16, [9] * 4)},
    5: {1: (26, [108]), 0: (24, [43] * 2), 3: (18, [15] * 2 + [16] * 2), 2: (22, [11] * 2 + [12] * 2)},
    6: {1: (18, [68] * 2), 0: (16, [27] * 4), 3: (24, [19] * 4), 2: (28, [15] * 4)},
}
_ALIGN = {2: 18, 3: 22, 4: 26, 5: 30, 6: 34}
_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _png_gray(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise QRError("not a PNG file (only PNG images are supported)")
    pos, idat, plte = 8, [], None
    hdr = None
    while pos + 8 <= len(data):
        n, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if len(body) < n:
            raise QRError("truncated PNG")
        if kind == b"IHDR":
            hdr = struct.unpack(">IIBBBBB", body)
        elif kind == b"PLTE":
            plte = body
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
        pos += 12 + n
    if hdr is None or not idat:
        raise QRError("PNG has no image data")
    w, h, depth, ctype, _, _, interlace = hdr
    if interlace:
        raise QRError("interlaced PNG is not supported")
    if w * h > 16_000_000:
        raise QRError("image too large")
    chans = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype)
    if chans is None or depth not in (1, 2, 4, 8) or (depth < 8 and ctype not in (0, 3)):
        raise QRError("unsupported PNG format (colour type %d, depth %d)" % (ctype, depth))
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error as e:
        raise QRError("corrupt PNG data: %s" % e) from None
    stride = (w * chans * depth + 7) // 8
    bpp = max(1, chans * depth // 8)
    if len(raw) < (stride + 1) * h:
        raise QRError("PNG data shorter than its header says")
    rows, prev = [], bytearray(stride)
    for y in range(h):
        off = y * (stride + 1)
        ft, line = raw[off], bytearray(raw[off + 1:off + 1 + stride])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if ft == 1:
                line[i] = (line[i] + a) & 255
            elif ft == 2:
                line[i] = (line[i] + b) & 255
            elif ft == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else b if pb <= pc else c
                line[i] = (line[i] + pred) & 255
            elif ft != 0:
                raise QRError("bad PNG filter type")
        rows.append(line)
        prev = line
    gray = []
    for line in rows:
        out = []
        if depth < 8:
            mask = (1 << depth) - 1
            for x in range(w):
                bit = x * depth
                v = (line[bit // 8] >> (8 - depth - bit % 8)) & mask
                if ctype == 3:
                    i = v * 3
                    if plte is None or i + 3 > len(plte):
                        raise QRError("PNG palette missing")
                    out.append((plte[i] * 3 + plte[i + 1] * 6 + plte[i + 2]) // 10)
                else:
                    out.append(v * 255 // mask)
        elif ctype == 0:
            out = list(line)
        elif ctype == 4:
            out = [(line[i] * line[i + 1] + 255 * (255 - line[i + 1])) // 255 for i in range(0, len(line), 2)]
        elif ctype == 3:
            for v in line:
                i = v * 3
                if plte is None or i + 3 > len(plte):
                    raise QRError("PNG palette missing")
                out.append((plte[i] * 3 + plte[i + 1] * 6 + plte[i + 2]) // 10)
        else:
            step = chans
            for i in range(0, len(line), step):
                lum = (line[i] * 3 + line[i + 1] * 6 + line[i + 2]) // 10
                a = line[i + 3] if ctype == 6 else 255
                out.append((lum * a + 255 * (255 - a)) // 255)
        gray.append(out)
    return w, h, gray


def _to_matrix(w, h, gray):
    lo = min(map(min, gray))
    hi = max(map(max, gray))
    if hi - lo < 64:
        raise QRError("image has no contrast; no QR code found")
    thr = (lo + hi) // 2
    xs = [x for row in gray for x, v in enumerate(row) if v < thr]
    if not xs:
        raise QRError("no QR code found")
    ys = [y for y, row in enumerate(gray) if any(v < thr for v in row)]
    x0, x1, y0, y1 = min(xs), max(xs), ys[0], ys[-1]
    run = 0
    while x0 + run <= x1 and gray[y0][x0 + run] < thr:
        run += 1
    mod = run / 7
    if mod < 1:
        raise QRError("cannot find the finder pattern")
    width = x1 - x0 + 1
    size = round(width / mod)
    if size not in range(21, 42, 4) or abs((y1 - y0 + 1) - width) > mod * 2:
        raise QRError("unsupported or unreadable QR geometry (module grid %d); only versions 1-6, unrotated" % size)
    step = width / size
    stepy = (y1 - y0 + 1) / size
    return [[gray[int(y0 + (r + .5) * stepy)][int(x0 + (c + .5) * step)] < thr for c in range(size)]
            for r in range(size)]


def _format_codes():
    table = {}
    for ecl in range(4):
        for mask in range(8):
            data = ecl << 3 | mask
            rem = data
            for _ in range(10):
                rem = (rem << 1) ^ ((rem >> 9) * 0x537)
            table[(data << 10 | rem) ^ 0x5412] = (ecl, mask)
    return table


_FORMATS = _format_codes()


def _read_format(m):
    n = len(m)
    first = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(14 - i, 8) for i in range(9, 15)]
    second = [(n - 1 - i, 8) for i in range(8)] + [(8, n - 15 + i) for i in range(8, 15)]
    for coords in (first, second):
        val = sum(1 << i for i, (x, y) in enumerate(coords) if m[y][x])
        best = min(_FORMATS, key=lambda k: bin(k ^ val).count("1"))
        if bin(best ^ val).count("1") <= 3:
            return _FORMATS[best]
    raise QRError("format information unreadable")


def _function_map(v):
    n = 17 + 4 * v
    f = [[False] * n for _ in range(n)]

    def rect(x0, y0, w, h):
        for y in range(y0, y0 + h):
            for x in range(x0, x0 + w):
                f[y][x] = True

    rect(0, 0, 9, 9)
    rect(n - 8, 0, 8, 9)
    rect(0, n - 8, 9, 8)
    for i in range(n):
        f[6][i] = f[i][6] = True
    if v >= 2:
        rect(_ALIGN[v] - 2, _ALIGN[v] - 2, 5, 5)
    return f


_MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def _codewords(m, v, mask):
    n = len(m)
    f = _function_map(v)
    fn = _MASKS[mask]
    bits = []
    right = n - 1
    while right >= 1:
        if right == 6:
            right = 5
        up = ((right + 1) & 2) == 0
        for vert in range(n):
            for j in range(2):
                x = right - j
                y = n - 1 - vert if up else vert
                if not f[y][x]:
                    bits.append(m[y][x] != fn(x, y))
        right -= 2
    return bytes(sum(b << (7 - k) for k, b in enumerate(bits[i:i + 8])) for i in range(0, len(bits) - 7, 8))


def _syndromes_zero(block, nsym):
    for i in range(nsym):
        acc = 0
        for c in block:
            acc = (_EXP[_LOG[acc] + i] if acc else 0) ^ c
        if acc:
            return False
    return True


def _split_blocks(cw, v, ecl):
    ecc, sizes = _BLOCKS[v][ecl]
    total = sum(sizes) + ecc * len(sizes)
    if len(cw) < total:
        raise QRError("not enough codewords for this version")
    data = [bytearray() for _ in sizes]
    pos = 0
    for i in range(max(sizes)):
        for b, size in enumerate(sizes):
            if i < size:
                data[b].append(cw[pos])
                pos += 1
    eccs = [bytearray() for _ in sizes]
    for _ in range(ecc):
        for b in range(len(sizes)):
            eccs[b].append(cw[pos])
            pos += 1
    for d, e in zip(data, eccs):
        if not _syndromes_zero(bytes(d + e), ecc):
            raise QRError("symbol has errors and this reader does not do error correction")
    return b"".join(bytes(d) for d in data)


def _parse(data, v):
    bits = "".join(format(b, "08b") for b in data)
    pos, out = 0, []
    counts = {1: 10, 2: 9, 4: 8} if v < 10 else {}

    def take(k):
        nonlocal pos
        if pos + k > len(bits):
            raise QRError("data ends mid-segment")
        val = int(bits[pos:pos + k], 2)
        pos += k
        return val

    while pos + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 7:
            take(8)
        elif mode == 4:
            out.append(bytes(take(8) for _ in range(take(counts[4]))))
        elif mode == 2:
            n = take(counts[2])
            s = ""
            for _ in range(n // 2):
                a = take(11)
                if a >= 45 * 45:
                    raise QRError("bad alphanumeric data")
                s += _ALNUM[a // 45] + _ALNUM[a % 45]
            if n % 2:
                a = take(6)
                if a >= 45:
                    raise QRError("bad alphanumeric data")
                s += _ALNUM[a]
            out.append(s.encode())
        elif mode == 1:
            n = take(counts[1])
            s = ""
            while n > 0:
                k = min(3, n)
                s += str(take({1: 4, 2: 7, 3: 10}[k])).zfill(k)
                n -= k
            out.append(s.encode())
        else:
            raise QRError("unsupported QR segment mode %d" % mode)
    raw = b"".join(out)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def decode_matrix(m):
    n = len(m)
    if n not in range(21, 42, 4) or any(len(r) != n for r in m):
        raise QRError("matrix size is not a QR version 1-6")
    v = (n - 17) // 4
    ecl, mask = _read_format(m)
    return _parse(_split_blocks(_codewords(m, v, mask), v, ecl), v)


def decode_png(data):
    w, h, gray = _png_gray(data)
    return decode_matrix(_to_matrix(w, h, gray))
