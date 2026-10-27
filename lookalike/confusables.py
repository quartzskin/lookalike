import unicodedata

# ascii letter -> code points (hex) that render almost identically.
# Characters NFKC already folds to ASCII (roman numerals, fullwidth) are left out.
_SETS = {
    "a": "0430 0251 03B1",
    "c": "0441 1D04",
    "d": "0501 0257",
    "e": "0435",
    "f": "03DD",
    "g": "0261 0581",
    "h": "04BB 0570",
    "i": "0456 0131 03B9 0269",
    "j": "0458 03F3",
    "k": "03BA 043A",
    "l": "04CF 01C0",
    "n": "0578 057C",
    "o": "043E 03BF 0585 1D0F",
    "p": "0440 03C1",
    "q": "051B",
    "r": "0433",
    "s": "0455",
    "t": "03C4",
    "u": "03C5 057D 1D1C",
    "v": "03BD 0475",
    "w": "0461 051D",
    "x": "0445 03C7",
    "y": "0443 03B3 04AF",
    "z": "1D22",
}

CONFUSABLE = {}
LOOKALIKES = {}
for _ascii, _cps in _SETS.items():
    LOOKALIKES[_ascii] = [chr(int(c, 16)) for c in _cps.split()]
    for _c in LOOKALIKES[_ascii]:
        CONFUSABLE[_c] = _ascii

SCRIPTS = (
    "LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "DEVANAGARI",
    "THAI", "HIRAGANA", "KATAKANA", "CJK", "HANGUL", "GEORGIAN", "COPTIC", "CHEROKEE",
)

INVISIBLE_CATEGORIES = {"Cf", "Cc", "Zs", "Zl", "Zp", "Co", "Cn"}


def script_of(ch):
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "COMMON"
    name = unicodedata.name(ch, "")
    for s in SCRIPTS:
        if name.startswith(s):
            return s
    return "OTHER"


def char_info(ch):
    cp = ord(ch)
    info = {
        "char": ch,
        "codepoint": "U+%04X" % cp,
        "name": unicodedata.name(ch, "<unnamed>"),
        "script": script_of(ch),
        "kind": None,
        "looks_like": None,
        "looks_like_name": None,
    }
    cat = unicodedata.category(ch)
    if cat in INVISIBLE_CATEGORIES and ch != " ":
        info["kind"] = "invisible"
        return info
    twin = CONFUSABLE.get(ch)
    if twin is None and not ch.isascii():
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
        if base.isascii() and base.isalpha():
            twin = base
            info["kind"] = "diacritic"
    if twin is not None:
        info["kind"] = info["kind"] or "confusable"
        info["looks_like"] = twin
        info["looks_like_name"] = unicodedata.name(twin)
    return info


def skeleton(text):
    out = []
    for ch in unicodedata.normalize("NFKC", text).lower():
        if ch in CONFUSABLE:
            out.append(CONFUSABLE[ch])
        elif ch.isascii():
            out.append(ch)
        else:
            base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
            out.append(base if base.isascii() else ch)
    return "".join(out)
