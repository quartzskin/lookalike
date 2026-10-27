import json
import string
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .analyze import KEYS, split_domain
from .confusables import LOOKALIKES

ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "app", "online", "site", "xyz", "top", "shop"]
SEQUENCES = [("m", "rn"), ("w", "vv"), ("d", "cl"), ("o", "0"), ("l", "1"), ("i", "1"), ("l", "i"), ("i", "l")]
DOH_URL = "https://cloudflare-dns.com/dns-query"


def _label_ok(s):
    return bool(s) and not s.startswith("-") and not s.endswith("-") and len(s) <= 63


def _puny(label):
    return label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")


def label_variants(label):
    out = []
    for i in range(len(label)):
        out.append((label[:i] + label[i + 1:], "omission"))
        out.append((label[:i] + label[i] * 2 + label[i + 1:], "repetition"))
        for k in KEYS.get(label[i], ""):
            out.append((label[:i] + k + label[i + 1:], "keyboard-neighbour"))
        for bit in range(8):
            c = chr(ord(label[i]) ^ (1 << bit))
            if c in string.ascii_lowercase + string.digits + "-":
                out.append((label[:i] + c + label[i + 1:], "bit-flip"))
        for twin in LOOKALIKES.get(label[i], []):
            out.append((label[:i] + twin + label[i + 1:], "homoglyph"))
        if i + 1 < len(label) and label[i] != label[i + 1]:
            out.append((label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition"))
        if i > 0:
            out.append((label[:i] + "-" + label[i:], "hyphen"))
        for a, b in SEQUENCES:
            if label[i:i + len(a)] == a:
                out.append((label[:i] + b + label[i + len(a):], "lookalike-sequence"))
    for c in string.ascii_lowercase:
        out.append((label + c, "addition"))
    for v1 in "aeiou":
        for v2 in "aeiou":
            if v1 != v2:
                for i, ch in enumerate(label):
                    if ch == v1:
                        out.append((label[:i] + v2 + label[i + 1:], "vowel-swap"))
    return out


def permutations(domain):
    domain = domain.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2 or not all(labels):
        raise ValueError("expected a domain like example.com, got %r" % domain)
    subs, sld, suffix = split_domain(labels)
    prefix = "".join(s + "." for s in subs)
    seen = {domain: "original"}
    for v, kind in label_variants(sld):
        if _label_ok(v):
            seen.setdefault(prefix + v + "." + suffix, kind)
    for tld in ALT_TLDS:
        if tld != suffix:
            seen.setdefault(prefix + sld + "." + tld, "other-tld")
    for i in range(1, len(sld)):
        if _label_ok(sld[:i]) and _label_ok(sld[i:]):
            seen.setdefault(prefix + sld[:i] + "." + sld[i:] + "." + suffix, "dot-inserted")
    del seen[domain]
    return [{"domain": d, "ascii": ".".join(_puny(p) for p in d.split(".")), "kind": k}
            for d, k in sorted(seen.items(), key=lambda kv: (kv[1], kv[0]))]


def doh_lookup(name, timeout=5.0):
    """Return A/AAAA addresses for name via DNS-over-HTTPS, [] if none, None on failure."""
    found = []
    for rtype in ("A", "AAAA"):
        url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = json.load(r)
        except (OSError, ValueError):
            return None
        found += [a["data"] for a in body.get("Answer", []) if a.get("type") in (1, 28)]
    return found


def resolve_all(items, workers=8, lookup=doh_lookup):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda it: lookup(it["ascii"]), items))
    for it, res in zip(items, results):
        it["addresses"] = res
    return items
