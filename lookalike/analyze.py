import ipaddress
import math
import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import unquote

from .confusables import char_info, skeleton

MAX_INPUT = 4096

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "co.in", "co.za",
    "com.tr", "com.ar", "com.sg", "com.hk", "com.tw", "co.kr",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "link", "work",
    "support", "rest", "country", "icu", "buzz", "cyou", "cfd", "sbs", "monster",
    "loan", "kim", "men", "date", "download", "review", "stream", "bid", "win",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "t.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id", "v.gd",
    "bl.ink", "short.io", "qr.net", "gg.gl",
}

NO_HOST_SCHEMES = {"javascript", "data", "vbscript", "file", "mailto", "tel"}

SEVERITY = {"high": 60, "medium": 30, "low": 10}
_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
_DOTS = str.maketrans({"\u3002": ".", "\uff61": ".", "\uff0e": "."})
_LABEL_OK = re.compile(r"^[a-z0-9-]+$")


def _neighbours():
    pos = {}
    for r, row in enumerate(_ROWS):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)
    out = {}
    for ch, (r, c) in pos.items():
        near = set()
        for rr, cc in ((r, c - 1), (r, c + 1), (r + 1, c - 1), (r + 1, c), (r - 1, c), (r - 1, c + 1)):
            if 0 <= rr < len(_ROWS) and 0 <= cc < len(_ROWS[rr]):
                near.add(_ROWS[rr][cc])
        out[ch] = "".join(sorted(near))
    return out


KEYS = _neighbours()


def finding(code, severity, message, score=None):
    return {
        "code": code,
        "severity": severity,
        "score": SEVERITY[severity] if score is None else score,
        "message": message,
    }


def verdict_for(score):
    if score >= 50:
        return "high-risk"
    if score >= 20:
        return "suspicious"
    return "clean"


def split_domain(labels):
    """Return (subdomain labels, second-level label, public suffix)."""
    if len(labels) < 2:
        return [], labels[0] if labels else "", ""
    n = 3 if ".".join(labels[-2:]) in MULTI_SUFFIX and len(labels) >= 3 else 2
    return labels[:-n], labels[-n], ".".join(labels[-n + 1:])


def damerau(a, b):
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def edit_kinds(s, b):
    """Name the single edit that turns brand label b into candidate s, or None."""
    if len(s) == len(b):
        diffs = [i for i in range(len(s)) if s[i] != b[i]]
        if len(diffs) == 1:
            i = diffs[0]
            kinds = []
            if b[i] in KEYS.get(s[i], ""):
                kinds.append("keyboard-neighbour typo")
            x = ord(s[i]) ^ ord(b[i])
            if x and x & (x - 1) == 0:
                kinds.append("bit flip")
            return kinds or ["substitution"]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 \
                and s[diffs[0]] == b[diffs[1]] and s[diffs[1]] == b[diffs[0]]:
            return ["transposition"]
    elif len(s) == len(b) + 1:
        for i in range(len(s)):
            if s[:i] + s[i + 1:] == b:
                if s[i] == "-":
                    return ["hyphen inserted"]
                if (i > 0 and s[i] == s[i - 1]) or (i + 1 < len(s) and s[i] == s[i + 1]):
                    return ["doubled letter"]
                return ["extra letter"]
    elif len(s) == len(b) - 1:
        for i in range(len(b)):
            if b[:i] + b[i + 1:] == s:
                return ["missing letter"]
    return None


def look_variants(s):
    out = set()
    for one in ("l", "i"):
        v = s.replace("0", "o").replace("1", one)
        out.add(v)
        out.add(v.replace("rn", "m").replace("vv", "w").replace("cl", "d"))
    out.discard(s)
    return out


def entropy(s):
    if not s:
        return 0.0
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def parse_target(text):
    s = text.strip().strip("<>\"'")
    if not s:
        raise ValueError("empty input")
    if len(s) > MAX_INPUT:
        raise ValueError("input longer than %d characters" % MAX_INPUT)
    if any(unicodedata.category(c) == "Cc" for c in s):
        raise ValueError("input contains control characters")
    if any(c.isspace() for c in s):
        raise ValueError("input contains whitespace; give one URL or domain at a time")
    t = {"raw": s, "scheme": "", "userinfo": None, "host": "", "port": "", "path": "", "backslash": False}
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", s)
    rest = s
    if m and (s[m.end():].startswith(("//", "\\\\")) or m.group(1).lower() in NO_HOST_SCHEMES):
        t["scheme"] = m.group(1).lower()
        rest = s[m.end():]
        if t["scheme"] in NO_HOST_SCHEMES:
            return t
    rest = rest[2:] if rest.startswith(("//", "\\\\")) else rest
    cut = re.search(r"[/?#]", rest.replace("\\", "/"))
    authority = rest[:cut.start()] if cut else rest
    t["path"] = rest[cut.start():] if cut else ""
    t["backslash"] = bool(cut) and rest[cut.start()] == "\\"
    if "@" in authority:
        t["userinfo"], _, authority = authority.rpartition("@")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ValueError("unterminated IPv6 literal")
        t["host"] = authority[:end + 1]
        port = authority[end + 1:].lstrip(":")
    else:
        host, sep, port = authority.rpartition(":")
        if not sep or not port.isdigit():
            host, port = authority, ""
        t["host"] = host
    t["port"] = port
    if not t["host"]:
        raise ValueError("no host found")
    return t


def parse_ipv4(host):
    """Browser-style IPv4 (decimal, hex, octal, short forms); None if not numeric."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(re.fullmatch(r"0x[0-9a-f]*|\d+", p) for p in parts):
        return None
    nums = []
    for p in parts:
        try:
            if p.startswith("0x"):
                nums.append(int(p[2:] or "0", 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p))
        except ValueError:
            return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + nums[-1]
    return ipaddress.IPv4Address(value)


def decode_label(label, findings):
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            findings.append(finding("bad-punycode", "high", "label %r claims to be punycode but does not decode" % label))
    return label


def to_ascii_label(label):
    if label.isascii():
        return label
    return "xn--" + label.encode("punycode").decode("ascii")


def label_findings(ulabels):
    out = []
    for label in ulabels:
        if label.isascii():
            continue
        infos = [char_info(c) for c in label]
        hidden = [i for i in infos if i["kind"] == "invisible"]
        if hidden:
            out.append(finding("invisible-char", "high", "label %r contains invisible characters: %s" % (
                label, ", ".join("%s %s" % (i["codepoint"], i["name"]) for i in hidden))))
        group = {"HIRAGANA": "CJK", "KATAKANA": "CJK", "HANGUL": "CJK"}
        scripts = sorted({group.get(i["script"], i["script"]) for i in infos
                          if i["script"] not in ("COMMON",) and i["kind"] != "invisible"})
        confusable = [i for i in infos if i["kind"] == "confusable"]
        mixed = len(scripts) > 1
        sk = skeleton(label)
        whole = sk.isascii() and sk != label
        if mixed:
            sev = "high" if confusable or {"CYRILLIC", "GREEK", "ARMENIAN"} & set(scripts) else "medium"
            out.append(finding("mixed-script", sev, "label %r mixes scripts: %s" % (label, ", ".join(scripts))))
        elif whole and confusable:
            out.append(finding("whole-script-confusable", "high",
                               "label %r is written entirely with lookalike letters and reads as %r" % (label, sk)))
        elif confusable:
            out.append(finding("confusable-chars", "medium",
                               "label %r uses letters that resemble ascii: %s" % (
                                   label, ", ".join("%s=%s" % (i["char"], i["looks_like"]) for i in confusable))))
        else:
            out.append(finding("idn", "low", "label %r is an internationalized name" % label, score=5))
    return out


def brand_findings(subs, sld, suffix, brands):
    best = {}
    if sld + "." + suffix in brands:
        return []

    def note(b, score, sev, code, msg):
        if b not in best or score > best[b]["score"]:
            best[b] = finding(code, sev, msg, score)

    reg = sld + "." + suffix
    sk = skeleton(sld)
    for b in brands:
        if reg == b:
            continue
        b_subs, b_sld, b_suffix = split_domain(b.split("."))
        if not b_sld:
            continue
        if sld != b_sld:
            if sk == b_sld:
                note(b, 80, "high", "homoglyph-brand", "%r reads as %r using lookalike letters: imitates %s" % (sld, b_sld, b))
            elif b_sld in look_variants(sk) and sld.replace("-", "") != b_sld:
                note(b, 70, "high", "lookalike-chars", "%r swaps in lookalike characters (0/o, 1/l, rn/m...): imitates %s" % (sld, b))
            if "-" in sld and sld.replace("-", "") == b_sld:
                note(b, 60, "high", "hyphen-trick", "%r is %s with hyphens added" % (sld, b))
            if len(b_sld) >= 5 and abs(len(sld) - len(b_sld)) <= 2 and sld.isascii():
                kinds = edit_kinds(sld, b_sld)
                if kinds:
                    score = 65 if suffix == b_suffix else 50
                    note(b, score, "high", "typosquat", "%r is one edit from %s (%s)" % (sld, b, ", ".join(kinds)))
                elif len(b_sld) >= 8 and damerau(sld, b_sld) == 2:
                    note(b, 40, "medium", "typosquat", "%r is two edits from %s" % (sld, b))
            if len(b_sld) >= 5 and b_sld in sld:
                note(b, 50, "high", "brand-embedded", "%r contains the name %r: possible imitation of %s" % (sld, b_sld, b))
        elif suffix != b_suffix:
            note(b, 35, "medium", "other-tld", "same name as %s on a different suffix (.%s)" % (b, suffix))
        for lab in subs:
            if lab == b_sld or lab == b.replace(".", "-"):
                note(b, 75, "high", "brand-subdomain", "%r appears as a subdomain; the real site is %s" % (lab, reg))
            elif len(b_sld) >= 5 and b_sld in lab:
                note(b, 60, "high", "brand-subdomain", "subdomain %r contains %r; the real site is %s" % (lab, b_sld, reg))
        if subs and ("." + ".".join(subs) + ".").find("." + b + ".") >= 0:
            note(b, 80, "high", "brand-subdomain", "%s appears as part of the subdomain; the real site is %s" % (b, reg))
    return list(best.values())


def analyze(text, brands, link_text=None):
    t = parse_target(text)
    findings = []
    report = {
        "input": text.strip(), "scheme": t["scheme"], "userinfo": t["userinfo"], "host": t["host"],
        "host_ascii": "", "host_unicode": "", "registrable": "", "port": t["port"],
        "verdict": "clean", "score": 0, "findings": findings, "chars": [],
    }
    if link_text is not None:
        report["link_text"] = link_text

    if t["scheme"] in ("javascript", "data", "vbscript"):
        findings.append(finding("script-scheme", "high", "%s: links run code or embed content instead of opening a site" % t["scheme"], 90))
    elif t["scheme"] == "file":
        findings.append(finding("file-scheme", "medium", "file: link points at a local file"))
    elif t["scheme"] in ("mailto", "tel"):
        findings.append(finding("not-web", "low", "%s: link, no site involved" % t["scheme"], 0))
    if t["scheme"] in NO_HOST_SCHEMES:
        return finish(report)

    if t["scheme"] == "http":
        findings.append(finding("no-tls", "low", "plain http, no encryption", 5))
    if t["backslash"]:
        findings.append(finding("backslash", "medium", "backslash in the host part: browsers treat it as '/', so the host ends there", 40))
    if t["port"] and t["port"] not in ("80", "443"):
        findings.append(finding("odd-port", "low", "non-standard port %s" % t["port"]))
    if t["userinfo"] is not None:
        u = unquote(t["userinfo"])
        if "." in u or "/" in u:
            findings.append(finding("userinfo-trick", "high", "text before '@' (%r) looks like a site, but the real host is %s" % (u, t["host"]), 75))
        else:
            findings.append(finding("userinfo", "medium", "link carries a username before '@'; the real host is %s" % t["host"]))

    host = t["host"]
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise ValueError("invalid IPv6 literal") from None
        findings.append(finding("ip-host", "medium", "raw IPv6 address instead of a name", 20))
        report.update(host_ascii=host, host_unicode=host)
        return finish(report)

    if "%" in host:
        findings.append(finding("encoded-host", "medium", "percent-encoding inside the host name"))
        host = unquote(host)
    norm = unicodedata.normalize("NFKC", host.translate(_DOTS)).lower().rstrip(".")
    if norm != host.lower().rstrip(".") and not host.isascii():
        findings.append(finding("normalized", "medium", "host changes under Unicode normalization (%r -> %r)" % (host, norm), 25))
    if not norm:
        raise ValueError("no host found")

    ip = parse_ipv4(norm)
    if ip is not None:
        if str(ip) == norm:
            findings.append(finding("ip-host", "medium", "raw IP address instead of a name", 25))
        else:
            findings.append(finding("obfuscated-ip", "high", "%r is an obfuscated spelling of %s" % (norm, ip)))
        report.update(host_ascii=str(ip), host_unicode=norm)
        return finish(report)

    labels = norm.split(".")
    if any(not l for l in labels) or any(len(l) > 63 for l in labels) or len(norm) > 253:
        findings.append(finding("malformed-host", "medium", "empty or oversized label in host name", 30))
    labels = [l for l in labels if l]
    ulabels = [decode_label(l, findings) for l in labels]
    try:
        alabels = [to_ascii_label(l) for l in ulabels]
    except UnicodeError:
        alabels = labels
    for a in alabels:
        if not _LABEL_OK.match(a):
            findings.append(finding("odd-chars", "medium", "label %r has characters that are not valid in host names" % a, 25))
            break

    report["host_unicode"] = ".".join(ulabels)
    report["host_ascii"] = ".".join(alabels)
    report["chars"] = [char_info(c) for c in report["host_unicode"]]
    findings.extend(label_findings(ulabels))

    subs, sld, suffix = split_domain(ulabels)
    report["registrable"] = (sld + "." + suffix) if suffix else sld
    if suffix:
        tld = suffix.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(finding("suspicious-tld", "medium", ".%s is cheap and heavily abused for throwaway sites" % tld, 20))
        if report["registrable"] in SHORTENERS:
            findings.append(finding("shortener", "medium", "%s is a link shortener: the destination is hidden" % report["registrable"]))
        findings.extend(brand_findings(subs, sld, suffix, brands))
        if len(subs) >= 4:
            findings.append(finding("deep-subdomains", "low", "%d subdomain levels" % len(subs)))
    if len(norm) > 60:
        findings.append(finding("long-host", "low", "host name is %d characters long" % len(norm), 15))
    if sld.count("-") >= 3:
        findings.append(finding("many-hyphens", "low", "%d hyphens in %r" % (sld.count("-"), sld), 15))
    core = sld.replace("-", "")
    if len(core) >= 12 and core.isascii():
        vowels = sum(core.count(v) for v in "aeiou") / len(core)
        digits = sum(c.isdigit() for c in core) / len(core)
        if (entropy(core) >= 3.4 and vowels < 0.25) or digits > 0.4:
            findings.append(finding("random-host", "medium", "%r looks machine-generated" % sld, 25))
    return finish(report)


def finish(report):
    score = min(100, sum(f["score"] for f in report["findings"]))
    report["score"] = score
    report["verdict"] = verdict_for(score)
    return report


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._open = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._open = {"href": dict(attrs).get("href") or "", "text": []}
            self.links.append(self._open)

    def handle_data(self, data):
        if self._open is not None:
            self._open["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "a":
            self._open = None


_URLISH = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^\s/@]+@)?[^\s/:]+\.[^\s/:]{2,}(?::\d+)?(?:[/?#]\S*)?$", re.I)


def html_links(html):
    p = _Links()
    p.feed(html)
    p.close()
    return [(l["href"].strip(), " ".join("".join(l["text"]).split())) for l in p.links]


def analyze_html(html, brands):
    out = []
    for href, text in html_links(html[: MAX_INPUT * 64]):
        if not href:
            continue
        try:
            r = analyze(href, brands, link_text=text)
        except ValueError as e:
            out.append({"input": href, "link_text": text, "error": str(e), "verdict": "clean", "score": 0,
                        "findings": [], "chars": []})
            continue
        if text and _URLISH.match(text) and r["registrable"] != "":
            try:
                shown = analyze(text, brands)
            except ValueError:
                shown = None
            if shown and shown["registrable"] and skeleton(shown["registrable"]) != skeleton(r["registrable"]):
                r["findings"].append(finding(
                    "text-href-mismatch", "high",
                    "link text shows %s but the link goes to %s" % (shown["registrable"], r["registrable"] or r["host"]), 80))
                finish(r)
        out.append(r)
    return out


def check(text, brands, html=False):
    if html or re.search(r"<a[\s>]", text, re.I):
        return analyze_html(text, brands)
    return [analyze(text, brands)]
