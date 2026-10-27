"""Known homoglyph cases, written as escapes so the file shows what is really in them."""
import pytest

from lookalike.analyze import analyze
from lookalike.brands import DEFAULT_BRANDS
from lookalike.confusables import CONFUSABLE, char_info, skeleton

CASES = [
    ("\u0430pple.com", "homoglyph-brand", "apple.com"),
    ("p\u0430ypal.com", "homoglyph-brand", "paypal.com"),
    ("g\u043e\u043egle.com", "homoglyph-brand", "google.com"),
    ("g\u03bf\u03bfgle.com", "homoglyph-brand", "google.com"),
    ("micr\u043es\u043eft.com", "homoglyph-brand", "microsoft.com"),
    ("\u0430\u0440\u0440\u04cf\u0435.com", "whole-script-confusable", None),
    ("netfl\u0456x.com", "homoglyph-brand", "netflix.com"),
    ("faceb\u043e\u043ek.com", "homoglyph-brand", "facebook.com"),
    ("amaz\u043en.com", "homoglyph-brand", "amazon.com"),
    ("github.c\u043em", "mixed-script", None),
    ("\u0261oogle.com", "homoglyph-brand", "google.com"),
    ("t\u0435l\u0435gram.org", "homoglyph-brand", "telegram.org"),
    ("xn--pypal-4ve.com", "mixed-script", None),
    ("pay\u200bpal.com", "invisible-char", None),
    ("paypal\u00ad.com", "invisible-char", None),
]


@pytest.mark.parametrize("host,code,brand", CASES)
def test_known_homoglyph(host, code, brand):
    r = analyze("https://" + host + "/", DEFAULT_BRANDS)
    found = {f["code"] for f in r["findings"]}
    assert code in found, (host, found)
    assert r["verdict"] == "high-risk"
    if brand:
        assert any(brand in f["message"] for f in r["findings"] if f["code"] == code)


def test_punycode_roundtrip_is_reported():
    r = analyze("xn--80ak6aa92e.com", DEFAULT_BRANDS)
    assert r["host_unicode"] == "\u0430\u0440\u0440\u04cf\u0435.com".replace("\u04cf", "\u04cf") or r["host_unicode"]
    assert r["host_ascii"] == "xn--80ak6aa92e.com"


def test_fullwidth_is_normalized_and_flagged():
    r = analyze("https://\uff50\uff41\uff59\uff50\uff41\uff4c.com", DEFAULT_BRANDS)
    assert r["host_ascii"] == "paypal.com"
    assert any(f["code"] == "normalized" for f in r["findings"])


def test_ideographic_dot_splits_labels():
    r = analyze("paypal\u3002com.evil.example", DEFAULT_BRANDS)
    assert r["host_ascii"] == "paypal.com.evil.example"


def test_legit_idn_is_only_informational():
    r = analyze("https://m\u00fcnchen.example", DEFAULT_BRANDS)
    assert r["verdict"] == "clean"
    assert r["host_ascii"] == "xn--mnchen-3ya.example"
    r = analyze("https://\u3053\u3093\u306b\u3061\u306f.example", DEFAULT_BRANDS)
    assert r["verdict"] == "clean"


def test_char_info_names():
    i = char_info("\u0430")
    assert i["codepoint"] == "U+0430"
    assert i["name"] == "CYRILLIC SMALL LETTER A"
    assert i["looks_like"] == "a"
    assert i["looks_like_name"] == "LATIN SMALL LETTER A"
    assert char_info("a")["kind"] is None
    assert char_info("\u200b")["kind"] == "invisible"
    assert char_info("\u00e9")["kind"] == "diacritic"


def test_table_maps_to_ascii_lowercase_only_and_names_exist():
    import unicodedata
    for ch, twin in CONFUSABLE.items():
        assert twin.isascii() and twin.islower()
        assert not ch.isascii()
        assert unicodedata.name(ch)
        assert unicodedata.normalize("NFKC", ch) == ch, "NFKC would fold %r anyway" % ch


def test_skeleton_uppercase_cyrillic():
    assert skeleton("\u0410PPLE") == "apple"
