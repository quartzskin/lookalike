import pytest

from lookalike.analyze import analyze, check, damerau, edit_kinds, parse_ipv4, parse_target, split_domain
from lookalike.brands import DEFAULT_BRANDS

B = DEFAULT_BRANDS + ["example-bank.co.uk"]


def codes(text):
    return {f["code"] for f in analyze(text, B)["findings"]}


def test_plain_brand_is_clean():
    r = analyze("https://www.paypal.com/signin", B)
    assert r["verdict"] == "clean"
    assert r["registrable"] == "paypal.com"


def test_unrelated_domain_is_clean():
    assert analyze("https://wiki.example.org/page", B)["verdict"] == "clean"


@pytest.mark.parametrize("url,kind", [
    ("paypall.com", "doubled letter"),
    ("paypl.com", "missing letter"),
    ("paypla.com", "transposition"),
    ("payp-al.com", "hyphen inserted"),
    ("paypak.com", "keyboard-neighbour typo"),
    ("paypao.com", "keyboard-neighbour typo"),
])
def test_typosquat_kinds(url, kind):
    r = analyze(url, B)
    msgs = [f["message"] for f in r["findings"] if f["code"] in ("typosquat", "hyphen-trick")]
    assert any(kind in m or "hyphens added" in m for m in msgs), r["findings"]
    assert r["verdict"] == "high-risk"


def test_bit_flip():
    assert edit_kinds("paypal", "qaypal") == ["bit flip"]
    assert edit_kinds("gooele", "google") == ["substitution"] or "bit flip" in edit_kinds("gooele", "google")


def test_digit_lookalikes():
    assert "lookalike-chars" in codes("paypa1.com")
    assert "lookalike-chars" in codes("g00gle.com")
    assert "lookalike-chars" in codes("rnicrosoft.com")


@pytest.mark.parametrize("url", [
    "paypal.com.evil.example",
    "https://paypal.evil.example/login",
    "https://secure-paypal.evil.example/",
])
def test_brand_in_subdomain(url):
    r = analyze(url, B)
    assert any(f["code"] == "brand-subdomain" for f in r["findings"])
    assert r["registrable"] == "evil.example"


def test_embedded_brand_and_other_tld():
    assert "brand-embedded" in codes("paypal-secure-login.com")
    assert "other-tld" in codes("https://paypal.co")


def test_userinfo_trick():
    r = analyze("https://www.paypal.com@evil.example/x", B)
    assert r["host_ascii"] == "evil.example"
    assert any(f["code"] == "userinfo-trick" for f in r["findings"])
    assert "userinfo" in codes("https://bob@evil.example/")


def test_backslash_trick():
    r = analyze("http://evil.example\\@paypal.com/", B)
    assert r["host_ascii"] == "evil.example"
    assert "backslash" in {f["code"] for f in r["findings"]}


def test_shortener_and_tld():
    assert "shortener" in codes("https://bit.ly/abc")
    assert "suspicious-tld" in codes("https://free-stuff.tk")


def test_random_and_long_hosts():
    assert "random-host" in codes("https://x7qk2vbz9wtr4m.com")
    assert "long-host" in codes("https://" + "a-b" * 25 + ".example.com")


def test_ip_hosts():
    assert "ip-host" in codes("http://192.168.0.1/")
    assert "obfuscated-ip" in codes("http://3232235777/")
    assert "obfuscated-ip" in codes("http://0xC0.0xA8.1.1/")
    assert "ip-host" in codes("http://[2001:db8::1]/")


def test_parse_ipv4_variants():
    assert str(parse_ipv4("3232235777")) == "192.168.1.1"
    assert str(parse_ipv4("0300.0250.1.1")) == "192.168.1.1"
    assert parse_ipv4("1.2.3.256") is None
    assert parse_ipv4("example.com") is None


def test_scheme_without_host():
    r = analyze("javascript:alert(1)", B)
    assert r["verdict"] == "high-risk"
    assert analyze("mailto:a@b.example", B)["verdict"] == "clean"


def test_port_and_bare_host_port():
    r = analyze("evil.example:8080/path", B)
    assert r["host_ascii"] == "evil.example" and r["port"] == "8080"
    assert "odd-port" in {f["code"] for f in r["findings"]}


def test_split_domain_multi_suffix():
    assert split_domain("a.b.example.co.uk".split(".")) == (["a", "b"], "example", "co.uk")
    assert split_domain(["localhost"]) == ([], "localhost", "")


def test_percent_encoded_host():
    assert "encoded-host" in codes("http://paypal%2Ecom.evil.example/")


def test_bad_punycode_and_odd_labels():
    assert "bad-punycode" in codes("xn--!!.example.com")
    assert "malformed-host" in codes("a..b.example.com")
    assert "odd-chars" in codes("under_score.example.com")


@pytest.mark.parametrize("bad", ["", "   ", "has space.com", "tab\there.com", "x" * 5000, "http://", "http://[::1",
                                 "http://[nonsense]/", "\x00evil.com", "///"])
def test_malformed_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        analyze(bad, B)


def test_parse_target_shapes():
    assert parse_target("//evil.example/x")["host"] == "evil.example"
    assert parse_target("HTTPS://User:pw@Host.Example:81/p?q#f")["userinfo"] == "User:pw"


def test_damerau():
    assert damerau("ab", "ba") == 1
    assert damerau("kitten", "sitting") == 3
    assert damerau("", "abc") == 3


def test_html_mismatch():
    html = ('<p><a href="https://evil.example/login">https://www.paypal.com/signin</a> '
            '<a href="https://www.paypal.com/help">help</a> <a href="/relative">x</a> <a>nohref</a></p>')
    reports = check(html, B)
    assert len(reports) == 3
    assert any(f["code"] == "text-href-mismatch" for f in reports[0]["findings"])
    assert reports[0]["verdict"] == "high-risk"
    assert reports[1]["verdict"] == "clean"
    assert "error" in reports[2]


def test_html_malformed_does_not_crash():
    assert check("<a href=\"http://x.example\"><b>unclosed", B)[0]["host_ascii"] == "x.example"
    assert check("<a href=>x</a>", B) == []


def test_html_text_same_site_is_fine():
    reports = check('<a href="https://paypal.com/a">paypal.com</a>', B)
    assert reports[0]["verdict"] == "clean"


def test_custom_brand_list():
    r = analyze("https://myc0mpany.com", ["mycompany.com"])
    assert any(f["code"] == "lookalike-chars" for f in r["findings"])


def test_subdomain_of_listed_brand_is_not_flagged():
    assert analyze("https://outlook.live.com/mail", B)["verdict"] == "clean"
