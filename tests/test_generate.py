import pytest

from lookalike.generate import permutations, resolve_all


def test_permutation_kinds():
    items = permutations("example.com")
    kinds = {i["kind"] for i in items}
    assert {"omission", "transposition", "keyboard-neighbour", "bit-flip", "homoglyph", "hyphen",
            "repetition", "other-tld", "addition"} <= kinds
    names = {i["domain"] for i in items}
    assert "exmaple.com" in names
    assert "example.com" not in names
    assert "examp1e.com" in names or "exampie.com" in names


def test_homoglyph_has_punycode():
    h = [i for i in permutations("apple.com") if i["kind"] == "homoglyph"]
    assert h and all(i["ascii"].startswith("xn--") for i in h)
    assert all(i["ascii"].isascii() for i in h)


def test_subdomain_and_multi_suffix_kept():
    names = {i["domain"] for i in permutations("shop.example.co.uk")}
    assert "shop.exmaple.co.uk" in names
    assert not any(n.startswith(".") or ".." in n for n in names)


def test_no_invalid_labels():
    for i in permutations("a-b.com"):
        for label in i["domain"].split("."):
            assert label and not label.startswith("-") and not label.endswith("-")


@pytest.mark.parametrize("bad", ["", "nodot", "a..com", ".com"])
def test_bad_domain(bad):
    with pytest.raises(ValueError):
        permutations(bad)


def test_resolve_uses_injected_lookup_only():
    items = [{"ascii": "a.example"}, {"ascii": "b.example"}]
    out = resolve_all(items, lookup=lambda n: ["1.2.3.4"] if n == "a.example" else None)
    assert out[0]["addresses"] == ["1.2.3.4"]
    assert out[1]["addresses"] is None


def test_generate_does_not_touch_network_by_default(monkeypatch, capsys):
    import urllib.request

    from lookalike.cli import main

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert main(["generate", "example.com"]) == 0
    assert "omission" in capsys.readouterr().out
