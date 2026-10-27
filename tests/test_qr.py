import pytest
import qrmake

from lookalike.cli import main
from lookalike.qr import QRError, decode_matrix, decode_png


@pytest.mark.parametrize("ecl", "LMQH")
@pytest.mark.parametrize("mask", range(8))
def test_all_masks_and_levels(ecl, mask):
    text = "https://example.org/a?b=c"
    assert decode_matrix(qrmake.build(text, ecl, mask)) == text


@pytest.mark.parametrize("version", range(1, 7))
def test_every_version(version):
    text = "hi" * version
    m = qrmake.build(text, "L", 3, version=version)
    assert len(m) == 17 + 4 * version
    assert decode_matrix(m) == text


def test_long_text_multi_block():
    text = "https://example.org/" + "x" * 40
    assert decode_matrix(qrmake.build(text, "Q", 5)) == text


def test_utf8_payload():
    assert decode_matrix(qrmake.build("caf\u00e9.example", "M", 2)) == "caf\u00e9.example"


@pytest.mark.parametrize("color_type", [0, 2])
@pytest.mark.parametrize("scale", [1, 3, 7])
def test_png_decode(color_type, scale):
    text = "https://paypa1.example/"
    data = qrmake.png(qrmake.build(text, "M", 4), scale=scale, color_type=color_type)
    assert decode_png(data) == text


def test_damaged_symbol_is_refused_not_misread():
    with pytest.raises(QRError, match="error correction"):
        decode_matrix(qrmake.build("https://example.org", "L", 0, corrupt=2))


@pytest.mark.parametrize("data", [b"", b"not a png", b"\x89PNG\r\n\x1a\n", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40])
def test_garbage_png(data):
    with pytest.raises(QRError):
        decode_png(data)


def test_truncated_png():
    data = qrmake.png(qrmake.build("abc"))
    with pytest.raises(QRError):
        decode_png(data[:60])


def test_blank_image():
    import struct
    import zlib

    def chunk(k, b):
        return struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b))

    raw = b"".join(b"\x00" + b"\xff" * 20 for _ in range(20))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 20, 20, 8, 0, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    with pytest.raises(QRError, match="contrast"):
        decode_png(png)


def test_bad_matrix_size():
    with pytest.raises(QRError):
        decode_matrix([[False] * 20] * 20)


def test_cli_qr(tmp_path, capsys):
    p = tmp_path / "q.png"
    p.write_bytes(qrmake.png(qrmake.build("https://www.paypal.com@evil.example/", "L", 1)))
    code = main(["check", "--qr", str(p), "--no-user-brands"])
    out = capsys.readouterr().out
    assert code == 2
    assert "userinfo-trick" in out


def test_cli_qr_bad_file(tmp_path, capsys):
    p = tmp_path / "bad.png"
    p.write_bytes(b"junk")
    assert main(["check", "--qr", str(p)]) == 3
    assert "error" in capsys.readouterr().out
