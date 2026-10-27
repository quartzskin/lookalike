import json

from lookalike.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_exit_codes(capsys):
    assert run(capsys, "check", "https://www.paypal.com/", "--no-user-brands")[0] == 0
    assert run(capsys, "check", "https://bit.ly/x", "--no-user-brands")[0] == 1
    assert run(capsys, "check", "paypa1.com", "--no-user-brands")[0] == 2


def test_json_output(capsys):
    code, out, _ = run(capsys, "check", "paypa1.com", "--format", "json", "--no-user-brands")
    data = json.loads(out)
    assert code == 2
    assert data["reports"][0]["findings"][0]["code"]
    assert data["errors"] == []


def test_bad_input_exit_3(capsys):
    code, out, _ = run(capsys, "check", "has space", "--no-user-brands")
    assert code == 3 and "error" in out


def test_usage_errors_exit_3(capsys):
    for argv in (["check"], ["nonsense"], ["generate"]):
        try:
            code = main(argv)
        except SystemExit as e:
            code = e.code
        capsys.readouterr()
        assert code == 3


def test_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("paypa1.com\n\nexample.org\n"))
    code, out, _ = run(capsys, "check", "--stdin", "--no-user-brands")
    assert code == 2 and out.count("verdict:") == 2


def test_html_file(tmp_path, capsys):
    p = tmp_path / "m.html"
    p.write_text('<a href="https://evil.example/">www.paypal.com</a>', encoding="utf-8")
    code, out, _ = run(capsys, "check", "--html", str(p), "--no-user-brands")
    assert code == 2 and "text-href-mismatch" in out


def test_text_report_shows_codepoints(capsys):
    _, out, _ = run(capsys, "check", "p\u0430ypal.com", "--no-user-brands")
    assert "U+0430" in out and "CYRILLIC SMALL LETTER A" in out


def test_user_brands_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOOKALIKE_HOME", str(tmp_path))
    assert run(capsys, "check", "myc0mpany.com")[0] == 0
    assert run(capsys, "brands", "add", "mycompany.com")[0] == 0
    assert run(capsys, "brands", "add", "mycompany.com")[1].startswith("mycompany.com already")
    assert run(capsys, "check", "myc0mpany.com")[0] == 2
    assert run(capsys, "brands", "add", "not a domain")[0] == 3
    assert (tmp_path / "brands.txt").read_text() == "mycompany.com\n"


def test_missing_brands_file(capsys):
    assert run(capsys, "check", "x.example", "--brands", "nope.txt")[0] == 3
