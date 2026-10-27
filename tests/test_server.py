import http.client
import json
import threading

import pytest
import qrmake

from lookalike.brands import DEFAULT_BRANDS
from lookalike.server import make_server


@pytest.fixture()
def srv():
    httpd = make_server(DEFAULT_BRANDS, 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": "127.0.0.1:%d" % port}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data, dict(r.getheaders())


def origin(port):
    return {"Origin": "http://127.0.0.1:%d" % port, "Content-Type": "application/json"}


def test_binds_loopback_only(srv):
    httpd = make_server([], 0)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
    finally:
        httpd.server_close()


def test_pages_served_with_csp(srv):
    for path in ("/", "/app.js", "/app.css"):
        status, body, h = req(srv, "GET", path)
        assert status == 200 and body
        assert "default-src 'none'" in h["Content-Security-Policy"]
    assert b"http://" not in req(srv, "GET", "/")[1]


def test_page_is_plain_form_and_tables(srv):
    page = req(srv, "GET", "/")[1].decode()
    for needle in ('type="text" id="input"', ">Check<", 'id="findings"', 'id="chars"', "Unicode name"):
        assert needle in page
    assert "loupe" not in page.lower() and "lens" not in page.lower()


def test_bad_host_rejected(srv):
    assert req(srv, "GET", "/", headers={"Host": "evil.example"})[0] == 403
    assert req(srv, "GET", "/", headers={"Host": "127.0.0.1:1"})[0] == 403


def test_localhost_host_ok(srv):
    assert req(srv, "GET", "/", headers={"Host": "localhost:%d" % srv})[0] == 200


def test_check_endpoint(srv):
    body = json.dumps({"input": "https://paypa1.com"})
    status, data, _ = req(srv, "POST", "/api/check", body, origin(srv))
    assert status == 200
    assert json.loads(data)["reports"][0]["verdict"] == "high-risk"


def test_post_needs_matching_origin(srv):
    body = json.dumps({"input": "x.example"})
    assert req(srv, "POST", "/api/check", body, {"Content-Type": "application/json"})[0] == 403
    assert req(srv, "POST", "/api/check", body, {"Origin": "http://evil.example"})[0] == 403
    assert req(srv, "POST", "/api/check", body, {"Origin": "null"})[0] == 403


@pytest.mark.parametrize("body", ["not json", "[]", "{}", '{"input": 5}', '{"input": ""}', '{"input": "a b"}'])
def test_bad_bodies_are_400(srv, body):
    assert req(srv, "POST", "/api/check", body, origin(srv))[0] == 400


def test_oversize_body(srv):
    try:
        status = req(srv, "POST", "/api/check", "x" * 70000, origin(srv))[0]
    except ConnectionError:
        return  # server closed before we finished sending, also a refusal
    assert status == 413


def test_qr_endpoint(srv):
    png = qrmake.png(qrmake.build("https://www.paypal.com@evil.example/", "L", 2))
    status, data, _ = req(srv, "POST", "/api/qr", png, origin(srv))
    assert status == 200 and json.loads(data)["text"].startswith("https://www.paypal.com@")
    assert req(srv, "POST", "/api/qr", b"junk", origin(srv))[0] == 400


def test_unknown_paths(srv):
    assert req(srv, "GET", "/etc/passwd")[0] == 404
    assert req(srv, "POST", "/api/other", "{}", origin(srv))[0] == 404
