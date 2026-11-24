"""Beacon tests against a RUNNING stack. Public listener = http://127.0.0.1:8090.
The off-network case needs PUBLIC_TRUST_CF=1 (docker compose up with that env), otherwise it is skipped.
Run: python tests/test_beacon.py"""
import json
import secrets
import sys
import time
import urllib.error
import urllib.request

API, PUB, KEY = "http://127.0.0.1:8000", "http://127.0.0.1:8090", "trap-demo-key"


def call(method, url, body=None, headers=None):
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def new_session():
    sid = "bt-" + secrets.token_hex(4)
    call("POST", API + "/events", {"session_id": sid, "src_ip": "198.51.100.7", "service": "ssh", "kind": "request", "detail": {}}, {"X-Trap-Key": KEY})
    tok = secrets.token_urlsafe(10)
    call("POST", API + "/canary", {"token": tok, "session_id": sid, "label": "x (test)"}, {"X-Trap-Key": KEY})
    return sid, tok


def hits(sid):
    s, b, _ = call("GET", API + "/sessions/" + sid)
    return [e for e in json.loads(b)["events"] if e["kind"] == "canary_triggered"]


def test_public_listener_exposes_only_beacon_paths():
    for p in ("/sessions", "/stats", "/analytics", "/docs", "/events", "/openapi.json", "/"):
        s, _, _ = call("GET", PUB + p)
        assert s == 404, (p, s)


def test_unknown_token_is_boring_404_same_as_valid():
    sid, tok = new_session()
    s1, b1, _ = call("GET", PUB + "/c/nope-" + secrets.token_hex(4))
    s2, b2, _ = call("GET", PUB + "/c/" + tok)
    assert s1 == s2 == 404 and b1 == b2


def test_valid_token_records_hit_with_details():
    sid, tok = new_session()
    call("GET", PUB + "/c/" + tok, headers={"User-Agent": "Mozilla/5.0 test", "Accept-Language": "en-GB"})
    time.sleep(0.4)
    h = hits(sid)
    assert h and h[0]["detail"]["via"] == "public" and h[0]["detail"]["accept_language"] == "en-GB"


def test_pixel_is_valid_png_and_records_hit():
    sid, tok = new_session()
    s, body, hd = call("GET", PUB + "/p/" + tok + ".png")
    assert s == 200 and body[:8] == b"\x89PNG\r\n\x1a\n" and "image/png" in hd.get("content-type", hd.get("Content-Type", ""))
    time.sleep(0.4)
    assert hits(sid)


def test_off_network_flag_when_ip_differs():
    sid, tok = new_session()
    call("GET", PUB + "/c/" + tok, headers={"CF-Connecting-IP": "203.0.113.50"})
    time.sleep(0.4)
    h = hits(sid)
    if not h or h[0]["src_ip"] != "203.0.113.50":
        print("SKIP (PUBLIC_TRUST_CF not enabled)")
        return
    assert h[0]["detail"]["off_network"] is True


if __name__ == "__main__":
    bad = 0
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            try:
                f(); print("PASS", n)
            except Exception as e:
                bad += 1; print("FAIL", n, repr(e))
    sys.exit(1 if bad else 0)
