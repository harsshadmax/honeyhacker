"""Decoy web service: a fake 'Company Admin Portal'. Nothing here is real or executes input."""
import hashlib
import json
import os
import secrets
import threading
import urllib.request

from flask import Flask, Response, make_response, redirect, render_template, request

API = os.environ.get("API_URL", "http://api:8000")
KEY = os.environ.get("TRAP_KEY", "trap-demo-key")
TRUST_XFF = os.environ.get("TRUST_XFF", "0") == "1"
CANARY_BASE = os.environ.get("CANARY_BASE", "http://127.0.0.1:8000")

app = Flask(__name__)
WEAK = {"admin", "password", "123456", "admin123", "letmein", "welcome1", "qwerty", "P@ssw0rd"}
fails: dict[str, int] = {}
authed: set[str] = set()


def src_ip() -> str:
    if TRUST_XFF:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def sid_for() -> str:
    """Stable session id per visitor: IP + user agent hash."""
    raw = f"{src_ip()}|{request.headers.get('User-Agent', '')}"
    return "web-" + hashlib.sha1(raw.encode()).hexdigest()[:10]


def _post(path: str, payload: dict):
    def go():
        try:
            req = urllib.request.Request(
                API + path, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "X-Trap-Key": KEY}, method="POST")
            urllib.request.urlopen(req, timeout=3).read()
        except Exception as e:  # never let logging break the decoy
            print("api post failed:", e, flush=True)
    threading.Thread(target=go, daemon=True).start()


def log(kind: str, **detail):
    _post("/events", {"session_id": sid_for(), "src_ip": src_ip(), "service": "web",
                      "kind": kind, "detail": detail})


@app.before_request
def log_request():
    # Every request is recorded (path, method, UA). Login and bait routes add their own events.
    log("request", method=request.method, path=request.path,
        ua=request.headers.get("User-Agent", "")[:200])


@app.after_request
def headers(r):
    r.headers["Server"] = "Apache/2.4.41 (Ubuntu)"  # believable banner
    return r


@app.get("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)
    user = request.form.get("username", "")[:64]
    pw = request.form.get("password", "")[:64]
    ip = sid_for()
    nfail = fails.get(ip, 0)
    ok = (user == "admin" and pw in WEAK) or nfail >= 4  # lets a brute-forcer "win" eventually
    log("login_attempt", username=user, password=pw, success=ok)
    if ok:
        authed.add(ip)
        log("login_success", username=user)
        return redirect("/admin")
    fails[ip] = nfail + 1
    return render_template("login.html", error="Invalid username or password."), 401


@app.get("/admin")
def admin():
    if sid_for() not in authed:
        return redirect("/login")
    return render_template("admin.html")


def _bait_text(token: str) -> str:
    tpl = open(os.path.join(os.path.dirname(__file__), "bait", "passwords_backup.txt.tmpl")).read()
    return tpl.replace("{{CANARY_URL}}", f"{CANARY_BASE}/c/{token}")


@app.get("/download/passwords_backup.txt")
def bait():
    if sid_for() not in authed:
        return redirect("/login")
    token = secrets.token_urlsafe(12)
    _post("/canary", {"token": token, "session_id": sid_for(), "label": "passwords_backup.txt"})
    log("bait_downloaded", file="passwords_backup.txt", canary_token=token)
    return Response(_bait_text(token), mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=passwords_backup.txt"})


FAKE_ENV = """APP_ENV=production
DB_HOST=10.0.4.12
DB_USER=svc_backup
DB_PASSWORD=Sup3rS3cret!2024
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE0000
AWS_SECRET_ACCESS_KEY=fakefakefakefakefakefakefakefakefake00
"""

FAKE_SQL = """-- MySQL dump 10.13  Distrib 5.7.38
-- Host: 10.0.4.12   Database: corp_hr
INSERT INTO `employees` VALUES (1,'A. Kumar','akumar@corp.example','HR'),(2,'S. Rao','srao@corp.example','FIN');
"""


@app.get("/.env")
def fake_env():
    log("sensitive_probe", path="/.env")
    return Response(FAKE_ENV, mimetype="text/plain")


@app.get("/backup.sql")
def fake_sql():
    log("sensitive_probe", path="/backup.sql")
    return Response(FAKE_SQL, mimetype="text/plain")


@app.errorhandler(404)
def nf(_e):
    return Response("<h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
                    "<hr><address>Apache/2.4.41 (Ubuntu) Server</address>", status=404, mimetype="text/html")


if __name__ == "__main__":
    from waitress import serve
    # Demo only: waitress strips X-Forwarded-For unless told to trust it. In compose the only client
    # is the host's Docker gateway, so we trust the header to let the demo script simulate a source IP.
    kw = {"trusted_proxy": "*", "trusted_proxy_headers": {"x-forwarded-for"}} if TRUST_XFF else {}
    serve(app, host=os.environ.get("BIND", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")), **kw)
