"""Hacker Trap API: collects decoy events, scores risk, streams to the dashboard."""
import asyncio
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("DB_PATH", "/data/trap.db")
TRAP_KEY = os.environ.get("TRAP_KEY", "trap-demo-key")
TRUST_XFF = os.environ.get("TRUST_XFF", "0") == "1"
STATIC = Path(__file__).parent / "static"

# ---- risk model (simple and explainable) -------------------------------------
POINTS = {
    "request": 1,
    "sensitive_probe": 10,
    "login_attempt": 5,
    "bruteforce_detected": 15,
    "login_success": 20,
    "ssh_login": 5,
    "command": 3,
    "suspicious_command": 15,
    "bait_downloaded": 25,
    "canary_triggered": 100,
}
REASON_TEXT = {
    "request": "Probing requests",
    "sensitive_probe": "Touched sensitive-looking files (.env, backups)",
    "login_attempt": "Login attempts",
    "bruteforce_detected": "Brute-force pattern (3+ failed logins)",
    "login_success": "Got past the fake login",
    "ssh_login": "SSH login",
    "command": "Shell commands run",
    "suspicious_command": "Suspicious commands (download/exec/credential access)",
    "bait_downloaded": "Downloaded bait file",
    "canary_triggered": "CANARY TOKEN TRIGGERED: bait was opened/used",
}
SUSPICIOUS = re.compile(
    r"\b(wget|curl|nc|ncat|netcat|chmod|sudo|su|base64|python3?|perl|bash\s+-i|"
    r"id_rsa|shadow|passwd|\.env|crontab|ssh-keygen)\b",
    re.I,
)


def level_for(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def severity_for(points: int) -> str:
    if points >= 90:
        return "critical"
    if points >= 15:
        return "high"
    if points >= 5:
        return "medium"
    return "info"


# ---- storage -----------------------------------------------------------------
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions(
                id TEXT PRIMARY KEY, src_ip TEXT, service TEXT,
                started_at REAL, last_seen REAL, risk_score INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session_id TEXT,
                src_ip TEXT, service TEXT, kind TEXT, detail_json TEXT,
                severity TEXT, points INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ev_sess ON events(session_id, id);
            CREATE TABLE IF NOT EXISTS canaries(
                token TEXT PRIMARY KEY, session_id TEXT, label TEXT, created_at REAL);
            """
        )
    return _conn


def _row_event(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"], "ts": r["ts"], "session_id": r["session_id"],
        "src_ip": r["src_ip"], "service": r["service"], "kind": r["kind"],
        "detail": json.loads(r["detail_json"] or "{}"),
        "severity": r["severity"], "points": r["points"],
    }


def _session_dict(r: sqlite3.Row, n_events: int | None = None) -> dict:
    d = {
        "id": r["id"], "src_ip": r["src_ip"], "service": r["service"],
        "started_at": r["started_at"], "last_seen": r["last_seen"],
        "risk_score": r["risk_score"], "risk_level": level_for(r["risk_score"]),
    }
    if n_events is not None:
        d["event_count"] = n_events
    return d


def _insert_event(session_id, src_ip, service, kind, detail, points=None) -> dict:
    """Insert one event and update its session. Caller must hold _lock."""
    c = db()
    now = time.time()
    if kind == "command" and SUSPICIOUS.search(str(detail.get("cmd", ""))):
        kind = "suspicious_command"
    pts = POINTS.get(kind, 0) if points is None else points
    sev = severity_for(pts)
    if not c.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone():
        c.execute(
            "INSERT INTO sessions(id,src_ip,service,started_at,last_seen,risk_score) VALUES(?,?,?,?,?,0)",
            (session_id, src_ip, service, now, now),
        )
    cur = c.execute(
        "INSERT INTO events(ts,session_id,src_ip,service,kind,detail_json,severity,points) VALUES(?,?,?,?,?,?,?,?)",
        (now, session_id, src_ip, service, kind, json.dumps(detail), sev, pts),
    )
    c.execute(
        "UPDATE sessions SET last_seen=?, risk_score=MIN(100, risk_score+?) WHERE id=?",
        (now, pts, session_id),
    )
    c.commit()
    r = c.execute("SELECT * FROM events WHERE id=?", (cur.lastrowid,)).fetchone()
    return _row_event(r)


# ---- websocket fan-out -------------------------------------------------------
clients: set[WebSocket] = set()


async def broadcast(msg: dict):
    dead = []
    for ws in list(clients):
        try:
            await ws.send_text(json.dumps(msg))
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


app = FastAPI(title="Hacker Trap API")


def require_key(key: str | None):
    if not key or not secrets.compare_digest(key, TRAP_KEY):
        raise HTTPException(401, "bad key")


def client_ip(request: Request) -> str:
    if TRUST_XFF:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class EventIn(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    src_ip: str = Field(max_length=64)
    service: str = Field(max_length=32)
    kind: str = Field(max_length=48)
    detail: dict = {}


class CanaryIn(BaseModel):
    token: str = Field(min_length=8, max_length=64)
    session_id: str
    label: str = "bait"


class BlockIn(BaseModel):
    ip: str


async def _record(ev: EventIn) -> list[dict]:
    out = []
    with _lock:
        e = _insert_event(ev.session_id, ev.src_ip, ev.service, ev.kind, ev.detail)
        out.append(e)
        # brute-force detection: exactly the 3rd failed login in a session
        if ev.kind == "login_attempt" and not ev.detail.get("success"):
            n = 0
            for r in db().execute(
                "SELECT detail_json FROM events WHERE session_id=? AND kind='login_attempt'",
                (ev.session_id,),
            ):
                if not json.loads(r["detail_json"]).get("success"):
                    n += 1
            if n == 3:
                out.append(_insert_event(ev.session_id, ev.src_ip, ev.service,
                                         "bruteforce_detected", {"failed_logins": 3}))
    for e in out:
        await broadcast({"type": "event", "event": e})
    return out


@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}


@app.post("/events")
async def post_event(ev: EventIn, x_trap_key: str | None = Header(default=None)):
    require_key(x_trap_key)
    out = await _record(ev)
    return {"stored": len(out), "ids": [e["id"] for e in out]}


@app.post("/canary")
def register_canary(c: CanaryIn, x_trap_key: str | None = Header(default=None)):
    require_key(x_trap_key)
    with _lock:
        db().execute(
            "INSERT OR REPLACE INTO canaries(token,session_id,label,created_at) VALUES(?,?,?,?)",
            (c.token, c.session_id, c.label, time.time()),
        )
        db().commit()
    return {"ok": True}


@app.get("/c/{token}")
async def canary_hit(token: str, request: Request):
    """Canary endpoint: the bait file embeds this URL. Any hit is a critical alert."""
    with _lock:
        row = db().execute("SELECT * FROM canaries WHERE token=?", (token,)).fetchone()
    if row:
        ev = EventIn(
            session_id=row["session_id"], src_ip=client_ip(request), service="canary",
            kind="canary_triggered",
            detail={"token": token, "label": row["label"],
                    "user_agent": request.headers.get("user-agent", ""),
                    "note": "Bait file was opened or its link was followed."},
        )
        await _record(ev)
    # Harmless, boring response either way (don't reveal whether the token was valid).
    return PlainTextResponse("Internal wiki: page not found (404)", status_code=404)


@app.get("/sessions")
def list_sessions():
    with _lock:
        rows = db().execute(
            "SELECT s.*, (SELECT COUNT(*) FROM events e WHERE e.session_id=s.id) AS n "
            "FROM sessions s ORDER BY s.last_seen DESC LIMIT 200"
        ).fetchall()
    return [_session_dict(r, r["n"]) for r in rows]


@app.get("/sessions/{sid}")
def get_session(sid: str):
    with _lock:
        s = db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "no such session")
        evs = [_row_event(r) for r in db().execute(
            "SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))]
    agg: dict[str, list] = {}
    for e in evs:
        a = agg.setdefault(e["kind"], [0, 0])
        a[0] += 1
        a[1] += e["points"]
    reasons = sorted(
        ({"kind": k, "text": REASON_TEXT.get(k, k), "count": v[0], "points": v[1]}
         for k, v in agg.items() if v[1] > 0),
        key=lambda x: -x["points"],
    )
    return {"session": _session_dict(s, len(evs)), "events": evs, "reasons": reasons}


@app.get("/stats")
def stats():
    with _lock:
        c = db()
        return {
            "sessions": c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "events": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "critical": c.execute("SELECT COUNT(*) FROM events WHERE severity='critical'").fetchone()[0],
        }


@app.get("/analytics")
def analytics(minutes: int = 30):
    """Read-only aggregates for the dashboard charts (events per minute, levels, top sources, kinds)."""
    minutes = max(5, min(minutes, 120))
    now = time.time()
    start = now - minutes * 60
    with _lock:
        c = db()
        buckets = [{"t": start + i * 60, "info": 0, "medium": 0, "high": 0, "critical": 0} for i in range(minutes)]
        for r in c.execute("SELECT ts, severity FROM events WHERE ts>=?", (start,)):
            i = min(minutes - 1, int((r["ts"] - start) // 60))
            buckets[i][r["severity"] if r["severity"] in buckets[i] else "info"] += 1
        levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in c.execute("SELECT risk_score FROM sessions"):
            levels[level_for(r["risk_score"])] += 1
        top = [{"ip": r["src_ip"], "score": r["score"], "events": r["n"], "sessions": r["s"], "last": r["last"]}
               for r in c.execute(
                   "SELECT src_ip, MAX(risk_score) AS score, COUNT(*) AS s, MAX(last_seen) AS last, "
                   "(SELECT COUNT(*) FROM events e WHERE e.src_ip=s.src_ip) AS n "
                   "FROM sessions s GROUP BY src_ip ORDER BY score DESC, n DESC LIMIT 6")]
        kinds = {r["kind"]: r["n"] for r in c.execute("SELECT kind, COUNT(*) AS n FROM events GROUP BY kind")}
        uniq = c.execute("SELECT COUNT(DISTINCT src_ip) FROM sessions").fetchone()[0]
        last_min = c.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (now - 60,)).fetchone()[0]
    return {"now": now, "buckets": buckets, "levels": levels, "top": top, "kinds": kinds,
            "unique_attackers": uniq, "events_last_min": last_min}


@app.post("/block-rule", response_class=PlainTextResponse)
def block_rule(b: BlockIn):
    """Generate (never apply) firewall rules. The IP is strictly validated first."""
    try:
        ip = ipaddress.ip_address(b.ip.strip())
    except ValueError:
        raise HTTPException(400, "not a valid IP address")
    ip = str(ip)
    warn = ""
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_private or a.is_link_local:
        warn = ("# NOTE: this is a private/loopback address (typical when attacking from this PC or\n"
                "# through Docker's gateway). Blocking it could cut off your own machine/Docker.\n"
                "# Only apply rules like this on a real perimeter firewall for a real attacker IP.\n\n")
    return (
        "# REVIEW BEFORE APPLYING. Generated by Hacker Trap; nothing has been changed.\n" + warn +
        "# --- Windows Firewall (run as Administrator) ---\n"
        f'netsh advfirewall firewall add rule name="HackerTrap block {ip}" dir=in action=block remoteip={ip}\n\n'
        "# --- Linux iptables ---\n"
        f"sudo iptables -I INPUT -s {ip} -j DROP\n\n"
        "# --- Linux ufw ---\n"
        f"sudo ufw insert 1 deny from {ip}\n\n"
        "# --- Undo (Windows) ---\n"
        f'netsh advfirewall firewall delete rule name="HackerTrap block {ip}"\n'
    )


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from the page
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
