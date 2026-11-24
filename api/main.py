"""Tarpit Ghost API: collects decoy events, scores risk, streams to the dashboard."""
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
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from classify import classify  # idea 4: explainable behaviour class
from export import to_navigator, to_sigma  # idea 4: Sigma / ATT&CK Navigator export

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
    "sql_login": 10,
    "sql_query": 8,
    "blocked_hit": 2,
    "blocked": 0,
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
    "sql_login": "Logged into the fake database",
    "sql_query": "SQL queries run against the fake schema",
    "blocked_hit": "Tried again after being blocked",
    "blocked": "RESPONSE: session blocked by the operator",
}
SUSPICIOUS = re.compile(
    r"\b(wget|curl|nc|ncat|netcat|chmod|sudo|su|base64|python3?|perl|bash\s+-i|"
    r"id_rsa|shadow|passwd|\.env|crontab|ssh-keygen)\b",
    re.I,
)

# MITRE ATT&CK mapping. One table, server-side, so the API, the dashboard and the metrics
# report can never disagree about what a technique ID means.
ATTACK = {
    "request": ("T1595", "Active Scanning"),
    "sensitive_probe": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "login_attempt": ("T1110", "Brute Force"),
    "bruteforce_detected": ("T1110.001", "Password Guessing"),
    "login_success": ("T1078", "Valid Accounts"),
    "ssh_login": ("T1021.004", "Remote Services: SSH"),
    "command": ("T1059", "Command and Scripting Interpreter"),
    "suspicious_command": ("T1059.004", "Unix Shell"),
    "bait_downloaded": ("T1005", "Data from Local System"),
    "canary_triggered": ("T1567", "Exfiltration Over Web Service"),
    "sql_login": ("T1078", "Valid Accounts: Database"),
    "sql_query": ("T1505", "Server Software Component: SQL enumeration"),
    "blocked_hit": ("T1595", "Active Scanning (blocked retry)"),
}


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
        _migrate(_conn)
    return _conn


def _migrate(c: sqlite3.Connection):
    """Add columns introduced after the first schema. Safe to run on every start."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)")}
    if "blocked" not in cols:
        c.execute("ALTER TABLE sessions ADD COLUMN blocked INTEGER DEFAULT 0")
    if "blocked_at" not in cols:
        c.execute("ALTER TABLE sessions ADD COLUMN blocked_at REAL")
    cols = {r["name"] for r in c.execute("PRAGMA table_info(events)")}
    if "lat_ms" not in cols:
        c.execute("ALTER TABLE events ADD COLUMN lat_ms REAL")
    c.commit()


def _row_event(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"], "ts": r["ts"], "session_id": r["session_id"],
        "src_ip": r["src_ip"], "service": r["service"], "kind": r["kind"],
        "detail": json.loads(r["detail_json"] or "{}"),
        "severity": r["severity"], "points": r["points"], "lat_ms": r["lat_ms"],
    }


def _session_dict(r: sqlite3.Row, n_events: int | None = None) -> dict:
    d = {
        "id": r["id"], "src_ip": r["src_ip"], "service": r["service"],
        "started_at": r["started_at"], "last_seen": r["last_seen"],
        "risk_score": r["risk_score"], "risk_level": level_for(r["risk_score"]),
        "blocked": bool(r["blocked"]), "blocked_at": r["blocked_at"],
    }
    if n_events is not None:
        d["event_count"] = n_events
    return d


def _insert_event(session_id, src_ip, service, kind, detail, points=None, lat_ms=None) -> dict:
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
        "INSERT INTO events(ts,session_id,src_ip,service,kind,detail_json,severity,points,lat_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (now, session_id, src_ip, service, kind, json.dumps(detail), sev, pts, lat_ms),
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


app = FastAPI(title="Tarpit Ghost API")


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
    client_ts: float | None = None  # set by the decoy so ingest latency is measurable


class CanaryIn(BaseModel):
    token: str = Field(min_length=8, max_length=64)
    session_id: str
    label: str = "bait"


class BlockIn(BaseModel):
    ip: str


async def _record(ev: EventIn) -> list[dict]:
    lat = None
    if ev.client_ts:
        d = (time.time() - ev.client_ts) * 1000
        if 0 <= d < 60_000:  # ignore clock skew and absurd values
            lat = round(d, 2)
    out = []
    with _lock:
        e = _insert_event(ev.session_id, ev.src_ip, ev.service, ev.kind, ev.detail, lat_ms=lat)
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


PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "0"))          # idea 2: second listener, beacon routes only
PUBLIC_TRUST_CF = os.environ.get("PUBLIC_TRUST_CF", "0") == "1"  # trust Cloudflare's CF-Connecting-IP header
# 1x1 transparent PNG, so an HTML/Office bait document can beacon when merely rendered.
def _make_pixel() -> bytes:
    """A real 1x1 transparent PNG, built (not hand-typed) so every chunk checksum is correct."""
    import struct
    import zlib

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    sig = bytes([137, 80, 78, 71, 13, 10, 26, 10])
    return (sig + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(5))) + chunk(b"IEND", b""))


PIXEL = _make_pixel()


def _hdr(request: Request, name: str, limit: int = 200) -> str:
    return request.headers.get(name, "")[:limit]


async def _beacon(token: str, request: Request, via: str, ip: str):
    """Shared by the local and public listeners. A hit on a known token is a CRITICAL alert on the thief's session.

    off_network is only claimed when the hit came through the public listener from an IP different from the
    session's own IP; the IP we see is the opener's (it may be a VPN or proxy), so this is evidence, not attribution.
    """
    with _lock:
        row = db().execute("SELECT * FROM canaries WHERE token=?", (token,)).fetchone()
        sess = db().execute("SELECT src_ip FROM sessions WHERE id=?", (row["session_id"],)).fetchone() if row else None
    if row:
        sess_ip = sess["src_ip"] if sess else None
        await _record(EventIn(
            session_id=row["session_id"], src_ip=ip, service="canary", kind="canary_triggered",
            detail={"token": token, "label": row["label"], "via": via,
                    "user_agent": _hdr(request, "user-agent"), "referer": _hdr(request, "referer"),
                    "accept_language": _hdr(request, "accept-language", 80),
                    "delay_s": round(time.time() - row["created_at"], 1),
                    "session_ip": sess_ip, "off_network": bool(via == "public" and ip != sess_ip),
                    "note": "Bait file was opened or its link was followed."},
        ))


@app.get("/c/{token}")
async def canary_hit(token: str, request: Request):
    """Canary endpoint: the bait file embeds this URL. Any hit is a critical alert."""
    await _beacon(token, request, "local", client_ip(request))
    # Harmless, boring response either way (don't reveal whether the token was valid).
    return PlainTextResponse("Internal wiki: page not found (404)", status_code=404)


@app.get("/p/{token}.png")
async def canary_pixel(token: str, request: Request):
    await _beacon(token, request, "local", client_ip(request))
    return Response(PIXEL, media_type="image/png", headers={"Cache-Control": "no-store"})


# ---- public beacon listener (idea 2) -----------------------------------------------------------
# Expose ONLY this app through a tunnel. It has no /sessions, /stats, /block, docs or websocket.
public_app = FastAPI(title="beacon", docs_url=None, redoc_url=None, openapi_url=None)


def _public_ip(request: Request) -> str:
    if PUBLIC_TRUST_CF:
        v = request.headers.get("cf-connecting-ip")
        if v:
            return v.strip()[:64]
    return client_ip(request)


@public_app.get("/c/{token}")
async def public_canary(token: str, request: Request):
    await _beacon(token, request, "public", _public_ip(request))
    return PlainTextResponse("Internal wiki: page not found (404)", status_code=404)


@public_app.get("/p/{token}.png")
async def public_pixel(token: str, request: Request):
    await _beacon(token, request, "public", _public_ip(request))
    return Response(PIXEL, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.on_event("startup")
async def _start_public_listener():
    if not PUBLIC_PORT:
        return
    import contextlib

    import uvicorn

    class _Quiet(uvicorn.Server):  # share the process; never fight the main server for signal handlers
        def install_signal_handlers(self):
            pass

        def capture_signals(self):
            return contextlib.nullcontext()

    server = _Quiet(uvicorn.Config(public_app, host="0.0.0.0", port=PUBLIC_PORT, log_level="warning"))
    app.state.public_task = asyncio.create_task(server.serve())


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
    seen: dict[str, dict] = {}
    for e in evs:
        a = ATTACK.get(e["kind"])
        if a:
            t = seen.setdefault(a[0], {"id": a[0], "name": a[1], "count": 0})
            t["count"] += 1
    techniques = sorted(seen.values(), key=lambda t: (-t["count"], t["id"]))
    return {"session": _session_dict(s, len(evs)), "events": evs, "reasons": reasons,
            "techniques": techniques, "behaviour": classify(evs)}


@app.get("/sessions/{sid}/sigma", response_class=PlainTextResponse)
def session_sigma(sid: str):
    """Sigma rule built from what this session actually did (text only, for human review)."""
    d = get_session(sid)
    return to_sigma(d["session"], d["events"], ATTACK, d["behaviour"])


@app.get("/sessions/{sid}/navigator")
def session_navigator(sid: str):
    """ATT&CK Navigator layer (JSON) with only the techniques this session exhibited."""
    d = get_session(sid)
    return to_navigator(d["session"], d["events"], ATTACK)


@app.get("/stats")
def stats():
    with _lock:
        c = db()
        return {
            "sessions": c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "events": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "critical": c.execute("SELECT COUNT(*) FROM events WHERE severity='critical'").fetchone()[0],
            "blocked": c.execute("SELECT COUNT(*) FROM sessions WHERE blocked=1").fetchone()[0],
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


def _validate_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        raise HTTPException(400, "not a valid IP address")


def _rule_text(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    warn = ""
    if a.is_loopback or a.is_private or a.is_link_local:
        warn = ("# NOTE: this is a private/loopback address (typical when attacking from this PC or\n"
                "# through Docker's gateway). Blocking it could cut off your own machine/Docker.\n"
                "# Only apply rules like this on a real perimeter firewall for a real attacker IP.\n\n")
    return (
        "# REVIEW BEFORE APPLYING. Generated by Tarpit Ghost; nothing has been changed on the host.\n" + warn +
        "# --- Windows Firewall (run as Administrator) ---\n"
        f'netsh advfirewall firewall add rule name="TarpitGhost block {ip}" dir=in action=block remoteip={ip}\n\n'
        "# --- Linux nftables ---\n"
        f"nft add rule inet filter input ip saddr {ip} drop\n\n"
        "# --- Linux iptables ---\n"
        f"sudo iptables -I INPUT -s {ip} -j DROP\n\n"
        "# --- Linux ufw ---\n"
        f"sudo ufw insert 1 deny from {ip}\n\n"
        "# --- Undo (Windows) ---\n"
        f'netsh advfirewall firewall delete rule name="TarpitGhost block {ip}"\n'
    )


@app.post("/block-rule", response_class=PlainTextResponse)
def block_rule(b: BlockIn):
    """Generate (never apply) perimeter firewall rules for an IP. Strictly validated first."""
    return _rule_text(_validate_ip(b.ip))


class BlockSessionIn(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="operator", max_length=120)


@app.post("/block")
async def block_session(b: BlockSessionIn):
    """Kill-switch: revoke the session at every decoy and return the perimeter rule text.

    Enforcement is real (decoys refuse the blocked session on their next action); the firewall
    rule is still only text, because applying it automatically could lock the operator out.
    """
    with _lock:
        s = db().execute("SELECT * FROM sessions WHERE id=?", (b.session_id,)).fetchone()
        if not s:
            raise HTTPException(404, "no such session")
        if s["blocked"]:
            return {"ok": True, "already": True, "blocked_at": s["blocked_at"],
                    "session_id": b.session_id, "rule": _rule_text(s["src_ip"])}
        now = time.time()
        db().execute("UPDATE sessions SET blocked=1, blocked_at=? WHERE id=?", (now, b.session_id))
        db().commit()
        dwell = round(now - s["started_at"], 2)
        ev = _insert_event(b.session_id, s["src_ip"], "response", "blocked",
                           {"reason": b.reason, "dwell_s": dwell})
    await broadcast({"type": "event", "event": ev})
    await broadcast({"type": "blocked", "session_id": b.session_id, "blocked_at": now})
    return {"ok": True, "blocked_at": now, "dwell_s": dwell,
            "session_id": b.session_id, "rule": _rule_text(s["src_ip"])}


@app.post("/unblock")
def unblock_session(b: BlockSessionIn):
    with _lock:
        db().execute("UPDATE sessions SET blocked=0, blocked_at=NULL WHERE id=?", (b.session_id,))
        db().commit()
    return {"ok": True, "session_id": b.session_id, "blocked": False}


@app.get("/blocked/{sid}")
def is_blocked(sid: str):
    """Polled by the decoys before serving an action. Cheap, one indexed lookup."""
    with _lock:
        r = db().execute("SELECT blocked FROM sessions WHERE id=?", (sid,)).fetchone()
    return {"blocked": bool(r and r["blocked"])}


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = max(0, min(len(v) - 1, int(round((p / 100) * (len(v) - 1)))))
    return round(v[k], 2)


@app.get("/metrics")
def metrics():
    """Everything the results table needs, computed from stored events, never estimated."""
    with _lock:
        c = db()
        sessions = [dict(r) for r in c.execute("SELECT * FROM sessions")]
        events = [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id")]
    by_sess: dict[str, list[dict]] = {}
    for e in events:
        by_sess.setdefault(e["session_id"], []).append(e)

    techniques: dict[str, dict] = {}
    for e in events:
        a = ATTACK.get(e["kind"])
        if not a:
            continue
        t = techniques.setdefault(a[0], {"id": a[0], "name": a[1], "count": 0, "sessions": set()})
        t["count"] += 1
        t["sessions"].add(e["session_id"])
    tech_out = [{"id": t["id"], "name": t["name"], "count": t["count"],
                 "sessions": len(t["sessions"])} for t in techniques.values()]
    tech_out.sort(key=lambda x: (-x["count"], x["id"]))

    # MTTD: first event in a session -> first HIGH/CRITICAL event in the same session.
    mttds: list[float] = []
    for sid, evs in by_sess.items():
        t0 = evs[0]["ts"]
        for e in evs:
            if e["severity"] in ("high", "critical"):
                mttds.append(e["ts"] - t0)
                break

    dwells = [s["blocked_at"] - s["started_at"] for s in sessions if s["blocked_at"]]
    lats = [e["lat_ms"] for e in events if e["lat_ms"] is not None]

    return {
        "generated_at": time.time(),
        "sessions": len(sessions),
        "events": len(events),
        "blocked_sessions": sum(1 for s in sessions if s["blocked"]),
        "canary_hits": sum(1 for e in events if e["kind"] == "canary_triggered"),
        "techniques": tech_out,
        "technique_count": len(tech_out),
        "mttd_s": {
            "count": len(mttds),
            "min": round(min(mttds), 2) if mttds else None,
            "median": _pct(mttds, 50),
            "p95": _pct(mttds, 95),
        },
        "dwell_s": {
            "count": len(dwells),
            "median": _pct(dwells, 50),
            "max": round(max(dwells), 2) if dwells else None,
        },
        "ingest_latency_ms": {
            "samples": len(lats),
            "median": _pct(lats, 50),
            "p95": _pct(lats, 95),
            "max": round(max(lats), 2) if lats else None,
        },
        "services": sorted({e["service"] for e in events}),
        "per_session": [
            {"id": s["id"], "src_ip": s["src_ip"], "service": s["service"],
             "events": len(by_sess.get(s["id"], [])), "risk": s["risk_score"],
             "level": level_for(s["risk_score"]), "blocked": bool(s["blocked"]),
             "duration_s": round((s["blocked_at"] or s["last_seen"]) - s["started_at"], 2)}
            for s in sorted(sessions, key=lambda s: -s["started_at"])[:50]
        ],
    }


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
