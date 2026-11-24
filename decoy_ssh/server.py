"""Decoy SSH server (asyncssh). Accepts a login after a couple of tries and hands out a fake shell."""
import asyncio
import json
import os
import secrets
import threading
import urllib.request

import asyncssh

from fakefs import BAIT_NAME, FakeFS

API = os.environ.get("API_URL", "http://api:8000")
KEY = os.environ.get("TRAP_KEY", "trap-demo-key")
CANARY_BASE = os.environ.get("CANARY_BASE", "http://127.0.0.1:8000")
HOST_KEY = os.environ.get("HOST_KEY", "/app/host_key")
BANNER = "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n\n"


def _post(path, payload):
    def go():
        try:
            req = urllib.request.Request(
                API + path, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "X-Trap-Key": KEY}, method="POST")
            urllib.request.urlopen(req, timeout=3).read()
        except Exception as e:
            print("api post failed:", e, flush=True)
    threading.Thread(target=go, daemon=True).start()


def log(sid, ip, kind, **detail):
    _post("/events", {"session_id": sid, "src_ip": ip, "service": "ssh", "kind": kind, "detail": detail})


STATE = {}  # connection -> TrapServer (ip, session id)


class TrapServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        STATE[conn] = self
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        self.ip = peer[0]
        self.sid = "ssh-" + secrets.token_hex(4)
        self.attempts = 0
        log(self.sid, self.ip, "request", note="ssh connection opened")

    def connection_lost(self, exc):
        for k in [k for k, v in STATE.items() if v is self]:
            STATE.pop(k, None)
        log(self.sid, self.ip, "request", note="ssh connection closed")

    def begin_auth(self, username):
        return True  # always require auth

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.attempts += 1
        ok = self.attempts >= 2  # "weak box": lets the attacker in on the 2nd try
        log(self.sid, self.ip, "login_attempt", username=username[:64], password=password[:64], success=ok)
        if ok:
            log(self.sid, self.ip, "ssh_login", username=username[:64])
        return ok


async def handle(process):
    srv = STATE[process.get_extra_info("connection")]
    ip, sid = srv.ip, srv.sid
    user = process.get_extra_info("username") or "admin"

    def bait():
        token = secrets.token_urlsafe(12)
        _post("/canary", {"token": token, "session_id": sid, "label": BAIT_NAME + " (ssh)"})
        log(sid, ip, "bait_downloaded", file=BAIT_NAME, canary_token=token, via="cat")
        return (f"# Northwind Corp - internal credential backup (CONFIDENTIAL)\n"
                f"# See the internal wiki for rotation policy: {CANARY_BASE}/c/{token}\n\n"
                "vpn.northwind.example   vpn_admin   Vp#n2024!rotate\n"
                "db-prod-01              svc_backup  Sup3rS3cret!2024\n")

    fs = FakeFS(user, on_bait=bait)

    if process.command:  # one-shot: ssh host "cmd"
        log(sid, ip, "command", cmd=process.command[:500], mode="exec")
        out, _ = fs.run(process.command)
        process.stdout.write(out)
        process.exit(0)
        return

    process.stdout.write(BANNER)
    try:
        while True:
            process.stdout.write(fs.prompt())
            try:
                line = await process.stdin.readline()
            except asyncssh.TerminalSizeChanged:
                continue
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            log(sid, ip, "command", cmd=line[:500], cwd=fs.cwd)
            out, close = fs.run(line)
            process.stdout.write(out)
            if close:
                break
    except (asyncssh.BreakReceived, asyncssh.SignalReceived, ConnectionError):
        pass
    process.exit(0)


async def main():
    await asyncssh.create_server(
        TrapServer, "", 2222,
        server_host_keys=[HOST_KEY],
        process_factory=handle,
        server_version="OpenSSH_8.2p1 Ubuntu-4ubuntu0.9",
        line_editor=True,
        encoding="utf-8",
    )
    print("decoy ssh listening on :2222", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
