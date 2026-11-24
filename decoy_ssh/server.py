"""Decoy SSH server (asyncssh). Accepts a login after a couple of tries and hands out a fake shell."""
import asyncio
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request

import asyncssh

import random

from fakefs import BAIT_NAME, FakeFS
from worldgen import WorldState

WORLD_MODEL = os.environ.get("WORLD_MODEL", "1") == "1"  # per-session adaptive fake machine (idea 1); 0 = original static box


async def run_cmd(fs, line):
    """Run one fake command. Model-backed worlds may block on a local LLM, so they run off the event loop;
    jitter makes response timing look like a real machine instead of an instant canned reply."""
    if fs.world is not None and fs.world.llm is not None:
        res = await asyncio.get_running_loop().run_in_executor(None, fs.run, line)
    else:
        res = fs.run(line)
    if fs.world is not None:
        await asyncio.sleep(random.uniform(0.03, 0.2))
    return res

API = os.environ.get("API_URL", "http://api:8000")
KEY = os.environ.get("TRAP_KEY", "trap-demo-key")
CANARY_BASE = os.environ.get("CANARY_BASE", "http://127.0.0.1:8000")
HOST_KEY = os.environ.get("HOST_KEY", "/app/host_key")
BANNER = "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n\n"


def _post(path, payload):
    payload = dict(payload, client_ts=time.time())

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


_blocked_cache = {}


def is_blocked(sid):
    """The operator's kill-switch. Checked before every command, so a block lands mid-session."""
    hit = _blocked_cache.get(sid)
    if hit and time.time() - hit[0] < 0.5:
        return hit[1]
    blocked = False
    try:
        r = urllib.request.urlopen(API + "/blocked/" + urllib.parse.quote(sid), timeout=0.6)
        blocked = bool(json.loads(r.read()).get("blocked"))
    except Exception:
        blocked = False
    _blocked_cache[sid] = (time.time(), blocked)
    return blocked


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

    def secret(path):
        """A generated secret file was read: register a per-path canary and log the theft. Called once per path."""
        token = secrets.token_urlsafe(12)
        _post("/canary", {"token": token, "session_id": sid, "label": path + " (ssh)"})
        log(sid, ip, "bait_downloaded", file=path, canary_token=token, via="cat")
        return f"{CANARY_BASE}/c/{token}"

    world = WorldState(sid, user, on_secret=secret) if WORLD_MODEL else None
    if world:
        log(sid, ip, "request", note=f"world model: {world.persona_name} box {world.host} ({world.mode} mode)")
    fs = FakeFS(user, on_bait=bait, world=world)

    if process.command:  # one-shot: ssh host "cmd"
        if is_blocked(sid):
            log(sid, ip, "blocked_hit", cmd=process.command[:200], mode="exec")
            process.stdout.write("Connection closed by remote host.\r\n")
            process.exit(255)
            return
        log(sid, ip, "command", cmd=process.command[:500], mode="exec")
        out, _ = await run_cmd(fs, process.command)
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
            if is_blocked(sid):
                log(sid, ip, "blocked_hit", cmd=line[:200])
                process.stdout.write("\r\nConnection closed by remote host.\r\n")
                break
            log(sid, ip, "command", cmd=line[:500], cwd=fs.cwd)
            out, close = await run_cmd(fs, line)
            process.stdout.write(out)
            if close:
                break
    except (asyncssh.BreakReceived, asyncssh.SignalReceived, ConnectionError):
        pass
    process.exit(0)


async def main():
    # A stock OpenSSH 8.2 box offers rsa, ecdsa and ed25519 host keys; offering only RSA is a fingerprint tell.
    # The extra keys are generated per start (in memory), the RSA one stays on disk.
    keys = [HOST_KEY, asyncssh.generate_private_key("ssh-ed25519"), asyncssh.generate_private_key("ecdsa-sha2-nistp256")]
    await asyncssh.create_server(
        TrapServer, "", 2222,
        server_host_keys=keys,
        process_factory=handle,
        server_version="OpenSSH_8.2p1 Ubuntu-4ubuntu0.9",
        line_editor=True,
        encoding="utf-8",
    )
    print("decoy ssh listening on :2222", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
