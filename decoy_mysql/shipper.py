"""Ship the MySQL general log to the trap API.

The decoy database writes every statement it receives to its general log (real server-side
capture: nothing in this container parses traffic or trusts the client). This process tails
that file, turns each line into an event, and posts it to the api.

Session ids are derived from the client IP + connection thread, so one attacker's queries
land on one session even across several `mysql` invocations from the same host.
"""
import hashlib
import json
import os
import re
import time
import urllib.request

LOG_PATH = os.environ.get("LOG_PATH", "/var/lib/mysql/general.log")
API = os.environ.get("API_URL", "http://api:8000")
KEY = os.environ.get("TRAP_KEY", "trap-demo-key")

# 2026-11-24T12:30:01.123456Z	   12 Query	show databases
LINE = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+Z)\s+(\d+)\s+(\w+)\s+(.*)$")
CONNECT = re.compile(r"^(?P<user>[^@\s]+)@(?P<ip>[0-9a-fA-F:.]+)\s+on\s+(?P<db>\S+)?")
SKIP_COMMANDS = {"Ping", "Quit", "Statistics", "Field List", "Init DB"}

threads: dict[str, str] = {}   # thread id -> client ip
last_offset = 0


def post(payload: dict):
    payload = dict(payload, client_ts=time.time())
    try:
        req = urllib.request.Request(
            API + "/events", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-Trap-Key": KEY}, method="POST")
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:
        print("api post failed:", e, flush=True)


def sid_for(ip: str, thread: str) -> str:
    return "sql-" + hashlib.sha1(f"{ip}|{thread}".encode()).hexdigest()[:10]


def handle(ts: str, thread: str, command: str, arg: str):
    arg = arg.strip()
    if command == "Connect":
        m = CONNECT.match(arg)
        ip = m.group("ip") if m else "unknown"
        user = m.group("user") if m else "unknown"
        db = (m.group("db") if m else "") or ""
        threads[thread] = ip
        post({"session_id": sid_for(ip, thread), "src_ip": ip, "service": "mysql",
              "kind": "sql_login", "detail": {"user": user, "db": db, "thread": thread}})
        return
    if command not in ("Query",):
        return
    if command in SKIP_COMMANDS or not arg:
        return
    if arg.upper() in ("SELECT 1", "SELECT 1;"):
        return  # our own healthcheck
    ip = threads.get(thread, "unknown")
    kind = "sensitive_probe" if any(t in arg.upper() for t in ("CREDENTIALS", "PASSWORD", "PAYMENTS")) else "sql_query"
    post({"session_id": sid_for(ip, thread), "src_ip": ip, "service": "mysql",
          "kind": kind, "detail": {"query": arg[:500], "thread": thread}})


def tail():
    global last_offset
    try:
        size = os.path.getsize(LOG_PATH)
    except OSError:
        return
    if size < last_offset:      # file rotated / truncated
        last_offset = 0
    if size == last_offset:
        return
    with open(LOG_PATH, "r", errors="replace") as f:
        f.seek(last_offset)
        chunk = f.read()
        last_offset = f.tell()
    for line in chunk.splitlines():
        m = LINE.match(line)
        if m:
            handle(*m.groups())


def main():
    print(f"shipping {LOG_PATH} -> {API}", flush=True)
    while True:
        tail()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
