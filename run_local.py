"""Run the whole Tarpit Ghost WITHOUT Docker (api + web decoy + ssh decoy as local Python processes).

    python run_local.py            # first run creates .local/venv and installs dependencies
    python run_local.py --reset    # wipe the local database first
    python run_local.py --attack   # also run the scripted attacker once everything is up

Ctrl-C stops everything. Same ports as the Docker version:
    dashboard http://127.0.0.1:8000 | web decoy http://127.0.0.1:8081 | ssh decoy 127.0.0.1:2222

NOTE: without containers there is NO isolation. The decoys are harmless (they never execute input) and bind to
127.0.0.1 only, but this mode is for demos and development, not for deployment.
"""
import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCAL = ROOT / ".local"
VENV = LOCAL / "venv"
PY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
HOST_KEY = LOCAL / "host_key"
DB = LOCAL / "trap.db"
REQS = ["api/requirements.txt", "decoy_web/requirements.txt", "decoy_ssh/requirements.txt"]
PORTS = {"dashboard/api": 8000, "web decoy": 8081, "ssh decoy": 2222}


def port_free(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def setup():
    LOCAL.mkdir(exist_ok=True)
    if not PY.exists():
        print("[setup] creating virtualenv (one time)...")
        run([sys.executable, "-m", "venv", VENV])
    stamp = LOCAL / ".deps-ok"
    newest = max((ROOT / r).stat().st_mtime for r in REQS)
    if not stamp.exists() or stamp.stat().st_mtime < newest:
        print("[setup] installing dependencies...")
        args = [PY, "-m", "pip", "install", "-q", "--disable-pip-version-check"]
        for r in REQS:
            args += ["-r", ROOT / r]
        run(args)
        stamp.touch()
    if not HOST_KEY.exists():
        print("[setup] generating throwaway SSH host key...")
        run([PY, "-c",
             "import asyncssh,sys;asyncssh.generate_private_key('ssh-rsa',key_size=2048).write_private_key(sys.argv[1])",
             HOST_KEY])


def wait_http(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return True
        except Exception:
            time.sleep(0.4)
    return False


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete the local database first")
    ap.add_argument("--attack", action="store_true", help="run the scripted attacker once the stack is up")
    args = ap.parse_args()

    busy = [f"{n} (port {p})" for n, p in PORTS.items() if not port_free(p)]
    if busy:
        sys.exit("These ports are already in use: " + ", ".join(busy) +
                 "\nStop whatever is using them (e.g. `docker compose down`) and try again.")

    setup()
    if args.reset and DB.exists():
        DB.unlink()
        print("[setup] database reset")

    base = dict(os.environ, PYTHONUNBUFFERED="1", TRAP_KEY="trap-demo-key", TRUST_XFF="1",
                API_URL="http://127.0.0.1:8000", CANARY_BASE="http://127.0.0.1:8000")
    procs = []
    try:
        procs.append(("api", subprocess.Popen(
            [str(PY), "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=ROOT / "api", env=dict(base, DB_PATH=str(DB)))))
        if not wait_http("http://127.0.0.1:8000/health"):
            sys.exit("api did not start")
        procs.append(("web", subprocess.Popen(
            [str(PY), "app.py"], cwd=ROOT / "decoy_web", env=dict(base, BIND="127.0.0.1", PORT="8081"))))
        procs.append(("ssh", subprocess.Popen(
            [str(PY), "server.py"], cwd=ROOT / "decoy_ssh", env=dict(base, HOST_KEY=str(HOST_KEY)))))
        if not wait_http("http://127.0.0.1:8081/login"):
            sys.exit("web decoy did not start")
        time.sleep(1.0)

        print("\n=== Tarpit Ghost is running (local mode, no Docker) ===")
        print("  Defender dashboard : http://127.0.0.1:8000")
        print("  Decoy web portal   : http://127.0.0.1:8081")
        print("  Decoy SSH          : ssh admin@127.0.0.1 -p 2222   (any password; accepts the 2nd try)")
        print("  Run the attacker   : python attacker_demo/attack.py     (in another terminal)")
        print("  Ctrl-C to stop.\n")

        if args.attack:
            subprocess.run([str(PY), str(ROOT / "attacker_demo" / "attack.py"), "--fast"])

        while True:
            for name, p in procs:
                if p.poll() is not None:
                    sys.exit(f"{name} exited unexpectedly (code {p.returncode})")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        for _, p in procs:
            if p.poll() is None:
                p.terminate()
        for _, p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
