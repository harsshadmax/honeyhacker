# Hacker Trap: a living deception system (PS-CYB-03)

An active defence tool. It lures attackers into believable fake services, keeps them sealed in
containers, records every move, alerts the defender live, tracks a bait file with a canary token,
and generates a one-click firewall block rule.

> **Defensive tool for your own machine.** Decoys never execute anything the attacker types, ports are bound
> to `127.0.0.1`, and block rules are only *generated as text*, never applied.

## Quickstart (3 commands)

```powershell
docker compose up --build -d          # starts api, web decoy, ssh decoy
python attacker_demo/attack.py        # runs the scripted attacker (add --fast to skip pauses)
start http://127.0.0.1:8000           # defender console
```

**No Docker?** Run everything locally with one command (creates its own virtualenv on first run):

```powershell
python run_local.py              # add --reset to wipe data, --attack to run the demo attacker automatically
```

Same URLs and ports as below. Local mode has **no container isolation** (the decoys are still harmless and bound to
127.0.0.1); use Docker for the safety story. Press Ctrl-C to stop.

Optional: `pip install asyncssh` first if you want the attacker script's SSH phase (use `--skip-ssh` otherwise).
Reset all data: `docker compose down -v`.

| What | Where |
|---|---|
| Defender console (dashboard) | http://127.0.0.1:8000 |
| Decoy admin portal (web) | http://127.0.0.1:8081 (container port 8080; 8080 was taken on the dev PC) |
| Decoy SSH | `ssh admin@127.0.0.1 -p 2222` (accepts the 2nd password you try) |

## Architecture

```
attacker --> decoy_web (Flask/waitress :8081) ---\
attacker --> decoy_ssh (asyncssh :2222) ---------+--> api (FastAPI :8000) --> SQLite
bait file canary URL  (/c/<token>) --------------/        |-- WebSocket /ws --> dashboard (static HTML+JS)
                                                          |-- POST /events, GET /sessions[/{id}], GET /stats
                                                          '-- POST /block-rule  (returns text only)
```

* **decoy_web**: fake "Northwind Corp" admin login. Logs every request and login attempt. After 3+ failures (or a
  weak admin password) the attacker "gets in" and can download `passwords_backup.txt`, which embeds a **unique
  canary URL**. Also serves tempting `/.env` and `/backup.sql`.
* **decoy_ssh**: asyncssh server with an in-memory fake Linux box. Every command is logged and answered from canned
  text; nothing is ever executed. `cat passwords_backup.txt` hands out another canary-tagged bait.
* **api**: stores events, scores risk, streams to the dashboard over WebSocket, serves the canary endpoint and generates
  block rules (IP strictly validated; output is text for a human to review).
* **dashboard**: live alert feed, session list with risk badges, replay timeline (with Play), risk-score reasons and the
  "Generate block rule" button. Attacker-controlled text is rendered with `textContent` only, so it cannot XSS the console.

## Risk scoring (explainable)

login attempt +5 · brute force (3+ failures) +15 · got past fake login +20 · suspicious command +15 each ·
sensitive file probe +10 · bait downloaded +25 · **canary triggered = CRITICAL (100)**.
LOW < 20 ≤ MEDIUM < 50 ≤ HIGH < 90 ≤ CRITICAL. Each session shows its breakdown.

## Demo script (about 3 minutes)

1. Open the dashboard (`http://127.0.0.1:8000`) on one side, a terminal on the other.
2. Run `python attacker_demo/attack.py`. Narrate each `[ATTACKER]` step.
3. Point out the live feed filling up, the **red canary banner**, and the session turning CRITICAL.
4. Click the session, press **Play replay**, then **Generate block rule**.
5. Optional live touch: `ssh admin@127.0.0.1 -p 2222`, type any password twice, run `ls`, `cat passwords_backup.txt`.

## Four additions (plan2.md)

1. **World-model shell** (`decoy_ssh/worldgen.py`): every SSH session gets its own self-consistent fake machine (persona, hostname,
   IP, users, processes, files). Same path always returns the same text; every generated secret file carries its own canary.
   Optional local-LLM mode (`OLLAMA_URL`) is only for non-secret files and falls back to rules; it works under `run_local.py`
   but not inside the isolated Docker network. Not wired or tested against a real model here.
2. **Beacon off the box** (`/c/{token}`, `/p/{token}.png`): a second listener on `PUBLIC_PORT` (8090) serves only those two routes.
   A hit from an IP that differs from the thief's session IP is flagged *off-network*. It needs a public URL (tunnel or reverse
   proxy, set `CANARY_BASE`; `PUBLIC_TRUST_CF=1` behind Cloudflare). **No tunnel is started by this repo.** Opened through a VPN
   or a mail scanner it will still fire, so treat "off-network" as strong evidence, not proof of a second human.
3. **Evidence harness** (`eval/run_eval.py`, output `eval/RESULTS.md`): stand-in attack tools, time-to-detect, false-positive
   check, fingerprint checks. Lab numbers on loopback only. `nmap`, `ssh-audit`, `nikto` are used if installed.
4. **Behaviour class + exports**: rule-based `automated-scanner / scripted-tool / likely-human / unknown` with reasons
   (heuristic, not ML), a Sigma rule and an ATT&CK Navigator layer per session (`/sessions/{id}/sigma`, `/navigator`).

## Tests

```powershell
python tests/test_fakefs.py     # offline, no Docker needed
python tests/test_worldmodel.py # offline
python tests/test_export.py     # offline
python tests/test_smoke.py      # needs the stack running (docker compose up)
python tests/test_beacon.py     # needs the stack; set PUBLIC_TRUST_CF=1 on the api to exercise the off-network case
python eval/run_eval.py         # needs the stack; writes eval/RESULTS.md
```

## Safety and known limits (be upfront about these)

Hardening in `docker-compose.yml`: egress-blocked decoy network, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, non-root users,
memory/CPU/pid limits, no host mounts, ports on `127.0.0.1` only. The fake shell never calls a shell or the OS.

Known limits:
* **Egress is blocked for decoys.** They live on an `internal: true` Docker network (no route to the internet or host);
  attackers reach them only through two tiny `socat` gateway containers. Verified: decoys cannot resolve or reach
  outside hosts but can still reach the api. This applies to the Docker version only, not `run_local.py`.
* **Source IPs:** behind Docker Desktop on Windows, the SSH decoy sees Docker's gateway IP, not the real client. For the
  web decoy the demo trusts `X-Forwarded-For` (`TRUST_XFF=1`) so the attack script can simulate a source IP. Never enable
  that on a public deployment.
* The dashboard and `/block-rule` have no login (demo scope). The decoys authenticate to the api with a shared key.
* The canary URL points at `127.0.0.1:8000`, so it only trips when opened from this machine. A real deployment would use
  a public hostname.
* SQLite and an in-memory brute-force/auth state: restarting a decoy forgets who was "logged in".

## Credits

Python, FastAPI, Flask, waitress, asyncssh (see `*/requirements.txt`). Honeypot and canary-token concepts follow the
public ideas behind Cowrie and Thinkst Canarytokens; no code from those projects is used here.
