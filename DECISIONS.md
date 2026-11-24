# Decisions

- Project lives in `C:\Users\Harsshad\.claude\hacker-trap` (the session's working folder); it can be moved anywhere.
- Own minimal asyncssh fake shell instead of Cowrie: fewer moving parts, full control, faster for a 2-hour build.
- Dashboard is one static HTML file with vanilla JS served by the api (no npm build to fail).
- Web decoy published on host port **8081** (container 8080) because another program already owns 8080 on this PC.
- Web decoy runs `python app.py` (waitress started in code) so `X-Forwarded-For` can be trusted when `TRUST_XFF=1`.
- Risk scoring and brute-force / suspicious-command classification live in the api only (single place).
- Canary tokens are created per bait download and bound to the session that downloaded the file, so a canary hit
  lands on the attacker's own session.
- Block rules are text only, IP validated with `ipaddress`; private/loopback IPs get a warning.
- Attacker script uses a fresh User-Agent per run so each demo run is a fresh session (brute-force fires every time).
- Egress isolation DONE: decoys on an `internal: true` network, published via socat gateways (verified by test).
- Adaptive fake filesystem (optional differentiator) NOT done; core first.
- Verification: first under plain Python, then under Docker (after fixing Docker Desktop: stale AF_UNIX socket files
  caused error 1920 and a backend crash; the `run` and `docker-secrets-engine` folders were renamed aside).
  Docker run: all 8 smoke tests pass, full attack incl. SSH works, hardening confirmed with `docker inspect`.
- `run_local.py` runs the three services as local Python processes (own venv in `.local/`) for machines without a working Docker; it was verified with all tests plus the full attack.
