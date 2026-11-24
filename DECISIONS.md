# Decisions (Tarpit Ghost)

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
- Adaptive fake filesystem: first deferred, later built as the per-session world model (plan2.md idea 1).
- Verification: first under plain Python, then under Docker (after fixing Docker Desktop: stale AF_UNIX socket files
  caused error 1920 and a backend crash; the `run` and `docker-secrets-engine` folders were renamed aside).
  Docker run: all 8 smoke tests pass, full attack incl. SSH works, hardening confirmed with `docker inspect`.
- `run_local.py` runs the three services as local Python processes (own venv in `.local/`) for machines without a working Docker; it was verified with all tests plus the full attack.

## plan2.md build (2026-11-24)
- Order built: beacon, behaviour/exports, world model, evidence harness. Cut: Cloudflare tunnel auto-start (needs the user's go-ahead), canary in Office/PDF files, ML classifier (rules only, labelled heuristic).
- Beacon shares one `_beacon()` for local and public listeners; public listener is a separate FastAPI app with no docs and a boring 404 for valid and invalid tokens alike.
- Sigma is produced with `yaml.safe_dump` of a dict, never string templates, so attacker-controlled text cannot inject YAML.
- World model: all personas are Ubuntu 20.04 so the OpenSSH banner stays consistent. Content is derived from a hash of (seed, path), so it is stable without storing files.
- Harness findings, fixed after the first run: the SSH decoy offered only an RSA host key (now also ed25519 and ecdsa, generated per start); Flask's 405 page, upper-case reason phrase and 400/500 pages were framework tells (now Apache-style). The first run also showed 1/5 on the full chain: that was a race in the harness (the decoy registers the canary in the background and the stand-in thief followed the link within milliseconds); the harness now waits 0.5 s. A real thief opening the link in under that time would still be missed; registration should be made synchronous in a hardening pass.
- Still visible to a careful scanner: `Via: waitress` response header on the web decoy.
