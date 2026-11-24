# Evidence report (generated)

Generated 2026-11-24 18:51:20 on Windows-11-10.0.26300-SP0, Python 3.12.10, commit `cbe0013`.

**Scope and honesty:** lab stack on `127.0.0.1`, stand-in attack tools written in this repo (not the real gobuster/hydra), unique source IP per run via `X-Forwarded-For` (demo-only setting). Loopback timings say nothing about real networks. Misses and fingerprint tells are reported as measured.

## 1. Detection coverage

| Action | Runs | Detected | Expected | Final levels | Median time to expected level | p95 | Behaviour class |
|---|---|---|---|---|---|---|---|
| web_recon_scan | 5 | 5/5 | MEDIUM | MEDIUM | 249 ms | 307 ms | automated-scanner |
| web_bruteforce | 5 | 5/5 | HIGH | CRITICAL | 178 ms | 221 ms | automated-scanner |
| web_sensitive_files | 5 | 5/5 | MEDIUM | MEDIUM | 50 ms | 85 ms | automated-scanner |
| web_full_chain | 5 | 5/5 | CRITICAL | CRITICAL | 561 ms | 587 ms | automated-scanner |
| web_low_and_slow | 2 | 2/2 | MEDIUM | MEDIUM | 3048 ms | 3056 ms | unknown |
| benign_browse | 5 | 5/5 | stay LOW | LOW | n/a | n/a | unknown |
| ssh_session | 3 | 3/3 | HIGH | HIGH | 900 ms | 1101 ms | scripted-tool |

Time to expected level = from the first request of the action until the dashboard API first reported that level (includes ~25 ms polling and HTTP overhead). 'Detected' means the session reached the expected level; for `benign_browse` it means the session stayed LOW.

**False positives on ordinary browsing:** 0 of 5 benign page loads reached MEDIUM or higher. Caveat: a decoy has no legitimate users, so any touch is suspicious by design; this only shows a normal page load is not scored as an attack.

## 2. Realism and fingerprint checks

| Check | Result |
|---|---|
| adaptivity | pass |
| ssh_banner_vs_os | pass: OpenSSH 8.2p1 matches the claimed Ubuntu 20.04 |
| ssh_host_key_algorithms | pass: host key algorithms resemble stock OpenSSH |
| http_error_pages | pass |
| http_response_timing_ms | informational (a lab loopback measurement; says nothing about WAN behaviour) |
| ssh_command_timing_ms | pass: response times vary like a real host |

## 3. External tools

| Tool | Status | Notes |
|---|---|---|
| nmap | skipped (not installed) |  |
| ssh-audit | skipped (not installed) |  |
| nikto | skipped (not installed) |  |

Rows marked skipped were not run, so nothing is claimed about them.

## 4. What this does NOT show

- Detection of real attackers, or of attackers who never touch a decoy.
- Resistance to a skilled human or to scanners not listed above. Passing these checks is not proof the decoy is undetectable.
- Anything about performance over a real network.
