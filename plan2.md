# plan2.md: Four novelty upgrades for Living Hacker Trap (PS-CYB-03)

Status of the base project (already built and tested): web decoy, SSH decoy with a canned fake shell, FastAPI api
with explainable risk scoring, session-bound canary token, SOC-style dashboard, text-only block rules,
Docker hardening with egress isolation, 13 passing tests, `run_local.py` fallback.

Goal of this plan: close the gaps a judge will find. The base project is a competent *static* honeypot; the four
upgrades make it **adaptive (living), traceable off-network, measured, and useful to other defenders**.

Be honest in every claim. Report real numbers, including failures. Never write "undetectable" or "100%".

---

## The four ideas at a glance

| # | Name | Gap it closes | Demo moment | Effort |
|---|------|---------------|-------------|--------|
| 1 | **World-model shell** (adaptive fake machine) | "Not living": same canned answers for every attacker | Two attackers see two consistent, different machines | 5-6 h |
| 2 | **Off-network beacon canary** | Canary only fires on this PC | Open the stolen file on a phone, alert appears with the phone's IP and user agent | 2-3 h |
| 3 | **Evidence harness** (red-team scoreboard) | "No evidence it works"; the 10 ms vanity metric | A table: real tools vs. detection rate, false positives, fingerprint checks | 3-4 h |
| 4 | **Session-to-detection-rule** (behaviour class + Sigma/ATT&CK export) | "Block-by-IP is weak value" | Click a session, get a Sigma rule and an ATT&CK Navigator layer | 3 h |

Total about 14 to 16 hours of the 24, leaving time for polish, the demo script and a recorded backup.
**Build order: 2, 4, 1, 3** (quick wins first, so something new works early). If time runs short, cut in this order:
idea 4's Navigator export, idea 3's fingerprint checks, idea 1's LLM mode (keep rule mode).

---

## Safety rules (apply to all four ideas; non-negotiable)

1. The decoys **never execute** attacker input. Generated text is only ever returned as text.
2. No hacking back. Beacons only record what the opener's own request reveals (IP, user agent, time).
3. Decoys stay on the `internal: true` network. Idea 2's tunnel points at the **api canary route only**,
   never at a decoy.
4. Anything attacker-controlled is rendered with `textContent` only. Rules and exports are text for a human to review.
5. Secrets (tunnel tokens, model keys) come from environment variables, never committed. Add to `.gitignore`.
6. Only test against your own machine. Do not run scanners against anything you do not own.

---

## Idea 1: World-model shell (adaptive fake machine)

**What it is.** Each SSH session gets its own consistent fake machine: hostname, users, installed packages,
a file tree, shell history, running processes. The shell can answer commands that were never scripted by
**generating** plausible content, then **remembering** it, so a second `cat` of the same file returns the same text.
Every generated file that looks valuable (credentials, `.env`, backups, keys) embeds a **unique per-file canary**.

**Why it is novel.** Static decoys give the same answers to everyone and give themselves away. Per-session state plus
on-demand generation plus per-file tracking means each attacker walks through a different world, and every stolen
file can be traced back to the exact session and path.

**Files to touch**
- `decoy_ssh/fakefs.py`: add `WorldState` (persona, users, tree as dict, history, processes) seeded per session.
- `decoy_ssh/worldgen.py` (new): `generate_file(path, persona)` and `generate_output(cmd, state)`.
  - **Mode A, rules (default, always works, offline):** templates plus seeded randomness (names, dates, IPs, passwords).
  - **Mode B, local LLM (optional):** call a local Ollama model with a strict prompt, 3 s timeout, fall back to Mode A.
    Env: `WORLDGEN_MODE=rules|llm`, `OLLAMA_URL`, `OLLAMA_MODEL`.
- `decoy_ssh/server.py`: build a `WorldState` per connection; pass `canary(path)` callback that registers a token with the api.
- `api/main.py`: no schema change; reuse `/canary` (label = file path). Add the file path to the canary event detail.

**Design rules**
- **Consistency over cleverness:** once a path's content is generated, store it in `WorldState` and always return the stored text.
- **Persona pool:** 4 to 6 personas (e.g. web server, small-office file server, dev box, DB host) chosen by seed; hostname, banner,
  `uname -a`, `/etc/os-release`, users and cron all agree with the persona.
- **Realism details:** command latency jitter (30 to 250 ms), correct `command not found` text, believable `ps`, `df`, `last`, `history`.
- **LLM safety:** the model only produces text for a fixed set of "render this file/output" prompts. Strip anything that looks like
  a real secret format you did not seed. Cap output length. The model never sees attacker input unescaped beyond the command string,
  and its output is never interpreted.
- Mode B must not be required for the demo.

**Acceptance tests (add to `tests/test_worldmodel.py`, offline)**
- Same seed gives identical machine; different seeds give different hostnames and file lists.
- `cat` the same generated file twice returns identical text.
- A generated credentials file contains a canary URL whose token is registered with a path label.
- Nothing is ever executed (extend the existing never-executes test to generated paths).
- Latency stays under 400 ms in rules mode.

**Demo.** Two terminals SSH in; `hostname`, `ls`, `cat` differ, each stays consistent, and the dashboard shows which file was stolen.

---

## Idea 2: Off-network beacon canary

**What it is.** Bait files and fake keys contain a beacon URL that is reachable from the internet, so when an attacker
exfiltrates a file and opens it **on their own machine**, the api records that device's IP, user agent and time and raises a CRITICAL alert
linked to the original session.

**Why it is novel.** Most demo canaries only work inside the lab. This shows attribution that survives exfiltration.

**Approach**
- Expose **only** `GET /c/{token}` publicly through a tunnel (Cloudflare Tunnel or similar). Everything else on the api stays local.
  Add a small public-only gateway container or an app-level allow-list (`PUBLIC_MODE=1` makes the public listener serve `/c/*` and nothing else).
- `CANARY_BASE` env var already exists; set it to the public URL. Fall back to `http://127.0.0.1:8000` when no tunnel is set.
- Capture on a hit: IP (trust only the tunnel's header), user agent, `Referer`, `Accept-Language`, timestamp, **time since the file was taken**.
- Add a tiny transparent-pixel route `/p/{token}.png` so an HTML bait document beacons when rendered.
- Add `Content-Type` variants: the `/c/` route stays a boring 404; the pixel returns a 1x1 PNG.
- Dashboard: a "Beacon hits" card with device IP, UA, delay after theft, and a flag when the IP differs from the session's IP
  (**"file left the network"**).

**Risks to state plainly.** Needs internet at the venue (keep a recorded backup clip). The IP seen is the opener's, which may be a VPN or proxy.
Public exposure means the route must be rate-limited and must return the same boring response for unknown tokens (already true).

**Acceptance tests**
- With `PUBLIC_MODE=1`, `/sessions`, `/stats`, `/analytics`, `/block-rule` are **not** reachable on the public listener; `/c/{token}` is.
- A hit from a different IP than the session's marks the event `off_network: true`.
- Unknown token returns the same 404 body and timing class as a known one.
- Pixel route returns a valid PNG and records a hit.

**Demo.** Take the bait via SSH or the portal, send the file to a phone, open it, and watch the alert appear with the phone's details.

---

## Idea 3: Evidence harness (red-team scoreboard)

**What it is.** A script that attacks the deployed stack with **real, off-the-shelf tools** and produces an honest scoreboard.
It replaces the "10 ms" headline with numbers that mean something.

**Metrics**
- **Detection coverage:** of N attack actions, how many produced an alert, and which level.
- **Time to alert:** from the action to the alert on the dashboard, reported as median and p95, labelled "local loopback".
- **False positives:** replay benign traffic (health checks, a normal browser load of the public landing page) against the decoys and the api.
  Decoys should see near-zero legitimate traffic by design; state what the harness actually measured, not the theory.
- **Realism / fingerprint checks:** run publicly available checks (e.g. `ssh-audit`, `nmap -sV` banner grab, a banner/host-key consistency check,
  response-timing variance) and report **which ones flag the decoy**. Failures go in the table.
- **Dwell time:** how long scripted "human-like" sessions stayed engaged before disconnecting.

**Files**
- `eval/run_eval.py` (new): orchestrates tools, calls the api for results, writes `eval/results.json` and `eval/RESULTS.md`.
- `eval/tools.md`: which tools to install (nmap, hydra, gobuster, nikto, ssh-audit; all optional, skip cleanly if missing).
- Dashboard (optional): an "Evidence" tab that renders `results.json`.

**Rules**
- Run only against `127.0.0.1`. Pin tool versions in `RESULTS.md`.
- Report what failed. A table with honest red cells is worth more than a table of green.
- Do not claim real-world detection rates; claim "on this lab, against these tools".

**Acceptance**
- `python eval/run_eval.py` exits 0 even if tools are missing and clearly marks skipped rows.
- `RESULTS.md` lists tool, version, actions, detected, level, time, and notes on every row.

**Demo.** One slide or screen with the scoreboard, plus a live run of a single tool (hydra against the web login) alerting in real time.

---

## Idea 4: Session-to-detection-rule (behaviour class + Sigma/ATT&CK export)

**What it is.** The api classifies each session as **bot / scripted tool / likely human** from timing and command patterns, then lets the defender
export (a) a **Sigma rule** describing the behaviour, (b) a **Suricata-style signature** where applicable, and (c) an **ATT&CK Navigator layer** JSON.
Output is reusable by other defenders, unlike an IP block.

**Classification (rule-based, explainable; no ML claim)**
- Inputs per session: inter-event gaps, request rate, command count, paste-like bursts (many chars with near-zero gap), repeated identical
  user agents, wordlist-like credential order, tool-signature user agents or paths (gobuster, nikto, hydra patterns).
- Output: `class`, `confidence` (low/medium/high), and the **reasons** shown in the UI. If evidence is thin, say "unknown".

**Exports**
- `GET /sessions/{id}/sigma` returns a Sigma YAML: logsource (web or auth), selection of the observed paths, user-agent or command patterns,
  condition, ATT&CK tags, level from the risk level. Static text only; values are escaped. Include a header comment: "generated, review before use".
- `GET /sessions/{id}/navigator` returns a Navigator layer JSON using the existing ATT&CK mapping (keep the "indicative" label).
- Keep the IP block rule, but label it "weak, easy to evade".

**Files**
- `api/classify.py` (new): `classify(events) -> {class, confidence, reasons}`.
- `api/export.py` (new): `to_sigma(session)`, `to_navigator(session)`.
- `api/main.py`: add the two GET routes; include `class` in `GET /sessions/{id}`.
- Dashboard: a "Behaviour" line in the attacker profile and "Export Sigma" / "Export ATT&CK" buttons.

**Acceptance (offline unit tests in `tests/test_export.py`)**
- A scripted attack session classifies as bot or scripted; a slow, irregular session classifies as likely human or unknown.
- The generated Sigma YAML parses (use `yaml.safe_load`) and contains the observed path or command and valid ATT&CK tags.
- Hostile input (quotes, newlines, `---`, YAML tricks in a command string) cannot break out of the YAML; test it.
- The Navigator JSON validates as JSON and lists only techniques actually seen.

**Demo.** Click the attacker session and download a Sigma rule; show it is human-readable and tied to what was actually observed.

---

## Shared work

- **Dashboard:** add one "Novelty" strip to the header badges (World model on, Beacon public/local, Evidence last run).
- **Docs:** update `README.md` (one new section per idea), `DECISIONS.md` (what was cut and why), and add an "Honest limits" list.
- **Tests:** keep `tests/test_fakefs.py` and `tests/test_smoke.py` green after every idea; run both before each commit.
- **Demo script (3 minutes):** (1) two attackers, two worlds; (2) stolen file opens on a phone; (3) scoreboard; (4) Sigma export.
- **Fallbacks:** record a backup video of the beacon demo and the full demo; `run_local.py` must still work without Docker.
- **PPT:** replace the "10 ms" headline with the strongest of ideas 1 to 3 once measured; keep the 10 ms as a footnote, labelled local.

## Honest limits to put in the README and say out loud
- The beacon needs internet and reveals only the opener's IP; a VPN hides the real source.
- Rule-based classification is a heuristic, not proof of identity or skill.
- Scoreboard numbers hold for this lab and these tool versions only.
- The LLM mode can be slow or inconsistent; rules mode is the dependable path.
- No honeypot is undetectable. Report which fingerprint checks flagged ours.

## Definition of done
- [x] Idea 2: public listener exposes only `/c/*` and the pixel route (tested); off-network flag tested with a simulated Cloudflare header. NOT done: a real phone over a real tunnel.
- [x] Idea 4: Sigma and Navigator exports and classifier pass their tests (7).
- [x] Idea 1: different, self-consistent machines per session and path-labelled canaries (10 offline tests). LLM mode untested against a real model.
- [x] Idea 3: `eval/RESULTS.md` produced; first run found 2 fingerprint tells (fixed) and a harness race.
- [~] All tests pass under Docker (5 fakefs, 10 worldmodel, 7 export, 8 smoke, 5 beacon). `run_local.py` NOT re-run after these changes.
- [~] README and DECISIONS updated. PPT headline and backup demo video NOT done.
