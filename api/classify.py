"""Explainable behaviour classification for one session. Rule-based on purpose: every verdict lists its reasons.

Output classes (a heuristic about *behaviour*, never an identity claim):
  automated-scanner   many requests, fast, tool-like user agent or wordlist order
  scripted-tool       fast, regular timing and/or scripted command bursts
  likely-human        slow, irregular gaps between actions, interactive pacing
  unknown             not enough evidence either way (this is the honest default)
"""
import re
import statistics

TOOL_UA = re.compile(
    r"(sqlmap|nikto|gobuster|dirbuster|dirb|ffuf|wfuzz|hydra|medusa|nmap|masscan|zgrab|nuclei|"
    r"python-requests|python-urllib|aiohttp|go-http-client|libwww|curl/|wget/|okhttp|httpx|attack-demo)",
    re.I,
)
SCRIPT_CMD = re.compile(r"(wget|curl)\s+\S+.*(\||;|&&)|chmod\s+\+x|base64\s+-d|bash\s+-i|nc\s+-e", re.I)


def _gaps(ts):
    return [b - a for a, b in zip(ts, ts[1:]) if b >= a]


def classify(events: list[dict]) -> dict:
    """events: dicts with ts, kind, detail (as returned by the API). Returns class, confidence, reasons, features."""
    ev = [e for e in events if e["kind"] not in ("blocked", "blocked_hit")]
    reasons: list[str] = []
    bot, scripted, human = 0, 0, 0

    ts = [e["ts"] for e in ev]
    gaps = _gaps(ts)
    dur = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
    n = len(ev)
    median_gap = statistics.median(gaps) if gaps else None
    cv = None
    if len(gaps) >= 4:
        mean = statistics.fmean(gaps)
        cv = (statistics.pstdev(gaps) / mean) if mean > 0 else 0.0

    # --- user agent evidence (web) ---
    uas = [e["detail"].get("ua") or e["detail"].get("user_agent") or "" for e in ev]
    tool_uas = sorted({m.group(1).lower() for ua in uas if (m := TOOL_UA.search(ua))})
    if tool_uas:
        bot += 2
        reasons.append("Tool-like user agent: " + ", ".join(tool_uas[:3]))

    # --- request volume and speed ---
    reqs = [e for e in ev if e["kind"] == "request"]
    paths = {e["detail"].get("path") for e in reqs if e["detail"].get("path")}
    if len(paths) >= 8 and dur and len(paths) / max(dur, 0.001) > 3:
        bot += 2
        reasons.append(f"{len(paths)} distinct paths at {len(paths) / max(dur, 0.001):.1f}/s (wordlist-style scan)")

    # --- credential guessing ---
    logins = [e for e in ev if e["kind"] == "login_attempt"]
    if len(logins) >= 3:
        lg = _gaps([e["ts"] for e in logins])
        if lg and statistics.median(lg) < 0.5:
            scripted += 2
            reasons.append(f"{len(logins)} login attempts, median gap {statistics.median(lg) * 1000:.0f} ms (automated guessing)")
        elif lg and statistics.median(lg) > 3:
            human += 1
            reasons.append(f"{len(logins)} login attempts spaced {statistics.median(lg):.1f}s apart (manual pacing)")

    # --- shell behaviour ---
    cmds = [e for e in ev if e["kind"] in ("command", "suspicious_command")]
    if len(cmds) >= 2:
        cg = _gaps([e["ts"] for e in cmds])
        if cg and statistics.median(cg) < 0.4:
            scripted += 2
            reasons.append(f"{len(cmds)} shell commands, median gap {statistics.median(cg) * 1000:.0f} ms (pasted or scripted)")
        elif cg and statistics.median(cg) >= 1.5:
            human += 2
            reasons.append(f"{len(cmds)} shell commands, median gap {statistics.median(cg):.1f}s (interactive pacing)")
    if any(SCRIPT_CMD.search(str(e["detail"].get("cmd", ""))) for e in cmds):
        scripted += 1
        reasons.append("Download-and-execute style command")

    # --- overall timing regularity ---
    if cv is not None and n >= 6:
        if cv < 0.35 and (median_gap or 1) < 1.0:
            scripted += 1
            reasons.append(f"Very regular timing (variation {cv:.2f}); machines are regular, people are not")
        elif cv > 0.9 and (median_gap or 0) > 1.0:
            human += 1
            reasons.append(f"Irregular timing (variation {cv:.2f})")

    # --- verdict ---
    score_auto = bot + scripted
    if bot >= 2 and (len(paths) >= 8 or tool_uas):
        cls = "automated-scanner"
        conf = "high" if bot >= 3 or (tool_uas and len(paths) >= 8) else "medium"
    elif scripted >= 2 and scripted > human:
        cls = "scripted-tool"
        conf = "high" if scripted >= 4 else "medium"
    elif human >= 2 and human > score_auto:
        cls = "likely-human"
        conf = "medium" if human >= 3 else "low"
    else:
        cls, conf = "unknown", "low"
        if not reasons:
            reasons.append("Not enough activity to tell")
    return {
        "class": cls, "confidence": conf, "reasons": reasons,
        "features": {
            "events": n, "duration_s": round(dur, 2),
            "median_gap_s": None if median_gap is None else round(median_gap, 3),
            "timing_variation": None if cv is None else round(cv, 2),
            "distinct_paths": len(paths), "tool_user_agents": tool_uas,
        },
        "note": "Heuristic about behaviour only. Not proof of identity, skill or intent.",
    }
