"""Offline tests for behaviour classification and Sigma/Navigator export. Run: python tests/test_export.py"""
import json
import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
from classify import classify  # noqa: E402
from export import to_navigator, to_sigma  # noqa: E402

ATTACK = {"request": ("T1595", "Active Scanning"), "sensitive_probe": ("T1552.001", "Credentials In Files"),
          "login_attempt": ("T1110", "Brute Force"), "bruteforce_detected": ("T1110.001", "Password Guessing"),
          "suspicious_command": ("T1059.004", "Unix Shell"), "command": ("T1059", "Command")}
SESSION = {"id": "web-abc123", "src_ip": "203.0.113.5", "service": "web", "risk_level": "HIGH"}


def ev(i, ts, kind, **detail):
    return {"id": i, "ts": ts, "kind": kind, "detail": detail, "severity": "info", "points": 0}


def scanner_events():
    out = [ev(i, 100 + i * 0.05, "request", method="GET", path=f"/p{i}", ua="gobuster/3.6") for i in range(20)]
    out.append(ev(99, 101.2, "sensitive_probe", path="/.env"))
    return out


def human_events():
    t = 100.0
    out = []
    for i, gap in enumerate([0, 4.2, 9.1, 2.0, 11.5, 3.3, 6.8]):
        t += gap
        out.append(ev(i, t, "command", cmd=["ls", "pwd", "cat notes.txt", "whoami", "ls -la", "cd /var", "ls"][i]))
    return out


def test_scanner_is_flagged_automated():
    c = classify(scanner_events())
    assert c["class"] == "automated-scanner", c
    assert any("gobuster" in r for r in c["reasons"])


def test_slow_human_pacing_is_not_called_a_bot():
    c = classify(human_events())
    assert c["class"] in ("likely-human", "unknown"), c
    assert c["class"] != "automated-scanner"


def test_thin_evidence_is_unknown():
    c = classify([ev(1, 100, "request", path="/", ua="Mozilla/5.0")])
    assert c["class"] == "unknown" and c["confidence"] == "low"


def test_fast_scripted_commands():
    evs = [ev(i, 100 + i * 0.05, "command", cmd=c) for i, c in enumerate(["id", "uname -a", "ls", "cat /etc/passwd"])]
    assert classify(evs)["class"] == "scripted-tool"


def test_sigma_parses_and_reflects_observation():
    b = classify(scanner_events())
    text = to_sigma(SESSION, scanner_events(), ATTACK, b)
    doc = yaml.safe_load(text)
    assert doc["logsource"]["category"] == "webserver"
    assert "/.env" in doc["detection"]["web_paths"]["cs-uri-stem|contains"]
    assert "gobuster" in doc["detection"]["tool_agent"]["c-useragent|contains"]
    assert "attack.t1552.001" in doc["tags"] and doc["level"] == "high"
    assert doc["status"] == "experimental" and "GENERATED" in doc["description"]


def test_sigma_is_injection_safe():
    evil = ['x"\n---\nlevel: informational', "'; !!python/object/apply:os.system ['calc']", "a: b\n- c", "\u0000‮\U0001F600"]
    evs = [ev(i, 100 + i, "suspicious_command", cmd=e) for i, e in enumerate(evil)]
    evs += [ev(10, 110, "sensitive_probe", path=e) for e in evil]
    text = to_sigma({**SESSION, "service": "ssh"}, evs, ATTACK, None)
    docs = list(yaml.safe_load_all(text))
    assert len(docs) == 1, "hostile text must not create a second YAML document"
    assert docs[0]["level"] == "high", "hostile text must not override fields"
    assert isinstance(docs[0]["detection"]["shell_commands"]["CommandLine|contains"], list)


def test_navigator_lists_only_observed_techniques():
    layer = to_navigator(SESSION, scanner_events(), ATTACK)
    json.dumps(layer)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1595", "T1552.001"}
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"


if __name__ == "__main__":
    bad = 0
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            try:
                f(); print("PASS", n)
            except Exception as e:
                bad += 1; print("FAIL", n, repr(e))
    sys.exit(1 if bad else 0)
