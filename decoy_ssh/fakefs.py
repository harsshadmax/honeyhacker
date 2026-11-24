"""In-memory fake Linux box. NOTHING here ever executes a command: it only returns text."""
import posixpath
import shlex

try:  # the sentinel lives with the world model; static mode never needs it
    from worldgen import DENIED
except ImportError:  # pragma: no cover
    DENIED = object()

HOST = "web-prod-03"

DIRS = {
    "/": ["bin", "etc", "home", "root", "tmp", "usr", "var", "opt"],
    "/home": ["admin"],
    "/home/admin": ["passwords_backup.txt", "notes.txt", "projects", ".bash_history", ".ssh"],
    "/home/admin/projects": ["payroll-sync", "deploy.sh"],
    "/home/admin/.ssh": ["authorized_keys"],
    "/etc": ["passwd", "hostname", "os-release", "hosts", "crontab"],
    "/tmp": [],
    "/var": ["log", "www", "backups"],
    "/var/log": ["auth.log", "syslog"],
    "/var/www": ["html"],
    "/var/backups": ["db_2024.sql.gz"],
    "/opt": [],
    "/usr": ["bin", "lib"],
    "/root": [],
}

FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:110:116:MySQL Server:/nonexistent:/bin/false\n"
        "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\nsvc_backup:x:1001:1001::/home/svc_backup:/bin/bash\n"
    ),
    "/etc/hostname": HOST + "\n",
    "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 " + HOST + "\n10.0.4.12 db-prod-01\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\n',
    "/etc/crontab": "0 2 * * * root /opt/backup.sh\n",
    "/home/admin/notes.txt": "TODO: rotate vpn creds (see passwords_backup.txt)\nTODO: patch web-prod-03\n",
    "/home/admin/.bash_history": "ls\ncd projects\nsudo systemctl restart apache2\nmysql -h 10.0.4.12 -u svc_backup -p\n",
    "/home/admin/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...FAKEKEY admin@corp\n",
    "/home/admin/projects/deploy.sh": "#!/bin/bash\n# deploy to prod\nrsync -az ./build/ web-prod-03:/var/www/html/\n",
    "/var/log/auth.log": "Nov 22 02:11:04 web-prod-03 sshd[912]: Accepted password for admin from 10.0.4.7\n",
}

BAIT_NAME = "passwords_backup.txt"
BAIT_PATH = "/home/admin/" + BAIT_NAME


class FakeFS:
    def __init__(self, user: str, on_bait=None, world=None):
        self.world = world  # optional per-session WorldState (decoy_ssh/worldgen.py); None = the original static box
        self.user = world.user if world else (user or "admin")
        self.host = world.host if world else HOST
        self.home = world.home if world else "/home/admin"
        self.cwd = self.home
        self.on_bait = on_bait  # callable -> bait text with a fresh canary URL

    # --- helpers -----------------------------------------------------------
    def prompt(self) -> str:
        shown = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.host}:{shown}$ "

    def _abs(self, p: str) -> str:
        if p.startswith("~"):
            p = self.home + p[1:]
        if not p.startswith("/"):
            p = posixpath.join(self.cwd, p)
        return posixpath.normpath(p)

    def _is_dir(self, p): return self.world.is_dir(p) if self.world else p in DIRS
    def _is_file(self, p): return self.world.is_file(p) if self.world else (p in FILES or p == BAIT_PATH)

    def _names(self, d):
        return self.world.dirs[d] if self.world else DIRS[d]

    def _read(self, p):
        """Text of a file, or None (missing) / worldgen.DENIED. Static mode keeps the original behaviour exactly."""
        if self.world:
            return self.world.read(p)
        if p == BAIT_PATH:
            return self.on_bait() if self.on_bait else "# fake credentials\n"
        return FILES.get(p)

    # --- commands ----------------------------------------------------------
    def run(self, line: str):
        """Returns (output_text, should_close). Handles ';' and '&&' chains; ignores pipes/redirects."""
        out, close = [], False
        for part in line.replace("&&", ";").split(";"):
            part = part.strip().split("|")[0].split(">")[0].strip()
            if not part:
                continue
            text, c = self._one(part)
            out.append(text)
            close = close or c
            if c:
                break
        return "".join(out), close

    def _one(self, cmd: str):
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return "bash: syntax error: unexpected end of file\n", False
        if not argv:
            return "", False
        name, args = argv[0], argv[1:]
        flags = [a for a in args if a.startswith("-")]
        pos = [a for a in args if not a.startswith("-")]

        if name in ("exit", "logout", "quit"):
            return "logout\n", True
        if name == "pwd":
            return self.cwd + "\n", False
        if name == "whoami":
            return self.user + "\n", False
        if name == "id":
            return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)\n", False
        if name == "hostname":
            return self.host + "\n", False
        if name == "uname":
            if any("a" in f for f in flags):
                if self.world:
                    return self.world.uname_a(), False
                return f"Linux {HOST} 5.4.0-169-generic #187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", False
            return "Linux\n", False
        if name == "uptime":
            if self.world:
                return self.world.uptime(), False
            return " 02:14:09 up 41 days,  3:02,  1 user,  load average: 0.08, 0.04, 0.01\n", False
        if name == "w":
            return f" 02:14:09 up 41 days\nUSER TTY FROM LOGIN@ WHAT\n{self.user} pts/0 - 02:11 -bash\n", False
        if name in ("ifconfig", "ip"):
            if self.world:
                return self.world.ifconfig(), False
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 10.0.4.21  netmask 255.255.255.0  broadcast 10.0.4.255\n"
                    "        ether 02:42:0a:00:04:15  txqueuelen 0  (Ethernet)\n"), False
        if name == "ps":
            if self.world:
                return self.world.ps(), False
            return ("  PID TTY          TIME CMD\n  912 ?        00:00:01 sshd\n 1033 ?        00:01:12 apache2\n"
                    " 1190 ?        00:03:40 mysqld\n 2210 pts/0    00:00:00 bash\n 2244 pts/0    00:00:00 ps\n"), False
        if name == "env":
            if self.world:
                return self.world.env(self.cwd), False
            return f"USER={self.user}\nHOME=/home/admin\nSHELL=/bin/bash\nPWD={self.cwd}\n", False
        if name == "echo":
            return " ".join(args) + "\n", False
        if name == "history":
            if self.world:
                return self.world.history(), False
            return "".join(f"  {i+1}  {l}\n" for i, l in enumerate(FILES["/home/admin/.bash_history"].splitlines())), False
        # commands only the world-model box answers (the static box keeps saying "command not found")
        if self.world:
            if name == "df":
                return self.world.df(), False
            if name == "free":
                return self.world.free(), False
            if name == "last":
                return self.world.last(), False
            if name == "date":
                import time as _t
                return _t.strftime("%a %b %e %H:%M:%S UTC %Y\n"), False
            if name == "crontab" and "-l" in flags:
                return self.world.read("/etc/crontab") or "", False
            if name == "lsb_release":
                return "Distributor ID:\tUbuntu\nDescription:\tUbuntu 20.04.6 LTS\nRelease:\t20.04\nCodename:\tfocal\n", False
        if name == "cd":
            target = self._abs(pos[0]) if pos else self.home
            if self._is_dir(target):
                self.cwd = target
                return "", False
            if self._is_file(target):
                return f"bash: cd: {pos[0]}: Not a directory\n", False
            return f"bash: cd: {pos[0]}: No such file or directory\n", False
        if name == "ls":
            target = self._abs(pos[0]) if pos else self.cwd
            if self._is_file(target):
                return posixpath.basename(target) + "\n", False
            if not self._is_dir(target):
                return f"ls: cannot access '{pos[0] if pos else target}': No such file or directory\n", False
            names = sorted(self._names(target))
            if any("a" in f for f in flags) or any("A" in f for f in flags):
                pass
            else:
                names = [n for n in names if not n.startswith(".")]
            if any("l" in f for f in flags):
                lines = [f"total {len(names) * 4}"]
                for n in names:
                    full = posixpath.join(target, n)
                    d = "d" if self._is_dir(full) else "-"
                    perm = "rwxr-xr-x" if d == "d" else "rw-r--r--"
                    if self.world:
                        size, when = self.world.stat(full)
                    else:
                        size, when = (4096 if d == "d" else len(FILES.get(full, "x" * 412))), "Nov 22 02:03"
                    lines.append(f"{d}{perm} 1 {self.user} {self.user} {size:>6} {when} {n}")
                return "\n".join(lines) + "\n", False
            return "  ".join(names) + ("\n" if names else ""), False
        if name in ("cat", "head", "tail", "less", "more") and (name == "cat" or self.world):
            if not pos:
                return "", False
            out = ""
            for p in pos:
                t = self._abs(p)
                if self._is_dir(t):
                    out += f"{name}: {p}: Is a directory\n"
                    continue
                text = self._read(t)
                if text is None:
                    out += (f"{name}: {p}: Permission denied\n" if t == "/etc/shadow" else f"{name}: {p}: No such file or directory\n")
                elif text is DENIED:
                    out += f"{name}: {p}: Permission denied\n"
                else:
                    if name == "head":
                        text = "".join(text.splitlines(True)[:10])
                    elif name == "tail":
                        text = "".join(text.splitlines(True)[-10:])
                    out += text
            return out, False
        if name in ("wget", "curl"):
            url = pos[-1] if pos else ""
            if not url:
                return f"{name}: missing URL\n", False
            fname = posixpath.basename(url.split("?")[0]) or "index.html"
            if name == "wget":
                return (f"--02:14:20--  {url}\nResolving host... connected.\nHTTP request sent, awaiting response... 200 OK\n"
                        f"Length: 1832 (1.8K)\nSaving to: '{fname}'\n\n{fname}            100%[===================>]   1.79K  --.-KB/s    in 0s\n\n"
                        f"'{fname}' saved [1832/1832]\n"), False
            return "", False
        if name in ("chmod", "chown", "mkdir", "touch", "rm", "mv", "cp", "kill"):
            return "", False
        if name == "sudo":
            return f"[sudo] password for {self.user}: \nSorry, try again.\nsudo: 3 incorrect password attempts\n", False
        if name in ("su",):
            return "su: Authentication failure\n", False
        if name in ("nano", "vi", "vim"):
            return "", False
        return f"bash: {name}: command not found\n", False
