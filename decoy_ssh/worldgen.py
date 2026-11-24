"""World model for the SSH decoy: every session gets its own consistent fake machine.

NOTHING in this module executes anything. It only produces text.

Consistency: all content is derived from random.Random(f"{seed}|{path}"), so the same path always yields the same text
for a session regardless of access order. Canary tokens are created once per secret path and cached, so a second `cat`
returns identical bytes (same canary URL).

Modes (WORLDGEN_MODE): "rules" (default, offline, always works) or "llm" (optional local Ollama for non-secret files only,
3 s timeout, falls back to rules on any failure). Secrets always come from rules so canary placement is guaranteed.
"""
import hashlib
import json
import os
import random
import re
import time
import urllib.request

DENIED = object()  # sentinel: path exists but reading is refused ("Permission denied")

# The SSH banner is fixed per server process (OpenSSH_8.2p1 Ubuntu), so every persona is Ubuntu 20.04. Varying the OS
# would make banner and os-release disagree, which is exactly the tell scanners look for.
OS_PRETTY = "Ubuntu 20.04.6 LTS"
KERNELS = [("5.4.0-169-generic", "#187"), ("5.4.0-167-generic", "#184"), ("5.4.0-171-generic", "#189"), ("5.4.0-174-generic", "#193")]

PERSONAS = {
    "web": {
        "hosts": ["web", "www", "app"], "desc": "an Apache/PHP production web server for a small company",
        "procs": ["/usr/sbin/apache2 -k start", "php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)", "/usr/sbin/mysqld"],
        "svc_users": ["www-data", "mysql"],
        "dirs": {
            "/var/www": ["html"],
            "/var/www/html": ["index.php", "config.php", ".env", "uploads", "db_backup.sql", "robots.txt"],
            "/var/www/html/uploads": ["logo.png", "invoice_2291.pdf"],
            "/etc/apache2": ["apache2.conf", "sites-enabled"],
            "/etc/apache2/sites-enabled": ["000-default.conf"],
        },
    },
    "files": {
        "hosts": ["fs", "files", "nas"], "desc": "an internal Samba file server used by finance and HR",
        "procs": ["/usr/sbin/smbd --foreground", "/usr/sbin/nmbd --foreground", "/usr/sbin/cron -f"],
        "svc_users": ["smbguest", "backup"],
        "dirs": {
            "/srv": ["share"],
            "/srv/share": ["finance", "hr", "public"],
            "/srv/share/finance": ["budget_q3.csv", "vendors.csv", "payroll_2024.xlsx"],
            "/srv/share/hr": ["employees.csv", "credentials.csv"],
            "/srv/share/public": ["readme.txt"],
            "/etc/samba": ["smb.conf"],
        },
    },
    "dev": {
        "hosts": ["dev", "build", "ci"], "desc": "a developer build box with git, docker and cloud credentials",
        "procs": ["/usr/bin/dockerd -H fd://", "/usr/bin/containerd", "/usr/sbin/cron -f"],
        "svc_users": ["jenkins", "docker"],
        "dirs": {
            "/opt": ["infra"],
            "/opt/infra": ["terraform.tfvars", "deploy.sh", "docker-compose.yml", ".env"],
        },
    },
    "db": {
        "hosts": ["db", "sql", "data"], "desc": "a MySQL database host with nightly dumps",
        "procs": ["/usr/sbin/mysqld", "/usr/sbin/cron -f", "/usr/bin/python3 /opt/backup/run_backup.py"],
        "svc_users": ["mysql", "backup"],
        "dirs": {
            "/var/lib": ["mysql"],
            "/var/lib/mysql": ["ibdata1", "corp_hr", "mysql.sock"],
            "/etc/mysql": ["my.cnf"],
            "/opt": ["backup"],
            "/opt/backup": ["run_backup.py", "db_full.sql"],
        },
    },
}

SECRET_NAMES = {
    "config.php", ".env", "db_backup.sql", "db_full.sql", "credentials.csv", "terraform.tfvars", "my.cnf",
    "passwords_backup.txt", "id_rsa", "credentials", "config",
}
BIN_EXT = (".png", ".pdf", ".xlsx", ".gz", ".tar", ".sock")
FIRST = ["Priya", "Arjun", "Meera", "Rohan", "Kavya", "Vikram", "Anita", "Sanjay", "Neha", "Karthik"]
LAST = ["Kumar", "Rao", "Iyer", "Nair", "Sharma", "Menon", "Reddy", "Patel", "Das", "Gupta"]
COMPANY = ["Northwind", "Contoso Labs", "Fabrikam", "Globex", "Initech", "Umbrella Works", "Acme Systems"]


def _rng(*parts) -> random.Random:
    return random.Random(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest())


def _secret(rng, kind="pw") -> str:
    base = rng.choice(["Summer", "Winter", "Monsoon", "Falcon", "Orion", "Delta", "Granite", "Harbor"])
    return f"{base}{rng.randint(10, 99)}{rng.choice('!#$%@')}{rng.choice(['rotate', 'prod', 'svc', 'x'])}{rng.randint(2022, 2025)}"


def _is_secret(path: str) -> bool:
    b = path.rsplit("/", 1)[-1]
    return b in SECRET_NAMES or b.startswith("passwords_backup")


class WorldState:
    def __init__(self, seed: str, user: str = "admin", on_secret=None, mode: str | None = None, llm=None):
        self.seed = str(seed)
        self.rng = _rng("world", self.seed)
        user = user if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user or "") else "admin"
        self.user = user
        self.home = f"/home/{user}"
        self.on_secret = on_secret          # callable(path) -> canary URL (registers token, logs the theft)
        self.mode = (mode or os.environ.get("WORLDGEN_MODE", "rules")).lower()
        self.llm = llm if llm is not None else (ollama_render if self.mode == "llm" else None)
        self._secret_url: dict[str, str] = {}
        self._cache: dict[str, str] = {}

        self.persona_name = self.rng.choice(sorted(PERSONAS))
        p = self.persona = PERSONAS[self.persona_name]
        self.company = self.rng.choice(COMPANY)
        self.host = f"{self.rng.choice(p['hosts'])}-{self.rng.choice(['prod', 'stg', 'int'])}-{self.rng.randint(1, 19):02d}"
        self.kernel, self.build = self.rng.choice(KERNELS)
        self.ip = f"10.{self.rng.randint(0, 9)}.{self.rng.randint(1, 9)}.{self.rng.randint(10, 240)}"
        self.db_ip = f"10.{self.ip.split('.')[1]}.{self.ip.split('.')[2]}.{self.rng.randint(10, 240)}"
        self.uptime_days = self.rng.randint(3, 160)
        self.others = self.rng.sample([n.lower() for n in FIRST], 2)
        self.dirs = self._build_dirs()

    # ---------------------------------------------------------------- structure
    def _build_dirs(self) -> dict[str, list[str]]:
        u = self.user
        d = {
            "/": ["bin", "etc", "home", "root", "tmp", "usr", "var", "opt", "srv"],
            "/home": sorted([u] + self.others),
            f"/home/{u}": ["passwords_backup.txt", "notes.txt", ".bash_history", ".ssh"],
            f"/home/{u}/.ssh": ["authorized_keys", "id_rsa"],
            "/etc": ["passwd", "hostname", "os-release", "hosts", "crontab"],
            "/tmp": [], "/opt": [], "/srv": [], "/root": [],
            "/usr": ["bin", "lib"],
            "/var": ["log", "backups"],
            "/var/log": ["auth.log", "syslog"],
            "/var/backups": ["passwd.bak"],
        }
        for o in self.others:
            d[f"/home/{o}"] = ["notes.txt"]
        if self.persona_name == "dev":
            d[f"/home/{u}"] += ["projects", ".aws"]
            d[f"/home/{u}/projects"] = ["api-gateway", "scripts"]
            d[f"/home/{u}/projects/api-gateway"] = ["README.md", "deploy.sh"]
            d[f"/home/{u}/projects/scripts"] = ["cleanup.sh"]
            d[f"/home/{u}/.aws"] = ["credentials", "config"]
        for path, names in self.persona["dirs"].items():
            cur = d.setdefault(path, [])
            for n in names:
                if n not in cur:
                    cur.append(n)
        # directories that appear in a listing but have no entries of their own still have to exist
        for p in ("/srv/share/finance", "/srv/share/hr", "/srv/share/public", "/var/www/html/uploads",
                  "/etc/apache2/sites-enabled", "/var/lib/mysql/corp_hr"):
            if any(p.rsplit("/", 1)[-1] in names for names in d.values()):
                d.setdefault(p, [])
        return d

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def is_file(self, path: str) -> bool:
        parent, _, name = path.rpartition("/")
        parent = parent or "/"
        return name in self.dirs.get(parent, []) and path not in self.dirs

    def exists(self, path: str) -> bool:
        return self.is_dir(path) or self.is_file(path) or path in ("/etc/shadow",)

    def stat(self, path: str):
        r = _rng("stat", self.seed, path)
        if path in self.dirs:
            return 4096, f"Nov {r.randint(1, 22):2d} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}"
        size = len(self._cache[path]) if path in self._cache else r.choice([220, 412, 1290, 3420, 9812, 20480, 51200])
        return size, f"{r.choice(['Oct', 'Nov', 'Sep'])} {r.randint(1, 28):2d} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}"

    # ---------------------------------------------------------------- content
    def read(self, path: str):
        """Return text, DENIED, or None (no such file). Same path -> same text for the life of the session."""
        if path == "/etc/shadow" or path.startswith("/root/"):
            return DENIED
        if not self.is_file(path):
            return None
        if path in self._cache:
            return self._cache[path]
        r = _rng("file", self.seed, path)
        base = path.rsplit("/", 1)[-1]
        if _is_secret(path):
            url = self._canary(path)
            text = self._secret_text(path, base, r, url)
        else:
            text = self._plain_text(path, base, r)
        self._cache[path] = text
        return text

    def _canary(self, path: str) -> str:
        if path not in self._secret_url:
            self._secret_url[path] = self.on_secret(path) if self.on_secret else f"http://127.0.0.1:8000/c/test-{abs(hash(path)) % 10**8}"
        return self._secret_url[path]

    def _creds(self, r, n=3):
        hosts = [("vpn", "vpn_admin"), (f"db-{self.persona_name}-01", "svc_backup"), ("jira", "svc_jira"), ("grafana", "monitor")]
        return [(f"{h}.{self.company.split()[0].lower()}.example", u, _secret(r)) for h, u in r.sample(hosts, n)]

    def _secret_text(self, path, base, r, url) -> str:
        co = self.company
        if base.startswith("passwords_backup"):
            rows = "".join(f"{h:<32}{u:<14}{p}\n" for h, u, p in self._creds(r))
            return f"# {co} - internal credential backup (CONFIDENTIAL)\n# See the internal wiki for rotation policy: {url}\n\n{rows}"
        if base == "config.php" or base == "wp-config.php":
            return ("<?php\n// Application settings. Do not commit.\n"
                    f"define('DB_HOST', '{self.db_ip}');\ndefine('DB_NAME', 'corp_{r.choice(['app', 'hr', 'shop'])}');\n"
                    f"define('DB_USER', 'svc_{r.choice(['web', 'app'])}');\ndefine('DB_PASSWORD', '{_secret(r)}');\n"
                    f"// runbook: {url}\n")
        if base in (".env", "terraform.tfvars"):
            ak = "AKIA" + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
            sk = "".join(r.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(40))
            return (f"APP_ENV=production\nDB_HOST={self.db_ip}\nDB_USER=svc_backup\nDB_PASSWORD={_secret(r)}\n"
                    f"AWS_ACCESS_KEY_ID={ak}\nAWS_SECRET_ACCESS_KEY={sk}\n# runbook: {url}\n")
        if base == "credentials" and "/.aws/" in path:
            ak = "AKIA" + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
            sk = "".join(r.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(40))
            return f"[default]\naws_access_key_id = {ak}\naws_secret_access_key = {sk}\n# rotation runbook: {url}\n"
        if base == "credentials.csv":
            rows = "".join(f"{n} {r.choice(LAST)},{n.lower()}@{co.split()[0].lower()}.example,{_secret(r)}\n" for n in r.sample(FIRST, 4))
            return f"name,email,temp_password\n{rows}# source: {url}\n"
        if base in ("db_backup.sql", "db_full.sql"):
            rows = ",".join(f"({i},'{r.choice(FIRST)} {r.choice(LAST)}','{r.choice(['HR', 'FIN', 'OPS'])}')" for i in range(1, 6))
            return (f"-- MySQL dump 10.13  Distrib 5.7.38, for Linux (x86_64)\n-- Host: {self.db_ip}   Database: corp_hr\n"
                    f"-- restore runbook: {url}\nINSERT INTO `employees` VALUES {rows};\n")
        if base == "my.cnf":
            return f"[client]\nuser=root\npassword={_secret(r)}\nhost=localhost\n# managed by ops: {url}\n"
        if base == "id_rsa":
            body = "\n".join("".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(70)) for _ in range(6))
            return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n# backup of deploy key, see {url}\n"
        if base == "config":
            return f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://{self.db_ip}:6443\n# kubeconfig runbook: {url}\n"
        return f"# {base}\n# see {url}\n"

    def _plain_text(self, path, base, r) -> str:
        u = self.user
        if base == "passwd.bak" or path == "/etc/passwd":
            return self.etc_passwd()
        if path == "/etc/hostname":
            return self.host + "\n"
        if path == "/etc/hosts":
            return f"127.0.0.1 localhost\n127.0.1.1 {self.host}\n{self.db_ip} db-{self.persona_name}-01\n"
        if path == "/etc/os-release":
            return 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
        if path == "/etc/crontab":
            return f"0 2 * * * root /opt/backup/run_backup.sh\n*/15 * * * * {u} /home/{u}/check.sh\n"
        if base == ".bash_history":
            return "".join(l + "\n" for l in self._history_lines(r))
        if base == "authorized_keys":
            return f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{''.join(r.choice('abcdef0123456789') for _ in range(24))}... {u}@{self.company.split()[0].lower()}\n"
        if base == "notes.txt":
            return f"TODO: rotate vpn creds (see passwords_backup.txt)\nTODO: patch {self.host}\nTODO: ask {r.choice(FIRST)} about the {r.choice(['backup', 'audit', 'migration'])}\n"
        if base == "auth.log":
            ip = f"10.0.{r.randint(1, 9)}.{r.randint(2, 99)}"
            return f"Nov 22 02:11:04 {self.host} sshd[912]: Accepted password for {u} from {ip} port 52114 ssh2\n"
        if base == "syslog":
            return f"Nov 22 02:00:01 {self.host} CRON[2101]: ({u}) CMD (/home/{u}/check.sh)\n"
        if base.endswith(BIN_EXT):
            return "\x1f\x8b\x08\x00" + "".join(chr(r.randint(33, 126)) for _ in range(120)) + "\n"
        text = None
        if self.llm and base.endswith((".php", ".sh", ".conf", ".md", ".py", ".yml", ".txt", ".csv", ".log")):
            text = self.llm(self.persona["desc"], path)
        if text:
            return text
        if base.endswith(".sh"):
            return f"#!/bin/bash\n# {base}\nset -e\nrsync -az ./build/ {self.host}:/var/www/html/\n"
        if base.endswith(".conf"):
            return f"# {base}\nServerName {self.host}\nDocumentRoot /var/www/html\nErrorLog /var/log/apache2/error.log\n"
        if base.endswith(".csv"):
            return "id,name,dept,amount\n" + "".join(f"{i},{r.choice(FIRST)} {r.choice(LAST)},{r.choice(['HR', 'FIN', 'OPS'])},{r.randint(1000, 90000)}\n" for i in range(1, 6))
        if base.endswith(".php"):
            return "<?php\nrequire_once 'config.php';\nsession_start();\necho '<h1>" + self.company + " Portal</h1>';\n"
        if base.endswith((".yml", ".yaml")):
            return "version: '3'\nservices:\n  app:\n    image: registry.local/app:latest\n    restart: always\n"
        if base == "robots.txt":
            return "User-agent: *\nDisallow: /uploads/\n"
        if base.endswith(".md"):
            return f"# {base[:-3]}\n\nInternal notes for {self.company}. Ask {r.choice(FIRST)} for access.\n"
        return f"# {base}\n"

    # ---------------------------------------------------------------- machine facts
    def etc_passwd(self) -> str:
        rows = ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"]
        for i, n in enumerate(self.persona["svc_users"]):
            rows.append(f"{n}:x:{33 + i * 77}:{33 + i * 77}:{n}:/nonexistent:/usr/sbin/nologin")
        for i, n in enumerate([self.user] + self.others):
            rows.append(f"{n}:x:{1000 + i}:{1000 + i}:{n.title()},,,:/home/{n}:/bin/bash")
        return "\n".join(rows) + "\n"

    def _history_lines(self, r) -> list[str]:
        pool = ["ls", "cd /var/www/html", "sudo systemctl restart apache2", f"mysql -h {self.db_ip} -u svc_backup -p",
                "df -h", "tail -f /var/log/syslog", "git pull", "vim config.php", "crontab -l", "docker ps", "exit"]
        return r.sample(pool, 6)

    def history(self) -> str:
        r = _rng("hist", self.seed)
        return "".join(f"  {i + 1}  {l}\n" for i, l in enumerate(self._history_lines(r)))

    def uname_a(self) -> str:
        return f"Linux {self.host} {self.kernel} {self.build}-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"

    def uptime(self) -> str:
        r = _rng("up", self.seed)
        return f" {time.strftime('%H:%M:%S')} up {self.uptime_days} days, {r.randint(0, 23)}:{r.randint(10, 59)},  1 user,  load average: {r.random() / 4:.2f}, {r.random() / 5:.2f}, {r.random() / 6:.2f}\n"

    def ifconfig(self) -> str:
        r = _rng("mac", self.seed)
        mac = ":".join(f"{r.randint(0, 255):02x}" for _ in range(6))
        return (f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet {self.ip}  netmask 255.255.255.0  broadcast {self.ip.rsplit('.', 1)[0]}.255\n"
                f"        ether {mac}  txqueuelen 1000  (Ethernet)\n")

    def ps(self) -> str:
        r = _rng("ps", self.seed)
        rows = ["    PID TTY      STAT   TIME COMMAND", f"    {r.randint(500, 900)} ?        Ss     0:01 /usr/sbin/sshd -D"]
        for cmd in self.persona["procs"]:
            rows.append(f"   {r.randint(901, 4000):>4} ?        Ssl    {r.randint(0, 9)}:{r.randint(10, 59)} {cmd}")
        pid = r.randint(5000, 9000)
        rows += [f"   {pid} pts/0    Ss     0:00 -bash", f"   {pid + 24} pts/0    R+     0:00 ps"]
        return "\n".join(rows) + "\n"

    def df(self) -> str:
        r = _rng("df", self.seed)
        size = r.choice([40, 80, 120, 200])
        used = int(size * r.uniform(0.3, 0.8))
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                f"/dev/sda1       {size}G   {used}G   {size - used}G  {int(used / size * 100)}% /\n"
                "tmpfs           2.0G     0  2.0G   0% /dev/shm\n")

    def free(self) -> str:
        r = _rng("free", self.seed)
        total = r.choice([3938, 7872, 15941])
        used = int(total * r.uniform(0.2, 0.6))
        return (f"              total        used        free      shared  buff/cache   available\n"
                f"Mem:          {total:>5}       {used:>5}       {total - used - 300:>5}          12         300       {total - used:>5}\n"
                "Swap:          2047           0        2047\n")

    def last(self) -> str:
        r = _rng("last", self.seed)
        rows = [f"{self.user:<9} pts/0        10.0.{r.randint(1, 9)}.{r.randint(2, 99)}   Fri Nov 22 02:11   still logged in"]
        for n in self.others:
            rows.append(f"{n:<9} pts/1        10.0.{r.randint(1, 9)}.{r.randint(2, 99)}   Thu Nov 21 {r.randint(8, 18):02d}:{r.randint(10, 59)} - 17:30  (07:12)")
        return "\n".join(rows) + "\n\nwtmp begins Sat Nov  2 06:41:12 2024\n"

    def env(self, cwd: str) -> str:
        return f"USER={self.user}\nHOME={self.home}\nSHELL=/bin/bash\nPWD={cwd}\nHOSTNAME={self.host}\n"


def ollama_render(persona_desc: str, path: str, timeout: float = 3.0):
    """Optional local-LLM file generation. Returns text or None. Never required; never used for secrets.

    The prompt contains only the persona description and a path from OUR OWN directory listing (not attacker text).
    Output is length-capped, stripped of code fences and URLs, and used purely as text.
    """
    url, model = os.environ.get("OLLAMA_URL"), os.environ.get("OLLAMA_MODEL")
    if not url or not model:
        return None
    prompt = (f"You are generating the raw contents of the file {path} on {persona_desc}. "
              "Output ONLY the file contents, 3 to 12 lines, no explanation, no markdown fences, no real secrets or URLs.")
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/generate", method="POST",
                                     data=json.dumps({"model": model, "prompt": prompt, "stream": False,
                                                      "options": {"temperature": 0.7, "num_predict": 300}}).encode(),
                                     headers={"Content-Type": "application/json"})
        text = json.loads(urllib.request.urlopen(req, timeout=timeout).read()).get("response", "")
    except Exception:
        return None
    text = re.sub(r"```\w*", "", text)
    text = "\n".join(l for l in text.splitlines() if "http" not in l.lower())[:1500].strip()
    if len(text) < 10 or re.search(r"as an ai|language model|i cannot", text, re.I):
        return None
    return text + "\n"
