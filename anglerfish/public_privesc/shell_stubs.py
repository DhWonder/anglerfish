"""Allowlisted fake-shell stubs only. No exec, no outbound, no include."""

from __future__ import annotations

import re
from typing import Dict, Tuple

from .creds import BACKUP_USER, CLINIC_HOSTNAME

# Hard stop: never run these — pattern used only to claim "connected" with no socket
_REV = re.compile(
    r"(?i)(bash\s+-i|/dev/tcp/|nc\s+-[el]|ncat|python[23]?\s+-c.*socket|"
    r"socat|mkfifo|0<&196)"
)

ALLOWED_CMDS = frozenset({
    "whoami", "id", "uname", "uname -a", "uname -m", "pwd", "hostname",
    "ls", "ls -la", "ls -l", "ls /", "ls loot", "ls ./loot", "ls loot/",
    "cat patient_roster_q3.xlsx", "cat clinic_billing_export.sql",
    "cat staff_ssh_id_rsa", "cat vpn_shared_secret.conf",
    "cat hr_salaries_2024.csv", "cat aws_keys_staging.json",
    "cat passwords_old.txt", "cat /etc/hostname", "cat /etc/passwd",
    "base64 patient_roster_q3.xlsx", "base64 clinic_billing_export.sql",
    "base64 staff_ssh_id_rsa",
    "ps", "ps aux", "help",
})

LOOT_LISTING = (
    "patient_roster_q3.xlsx\n"
    "clinic_billing_export.sql\n"
    "staff_ssh_id_rsa\n"
    "vpn_shared_secret.conf\n"
    "hr_salaries_2024.csv\n"
    "aws_keys_staging.json\n"
    "passwords_old.txt\n"
)

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "lfield-backup:x:1002:1002:Backup:/home/lfield-backup:/bin/bash\n"
    "clinic:x:1001:1001:Clinic App:/home/clinic:/bin/bash\n"
)


def run_stub(cmd: str, escalated: bool = False) -> Tuple[str, Dict]:
    """Return (output, extras). Never executes anything real."""
    extras: Dict = {"tag": "bait-fake-shell", "outbound": False, "exec": False}
    raw = (cmd or "").strip()
    c = " ".join(raw.lower().split())

    if not c:
        who = BACKUP_USER if escalated else "www-data"
        uid = "1002(%s)" % BACKUP_USER if escalated else "33(www-data)"
        return (
            "uid=%s gid=%s groups=%s\n%s\nPHP 8.4.26 (cli)\n"
            % (uid, uid, uid, CLINIC_HOSTNAME)
        ), extras

    if _REV.search(raw) or _REV.search(c):
        extras["revshell_claimed"] = True
        return "connected\n", extras

    if c.startswith("curl") or c.startswith("wget"):
        extras["fetch_url_logged_only"] = True
        return "OK\n", extras  # never fetch

    if c in ("whoami",):
        return (BACKUP_USER if escalated else "www-data") + "\n", extras
    if c in ("id",):
        if escalated:
            return (
                "uid=1002(%s) gid=1002(%s) groups=1002(%s)\n"
                % (BACKUP_USER, BACKUP_USER, BACKUP_USER)
            ), extras
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", extras
    if c in ("uname", "uname -a"):
        return (
            "Linux %s 6.8.0-1017-aws #19-Ubuntu SMP "
            "x86_64 x86_64 x86_64 GNU/Linux\n" % CLINIC_HOSTNAME
        ), extras
    if c == "uname -m":
        return "x86_64\n", extras
    if c == "pwd":
        return "/var/www/html/staff/loot\n" if escalated else "/var/www/html\n", extras
    if c in ("hostname", "cat /etc/hostname"):
        return CLINIC_HOSTNAME + "\n", extras
    if c in ("cat /etc/passwd",):
        return _PASSWD, extras
    if c in ("ps", "ps aux"):
        return (
            "USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 167890  9876 ?        Ss   08:01   0:02 /sbin/init\n"
            "www-data  1204  0.0  0.5 362880 24832 ?        S    08:01   0:03 apache2 -k start\n"
            "%s  1888  0.0  0.2  18944  5120 pts/0    S+   12:10   0:00 -bash\n"
            % (BACKUP_USER if escalated else "www-data")
        ), extras

    if c in ("ls", "ls -l", "ls -la", "ls loot", "ls ./loot", "ls loot/"):
        return LOOT_LISTING, extras
    if c == "ls /":
        return "bin\nboot\netc\nhome\nvar\nwww\n", extras

    if c.startswith("base64 "):
        # Handler encodes bait bytes as base64 text (not image/*).
        name = c.split(None, 1)[1].strip().lstrip("./")
        extras["loot_request"] = name
        extras["loot_as_base64"] = True
        return "", extras

    if c.startswith("cat "):
        # Handler serves real bait bytes for known loot names; stub only names them.
        name = c.split(None, 1)[1].strip().lstrip("./")
        extras["loot_request"] = name
        return "", extras  # empty → handler streams file

    if c == "help":
        return (
            "commands: whoami id uname ls cat <loot> base64 <loot> "
            "pwd hostname ps\n"
        ), extras

    tok = (raw.split() or ["?"])[0][:40]
    return "sh: 1: %s: not found\n" % tok, extras
