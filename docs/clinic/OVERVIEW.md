# Clinic Apache/PHP cover

Status as of 2026-10-28 (public tree).

## Why clinic, not NAS

A bare Synology DSM / File Station cover on a public cloud IP is an easy tell.
Anglerfish presents a small **clinic site** on a misconfigured Ubuntu
**Apache/PHP 8.x** host that fits the IP story, while keeping the multi-service
SSH / FTP / SMTP / telnet facades.

DSM / File Station code remains in-tree for labs (`ANGLERFISH_ALLOW_DSM=1`) but
is not the default cover.

## Modules

| Module | Role |
|---|---|
| `phpapp.py` | Clinic pages, soft-fail login/upload/phpinfo, Apache errors, PHP2Shell inspect |
| `php2shell_chain.py` | FULLCHAIN / FAKE_LEAK / FAKE_PERSIST shapes — never fetches attacker URLs |
| `public_privesc/` | 3-beat public leak → weak login → escalate on `/staff/admin/term.php` |
| `vhosts.py` | Host roles: clinic / portal / billing / mail (files remaps to PHP unless DSM allowed) |

## Public → privesc beats

1. **Public leak** — staging config / backup zip under scanner-friendly paths.
2. **Weak login** — fictional staff user `mjones` (example password in
   `creds.py`; change before deploy). Portal login only accepts the weak
   staff account.
3. **Escalate** — `lfield-backup` on `/staff/admin/term.php` (needs a session
   cookie from the weak login first). After escalate, the sticky term UI
   hides user/pass and shows `escalated as lfield-backup · session sticky`.

Gotcha loot uses juicy names with Content-Type chosen from image magic bytes;
`cat`/`base64` paths still return text safely.

## Hard stops (unchanged)

- No real RCE
- No outbound fetch of attacker payloads
- Bait only — nothing real is unlocked

## Detection

CloudWatch Logs + metric filters / alarms as before. PHP2Shell and bait tags
(`php2shell-*`, `bait-weak-login`, `bait-gotcha`, …) feed High/Critical
roll-ups. Prefer plain, readable alert mail over cryptic default SNS email
templates when you wire notifications.

## Tests

```bash
for t in tests/test_*.py; do python3 "$t"; done
```

NAS-era live HTTP File Station checks are skipped under the default clinic
cover (see notes in `tests/test_sensor.py` / `tests/test_rework_deception.py`).
Enable `ANGLERFISH_ALLOW_DSM=1` with a `files.` Host for that surface in labs.
