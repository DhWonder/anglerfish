# Short demo

```bash
cp config/persona.example.yaml config/persona.yaml
python3 anglerfish_cli.py sensor --bind 127.0.0.1 --ports 2222 8080 8443 \
  --persona config/persona.yaml --state-dir /tmp/anglerfish-demo
```

Then:

```bash
# SSH banner + HASSH-able KEXINIT
nc 127.0.0.1 2222

# Clinic Apache/PHP cover (not a NAS login)
curl -s http://127.0.0.1:8080/ | head

# Soft-fail staff portal
curl -s http://127.0.0.1:8080/portal/login.php | head

# Public→privesc beat 1 — leaked staging config (example passwords only)
curl -s http://127.0.0.1:8080/store/portal-config.js | head
```

Planted shell/File Station passwords were printed when the sensor minted its
state. For the 3-beat staff-portal chain, use the **example** weak/backup
credentials from `anglerfish/public_privesc/creds.py` (change them before any
public bind). After escalate on `/staff/admin/term.php`, the sticky term UI
hides user/pass and shows `escalated as lfield-backup · session sticky`.
