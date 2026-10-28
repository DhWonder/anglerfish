# Deploying Anglerfish

For the AWS path see [`deploy/aws/README.md`](deploy/aws/README.md).
Clinic cover notes: [`docs/clinic/OVERVIEW.md`](docs/clinic/OVERVIEW.md).

## Local / lab

1. `cp config/persona.example.yaml config/persona.yaml` and edit.
2. Change example public→privesc passwords in
   `anglerfish/public_privesc/creds.py` (and matching bait store files) so
   they do not match any live sensor.
3. High ports: `python3 anglerfish_cli.py sensor --bind 127.0.0.1 --ports 2222 8080 8443 --persona config/persona.yaml`
4. Privileged (real 22/80/443): run under systemd as the `anglerfish` user; see the CloudFormation user-data for a working unit file.
5. Optional clinic lure flags (lab): `ANGLERFISH_PHP2SHELL_FULLCHAIN=1`,
   `ANGLERFISH_PHP2SHELL_FAKE_LEAK=1`, `ANGLERFISH_PHP2SHELL_FAKE_PERSIST=1`.
6. Optional console: `python3 anglerfish_cli.py console --port 8770 --token <same as sensor>`

## Non-negotiables

- Persona file is **not** the example before any public bind.
- Admin SSH (non-22) locked to your `/32`.
- Instance role Deny outside `/anglerfish/*`; IMDSv2 hop limit 1.
- No real credentials anywhere on the box.
- No real RCE; attacker payload URLs are logged only, never fetched.

## Real domain + Let's Encrypt

Pointing a real domain at the sensor (A records for the apex and `www`, DNS
only, no proxy) draws in more human visitors than a bare IP. Use an Elastic IP
first so a stop/start doesn't change the address under your DNS. Set
`identity.domain` in your persona to that domain before the first run. If the
persona is already minted, edit `domain`/`fqdn` in `state/persona.json` and
restart.

Port 80 is REDIRECTed to the sensor, so use certbot `--standalone` and let the
renewal hooks free :80 while the challenge runs. Below, `example.net` and
`you@example.net` are placeholders:

```bash
D=example.net
cat > /etc/letsencrypt/renewal-hooks/pre/anglerfish.sh <<'H'
#!/bin/sh
iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080 || true
H
cat > /etc/letsencrypt/renewal-hooks/post/anglerfish.sh <<'H'
#!/bin/sh
iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080 2>/dev/null \
  || iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
H
cat > /etc/letsencrypt/renewal-hooks/deploy/anglerfish.sh <<H
#!/bin/sh
L=/etc/letsencrypt/live/$D
install -o anglerfish -g anglerfish -m 644 \$L/fullchain.pem /opt/anglerfish/state/tls-cert.pem
install -o anglerfish -g anglerfish -m 600 \$L/privkey.pem   /opt/anglerfish/state/tls-key.pem
systemctl restart anglerfish-sensor.service
H
chmod +x /etc/letsencrypt/renewal-hooks/*/anglerfish.sh

# The hooks also run on the first issue.
certbot certonly --standalone -d $D -d www.$D -m you@example.net --agree-tos -n \
  --pre-hook  /etc/letsencrypt/renewal-hooks/pre/anglerfish.sh \
  --post-hook /etc/letsencrypt/renewal-hooks/post/anglerfish.sh \
  --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/anglerfish.sh
```

Some distro packages don't install a renewal timer, so check
`systemctl list-timers | grep -i cert`. If none is listed, add one:

```bash
cat > /etc/systemd/system/anglerfish-certbot-renew.service <<'U'
[Unit]
Description=Renew Let's Encrypt cert for Anglerfish
[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew -q --no-random-sleep-on-renew
U
cat > /etc/systemd/system/anglerfish-certbot-renew.timer <<'U'
[Unit]
Description=Twice-daily Let's Encrypt renewal check
[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
U
systemctl daemon-reload && systemctl enable --now anglerfish-certbot-renew.timer
certbot renew --dry-run
```

**HTTP to HTTPS:** when a TLS cert is loaded, plain-HTTP requests whose `Host`
is the persona domain (or a subdomain of it) get a `301` to
`https://<host><path>`, logged as an `http` event tagged `https-redirect`.
The bare IP and unknown Hosts stay on plain HTTP, so scanner logging doesn't
change. The ACME challenge never reaches the sensor because the pre-hook
removes the :80 REDIRECT first. To turn the redirect off, pass
`--no-https-redirect` or set `ANGLERFISH_HTTPS_REDIRECT=0`.
