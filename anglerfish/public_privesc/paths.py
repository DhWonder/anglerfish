"""URL map — scanner-friendly public doors, one escalate, gotcha.

Middle ground: kit-volume paths scanners hit + light human CTF breadcrumbs.
Both public leads → SAME weak login. No extra hops / no lateral.
"""

# Beat 1 — public (unauth). Prefer paths scanners already hit.
PUBLIC_ZIP = "/backups/staff-portal-backup.zip"
PUBLIC_UPLOADS_INDEX = "/uploads/tmp/"
PUBLIC_UPLOADS_BAK = "/uploads/tmp/portal-config.bak"
PUBLIC_UPLOADS_ZIP = "/uploads/tmp/staff-portal-backup.zip"
PUBLIC_BACKUPS_INDEX = "/backups/"
PUBLIC_JS = "/assets/js/portal-config.js"
# Optional flavor only (not the password itself)
PUBLIC_ROBOTS = "/robots.txt"
# Scanner breadcrumb → same JS lead (no new cred/hop)
PUBLIC_PHPMYADMIN = "/phpmyadmin/"
PUBLIC_PHPMYADMIN_ALT = frozenset({"/phpmyadmin", "/phpmyadmin/", "/phpMyAdmin/", "/phpMyAdmin"})
# Observed RT path-traversal probes (docpath=../) — breadcrumb only, never read
PMA_DOCPATH_SCRIPT = "db_details_importdocsql.php"
PMA_DOCPATH_PATHS = frozenset({
    "/phpmyadmin/db_details_importdocsql.php",
    "/phpMyAdmin/db_details_importdocsql.php",
    "/3rdparty/phpMyAdmin/db_details_importdocsql.php",
    "/3rdparty/phpmyadmin/db_details_importdocsql.php",
})
# Extra Red breadcrumbs → same JS lead (no new cred)
PUBLIC_GIT_HEAD = "/.git/HEAD"
PUBLIC_GIT_CONFIG = "/.git/config"
PUBLIC_SERVER_STATUS = frozenset({"/server-status", "/server-status/"})
PUBLIC_ACTUATOR_ENV = frozenset({"/actuator/env", "/actuator/env/"})
PUBLIC_WP_LOGIN = frozenset({"/wp-login.php", "/wordpress/wp-login.php"})

# Beat 2 — weak login (same cred from either public door)
LOGIN_PATHS = frozenset({
    "/portal/login.php",
    "/portal/",
    "/portal",
    "/staff/",
    "/staff",
    "/staff/login.php",
    "/login.php",
})
DASHBOARD = "/staff/dashboard.php"

# Beat 3 — ONE escalate (post-auth only)
HANDOFF = "/staff/docs/it-handoff.txt"
DEPLOY_ID = "/staff/.deploy_id"
TERM = "/staff/admin/term.php"  # gated fake shell (backup cred)

# Gotcha loot (post-escalate shell or GET)
LOOT_PREFIX = "/staff/loot/"
GOTCHA_NAMES = frozenset({
    "patient_roster_q3.xlsx",
    "clinic_billing_export.sql",
    "staff_ssh_id_rsa",
    "vpn_shared_secret.conf",
    "hr_salaries_2024.csv",
    "aws_keys_staging.json",
    "passwords_old.txt",
})
