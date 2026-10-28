"""Planted honeypot credentials only — unlock nothing real on any host.

Public-tree passwords are EXAMPLE placeholders. Change them (or mint at
install) before any network exposure so clones cannot fingerprint a live
sensor. Usernames are fictional clinic staff.
"""

# Beat 1 / 2 — weak staff (public leak)
WEAK_USER = "mjones"
WEAK_PASS = "StagingWinter.example"

# Beat 3 — escalate (post-auth plant only)
BACKUP_USER = "lfield-backup"
BACKUP_PASS = "BackupRotate.example"

CLINIC_HOSTNAME = "files01"
COMPANY = "Example Clinic"
