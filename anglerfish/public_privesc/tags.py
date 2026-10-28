"""Blue event / path tags for the public→privesc chain."""

BAIT_PUBLIC_LEAK = "bait-public-leak"
BAIT_PUBLIC_LEAK_JS = "bait-public-leak-js"
BAIT_WEAK_LOGIN = "bait-weak-login"
BAIT_PRIVESC = "bait-privesc"
BAIT_GOTCHA = "bait-gotcha"
BAIT_SCANNER_BREADCRUMB = "bait-scanner-breadcrumb"
BAIT_PMA_DOCPATH = "bait-pma-docpath"

# Parallel kit path — do not modify php2shell here
PHP2SHELL_PARALLEL = "php2shell-parallel-untouched"

ALL_TAGS = (
    BAIT_PUBLIC_LEAK,
    BAIT_PUBLIC_LEAK_JS,
    BAIT_WEAK_LOGIN,
    BAIT_PRIVESC,
    BAIT_GOTCHA,
    BAIT_SCANNER_BREADCRUMB,
    BAIT_PMA_DOCPATH,
)
