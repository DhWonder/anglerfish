"""
Per-Host decoy content for a small clinic + billing office persona.

Roles:
  clinic  — apex / www static office site + robots/sitemap + one outbound canary
  files   — legacy Synology label; Sunday cover remaps to PHP staff portal unless ALLOW_DSM
  portal  — staff portal soft-fail login
  billing — billing portal maintenance + soft-fail login
  mail    — webmail soft-fail login

No patient PHI. Soft-fail only on non-files hosts (never mint File Station sessions).
"""

from __future__ import print_function

# "clinic" = boring homepage on apex/www; "dsm" = leave apex/www on Synology.
VHOST_APEX_MODE = "clinic"

# Canary URL undecided: leave empty -> footer "IT vendor notes" link is omitted.
CANARY_URL = ""

# Left-most label -> role. Apex/www handled separately.
_LABEL_ROLE = {
    "files": "files",
    "srv-files": "files",
    "portal": "portal",
    "billing": "billing",
    "mail": "mail",
    "www": "clinic",
}

# Left-most labels the sensor's _known_host accepts under the persona domain.
SERVED_LABELS = frozenset(_LABEL_ROLE)

# Mundane office details (fictional; 555-01xx). Persona has no city/state on disk.
_OFFICE = {
    "town": "Berryville, Virginia",
    "phone": "(555) 010-0140",
    "fax": "(555) 010-0142",
    "billing_phone": "(555) 010-0141",
}


def _host_label(host_header, domain=""):
    host = (host_header or "").split(":")[0].strip().lower()
    if not host:
        return "", host
    domain = (domain or "").lower().lstrip(".")
    if domain and (host == domain or host == "www." + domain):
        return "www" if host.startswith("www.") else "@", host
    if domain and host.endswith("." + domain):
        label = host[: -(len(domain) + 1)]
        # only leftmost of multi-label (e.g. a.b.domain -> a.b); we use single labels
        return label.split(".", 1)[0], host
    if "." not in host:
        return host, host
    return host.split(".", 1)[0], host


def role_for_host(host_header, domain="", fqdn="", hostname=""):
    """Return role string: clinic|files|portal|billing|mail|unknown."""
    label, host = _host_label(host_header, domain)
    domain = (domain or "").lower()
    fqdn = (fqdn or "").lower()
    hostname = (hostname or "").lower()

    if not host:
        # Sunday overhaul: bare / missing Host → clinic PHP cover (not NAS).
        return "clinic"

    if host == fqdn or host == hostname or (hostname and host.startswith(hostname + ".")):
        return "files"  # retired to php staff portal by sensor unless ALLOW_DSM

    # Bare IP / IPv6 literal / dotless LAN name → clinic PHP (fits AWS IP story).
    raw = (host_header or "").strip().lower()
    if raw.startswith("[") or all(c in "0123456789." for c in host):
        return "clinic"
    if "." not in host and host not in _LABEL_ROLE:
        return "clinic"

    if label in ("@", "www") or host == domain or host == "www." + domain:
        return "clinic" if VHOST_APEX_MODE == "clinic" else "files"

    if label in _LABEL_ROLE:
        return _LABEL_ROLE[label]

    # Any other *.domain still "known" to _known_host — serve clinic soft page
    # rather than Synology (avoids DSM on random labels).
    if domain and host.endswith("." + domain):
        return "clinic"
    return "unknown"


def handle(role, path, method="GET", body=b"", world=None, failed=False):
    """Return (body_str_or_bytes, content_type, status, set_cookie, extra_headers)
    or None to fall through to the Synology / existing _page logic.
    """
    world = world or {}
    clean = (path or "/").split("?", 1)[0]
    company = world.get("company") or "Example Clinic"
    domain = world.get("domain") or "example.net"

    # Shared discovery files
    if clean == "/robots.txt":
        return (_robots_txt(domain, role), "text/plain; charset=utf-8", 200, "", [])
    if clean == "/sitemap.xml" and role in ("clinic",):
        return (_sitemap_xml(domain), "application/xml; charset=utf-8", 200, "", [])
    if clean == "/favicon.ico":
        return (b"", "image/x-icon", 204, "", [])

    if role == "files":
        return None  # existing DSM path

    if role == "clinic":
        return _clinic_page(clean, company, domain)

    if role == "portal":
        return _portal_page(clean, method, body, company, failed=failed)

    if role == "billing":
        return _billing_page(clean, method, body, company, failed=failed)

    if role == "mail":
        return _mail_page(clean, method, body, company, domain, failed=failed)

    return None


def soft_fail_login(path, method, body):
    """True when this request is a login POST we should log then soft-fail."""
    if method != "POST":
        return False
    clean = (path or "/").split("?", 1)[0]
    return clean in ("/", "/login", "/index.php", "/?_task=login")


# ----- page builders ---------------------------------------------------------

def _robots_txt(domain, role):
    if role == "clinic":
        return ("User-agent: *\nDisallow: /admin/\nDisallow: /login.php\n"
                "Disallow: /upload.php\nDisallow: /.env\n\n"
                "Sitemap: https://%s/sitemap.xml\n" % domain)
    if role in ("portal", "billing", "mail"):
        return "User-agent: *\nDisallow: /\n"
    lines = [
        "User-agent: *",
        "Disallow: /admin",
        "Disallow: /login",
        "Disallow: /webman",
        "Disallow: /webapi",
        "Allow: /",
        "",
    ]
    if role == "clinic":
        lines.append("Sitemap: https://%s/sitemap.xml" % domain)
        lines.append("")
    return "\n".join(lines)


def _sitemap_xml(domain):
    # Same-host public clinic pages only (sitemap protocol disallows cross-host
    # URLs; listing files./portal. here would be a tell). Subdomains are left
    # for attackers to find via CT logs / DNS recon.
    urls = [
        "https://%s/" % domain,
        "https://%s/about.html" % domain,
        "https://%s/services.html" % domain,
        "https://%s/providers.html" % domain,
        "https://%s/patients.html" % domain,
        "https://%s/billing.html" % domain,
        "https://%s/contact.html" % domain,
        "https://%s/hours.html" % domain,
        "https://%s/privacy.html" % domain,
    ]
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for u in urls:
        parts.append("  <url><loc>%s</loc></url>" % u)
    parts.append("</urlset>")
    parts.append("")
    return "\n".join(parts)


def _canary_enabled():
    u = (CANARY_URL or "").strip()
    return bool(u) and "REPLACE_ME" not in u and u.startswith(("http://", "https://"))


def _canary_link():
    if not _canary_enabled():
        return ""
    return ('IT vendor notes: <a href="%s" rel="noopener">knowledge base</a>\n'
            '&nbsp;&middot;&nbsp; ' % CANARY_URL)


def _shell(title, body_html, company="Example Clinic", domain="example.net",
           active="", updated="Sept 12, 2026"):
    # Use replace() so CSS width:100% does not break %-formatting.
    # Slightly dated practice-website look: Arial, solid navy bar, no gradients.
    o = _OFFICE
    nav = [
        ("/", "Home", "home"),
        ("/about.html", "About", "about"),
        ("/services.html", "Services", "services"),
        ("/providers.html", "Providers", "providers"),
        ("/patients.html", "Patients", "patients"),
        ("/billing.html", "Insurance &amp; Billing", "billing"),
        ("/contact.html", "Contact", "contact"),
    ]
    nav_html = []
    for href, label, key in nav:
        cls = ' class="on"' if key == active else ""
        nav_html.append('<a href="%s"%s>%s</a>' % (href, cls, label))
    nav_str = "\n".join(nav_html)

    tpl = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="__COMPANY__ - family medicine and outpatient care in Berryville, Virginia">
<title>__TITLE__</title>
<style>
body{margin:0;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.45;color:#222;background:#fff}
a{color:#0a4a6e}
a:visited{color:#0a4a6e}
.topbar{background:#f0f0f0;border-bottom:1px solid #ccc;padding:6px 16px;font-size:13px;color:#333}
.topbar span{margin-right:18px}
.brand{background:#0a4a6e;color:#fff;padding:14px 16px}
.brand h1{margin:0;font-size:22px;font-weight:bold;letter-spacing:0.02em}
.brand .tag{font-size:13px;margin-top:3px;color:#d0e4f0}
nav{background:#135a82;padding:0 8px;border-bottom:3px solid #0a3a55}
nav a{display:inline-block;color:#fff;text-decoration:none;padding:10px 12px;font-size:13px}
nav a:hover,nav a.on{background:#0a3a55}
.wrap{max-width:860px;margin:0 auto;padding:18px 16px 32px}
h2{font-size:20px;margin:0 0 12px;color:#0a4a6e;border-bottom:1px solid #ccd;padding-bottom:6px}
h3{font-size:16px;margin:18px 0 8px;color:#333}
p{margin:0 0 12px}
ul{margin:0 0 12px 20px;padding:0}
li{margin:0 0 6px}
table.hours{border-collapse:collapse;width:100%;max-width:420px;margin:8px 0 16px}
table.hours th,table.hours td{border:1px solid #bbb;padding:6px 10px;text-align:left;font-size:14px}
table.hours th{background:#e8eef2;width:40%}
.notice{background:#fff8e0;border:1px solid #e0d090;padding:10px 12px;margin:14px 0;font-size:14px}
.box{border:1px solid #ccc;padding:12px 14px;margin:14px 0;background:#fafafa}
.muted{color:#555;font-size:13px}
.providers{margin:0;padding:0;list-style:none}
.providers li{border:1px solid #ccc;padding:10px 12px;margin:0 0 10px;background:#fafafa}
.foot{background:#f0f0f0;border-top:1px solid #ccc;padding:16px;font-size:12px;color:#444;margin-top:28px}
.foot .cols{max-width:860px;margin:0 auto}
.foot a{color:#0a4a6e}
.lang{font-size:11px;color:#666;margin-top:10px;line-height:1.4}
</style>
</head>
<body>
<div class="topbar">
<span>Main: __PHONE__</span>
<span>Fax: __FAX__</span>
<span>Mon&ndash;Thu 8:00&ndash;5:00 &middot; Fri 8:00&ndash;3:00 &middot; closed for lunch 12:00&ndash;1:00</span>
</div>
<div class="brand">
<h1>__COMPANY__</h1>
<div class="tag">Family Medicine &middot; Berryville, Virginia</div>
</div>
<nav>
__NAV__
</nav>
<div class="wrap">
__BODY__
</div>
<div class="foot">
<div class="cols">
<p><strong>__COMPANY__</strong><br>
__TOWN__<br>
Phone __PHONE__ &nbsp;|&nbsp; Fax __FAX__ &nbsp;|&nbsp; Billing __BILLING__</p>
<p><a href="/contact.html">Contact us</a>
&nbsp;&middot;&nbsp; <a href="/privacy.html">Notice of Privacy Practices</a>
&nbsp;&middot;&nbsp; <a href="https://portal.__DOMAIN__/">Staff sign-in</a></p>
<p class="muted">If this is a medical emergency, call 911. Do not use email for urgent medical questions.</p>
<p class="lang">ATTENTION: If you speak a language other than English, language assistance services are available to you free of charge. Call __PHONE__.<br>
ATENCI&Oacute;N: si habla espa&ntilde;ol, tiene a su disposici&oacute;n servicios gratuitos de asistencia ling&uuml;&iacute;stica. Llame al __PHONE__.</p>
<p class="muted">__CANARYLINK__&copy; 2019&ndash;2026 __COMPANY__
&nbsp;&middot;&nbsp; Page updated __UPDATED__</p>
</div>
</div>
</body>
</html>
"""
    return (
        tpl.replace("__TITLE__", title)
        .replace("__COMPANY__", company)
        .replace("__DOMAIN__", domain)
        .replace("__BODY__", body_html)
        .replace("__CANARYLINK__", _canary_link())
        .replace("__NAV__", nav_str)
        .replace("__PHONE__", o["phone"])
        .replace("__FAX__", o["fax"])
        .replace("__BILLING__", o["billing_phone"])
        .replace("__TOWN__", o["town"])
        .replace("__UPDATED__", updated)
    )


def _clinic_page(clean, company, domain):
    # Normalize a few aliases so older bookmarks / sitemap entries still work.
    aliases = {
        "/index.html": "/",
        "/index.htm": "/",
        "/about": "/about.html",
        "/services": "/services.html",
        "/providers": "/providers.html",
        "/our-team": "/providers.html",
        "/our-team.html": "/providers.html",
        "/patients": "/patients.html",
        "/new-patients": "/patients.html",
        "/new-patients.html": "/patients.html",
        "/billing-insurance": "/billing.html",
        "/billing-insurance.html": "/billing.html",
        "/insurance.html": "/billing.html",
        "/contact": "/contact.html",
        "/hours": "/hours.html",
        "/privacy": "/privacy.html",
        "/privacy-practices": "/privacy.html",
        "/privacy-practices.html": "/privacy.html",
    }
    clean = aliases.get(clean, clean)

    # Per-page "Page updated" dates (staggered; none after Oct 20, 2026).
    updated = {
        "/": "Oct 6, 2026",
        "/about.html": "Feb 17, 2025",
        "/services.html": "Aug 4, 2026",
        "/providers.html": "Jan 9, 2026",
        "/patients.html": "Jun 23, 2026",
        "/billing.html": "Sept 12, 2026",
        "/contact.html": "Apr 28, 2026",
        "/hours.html": "Nov 24, 2025",
        "/privacy.html": "Mar 18, 2025",
    }
    pages = {
        "/": (_home, "home", "%s | Family Medicine" % company),
        "/about.html": (_about, "about", "About Us | %s" % company),
        "/services.html": (_services, "services", "Services | %s" % company),
        "/providers.html": (_providers, "providers", "Our Providers | %s" % company),
        "/patients.html": (_patients, "patients", "Patient Information | %s" % company),
        "/billing.html": (_billing_info, "billing", "Insurance & Billing | %s" % company),
        "/contact.html": (_contact, "contact", "Contact | %s" % company),
        "/hours.html": (_hours, "contact", "Office Hours | %s" % company),
        "/privacy.html": (_privacy, "home", "Notice of Privacy Practices | %s" % company),
    }

    if clean not in pages:
        return (
            _not_found(company, domain),
            "text/html; charset=utf-8",
            404,
            "",
            [],
        )

    builder, active, title = pages[clean]
    body = builder(company, domain)
    html = _shell(title, body, company, domain, active=active,
                  updated=updated.get(clean, "Sept 12, 2026"))
    return html, "text/html; charset=utf-8", 200, "", []


def _home(company, domain):
    o = _OFFICE
    return (
        "<h2>Welcome</h2>\n"
        "<p>%s is a small, independently owned family medicine practice. "
        "We see adults and older kids for day-to-day care, chronic conditions, "
        "and yearly checkups. Same building has our billing office, which helps "
        "when you have a question about a statement.</p>\n"
        "<div class=\"notice\"><strong>Flu shots:</strong> Walk-in flu shots "
        "are available most weekday mornings while supply lasts. "
        "Bring your insurance card. No appointment needed for the shot alone, "
        "but please check in at the front desk first.</div>\n"
        "<div class=\"box\">\n"
        "<h3 style=\"margin-top:0\">Office hours</h3>\n"
        "<table class=\"hours\">\n"
        "<tr><th>Monday &ndash; Thursday</th><td>8:00 AM &ndash; 5:00 PM "
        "(closed 12:00&ndash;1:00 for lunch)</td></tr>\n"
        "<tr><th>Friday</th><td>8:00 AM &ndash; 3:00 PM "
        "(closed 12:00&ndash;1:00)</td></tr>\n"
        "<tr><th>Saturday / Sunday</th><td>Closed</td></tr>\n"
        "</table>\n"
        "<p class=\"muted\">We are closed New Year&rsquo;s Day, Memorial Day, "
        "July 4, Labor Day, Thanksgiving, and Christmas. "
        "The office usually closes at noon the day before Thanksgiving.</p>\n"
        "</div>\n"
        "<p>To make or change an appointment, call the front desk at %s. "
        "We do not take walk-ins for new patients.</p>\n"
        "<p class=\"muted\">Parking is behind the building; "
        "use the side entrance marked Suite 200. The elevator is slow after 8:30 &mdash; "
        "plan a few extra minutes if you have a morning appointment.</p>\n"
        % (company, o["phone"])
    )


def _about(company, domain):
    return (
        "<h2>About the practice</h2>\n"
        "<p>%s opened in 2014. We are not part of a hospital system. "
        "Most of our patients live in Berryville and around Clarke County; "
        "a few drive in from farther out because they have been with us a long time.</p>\n"
        "<p>Dr. Whitacre started the practice after working in a larger group "
        "and wanting a smaller panel. Dr. Boudreau joined in 2018. "
        "Nora Kellerman, our nurse practitioner, came on in 2021 and sees "
        "a mix of acute visits and follow-ups.</p>\n"
        "<p>We still use paper forms for some new-patient paperwork. "
        "Sorry about that &mdash; we are mid-way through a records upgrade "
        "and would rather get the chart right than rush it.</p>\n"
        "<h3>What we are not</h3>\n"
        "<p>We are not an urgent care and we do not have X-ray or a full lab "
        "on site. Basic labs are drawn here on weekday mornings; "
        "imaging is referred out. We also are <strong>not accepting new "
        "Medicare patients at this time</strong>. Current Medicare patients "
        "of the practice are unaffected.</p>\n"
        % company
    )


def _services(company, domain):
    return (
        "<h2>Services</h2>\n"
        "<p>Most visits are scheduled. Same-day sick slots open in the morning "
        "when we have them; call early if you need one.</p>\n"
        "<ul>\n"
        "<li>Adult and adolescent primary care</li>\n"
        "<li>Annual physicals and school/sports forms (48 hours notice helps)</li>\n"
        "<li>Blood pressure, diabetes, and cholesterol follow-up</li>\n"
        "<li>Asthma and allergy management (no allergy shots in-office)</li>\n"
        "<li>Minor skin procedures: biopsies, laceration repair, toenail care</li>\n"
        "<li>Vaccines, including seasonal flu</li>\n"
        "<li>DOT physicals &mdash; ask when you book; not every day has a slot</li>\n"
        "<li>Telehealth only when the provider agrees it fits the visit</li>\n"
        "</ul>\n"
        "<p class=\"muted\">We do not offer obstetrics, pediatrics under age 10, "
        "or controlled-substance contracts for new patients transferring in "
        "solely for pain management.</p>\n"
    )


def _providers(company, domain):
    # Names are fictional composites; quick web check found no matching
    # family-medicine providers under these full names.
    return (
        "<h2>Our providers</h2>\n"
        "<ul class=\"providers\">\n"
        "<li><strong>Ellen R. Whitacre, MD</strong><br>\n"
        "Family Medicine &nbsp;&middot;&nbsp; Board certified<br>\n"
        "<span class=\"muted\">In clinic Mon, Tue, Thu. Admin half-day Wed.</span></li>\n"
        "<li><strong>James K. Boudreau, DO</strong><br>\n"
        "Family Medicine &nbsp;&middot;&nbsp; Board certified<br>\n"
        "<span class=\"muted\">In clinic Mon&ndash;Wed and Fri mornings.</span></li>\n"
        "<li><strong>Nora P. Kellerman, FNP-C</strong><br>\n"
        "Family Nurse Practitioner<br>\n"
        "<span class=\"muted\">Sees acute visits and follow-ups; "
        "works with both physicians.</span></li>\n"
        "</ul>\n"
        "<p>When you book, ask for a specific provider if you have a preference. "
        "We try, but sick visits sometimes go to whoever is open that day.</p>\n"
    )


def _patients(company, domain):
    o = _OFFICE
    return (
        "<h2>Patient information</h2>\n"
        "<h3>New patients</h3>\n"
        "<p>Call %s to ask about openings. We are accepting some new patients "
        "age 10 and up. Bring a photo ID, your insurance card, and a list of "
        "medications (bottle labels are fine). If you have records from another "
        "office, have them faxed to %s before your visit when you can.</p>\n"
        "<p>New-patient packets are at the front desk. We can also email a PDF "
        "if you ask &mdash; we are not set up for a full online portal signup yet. "
        "Please fill forms out before you arrive when possible; the first visit "
        "runs long.</p>\n"
        "<h3>Existing patients</h3>\n"
        "<p>For refills, call during office hours and leave the medication name "
        "and pharmacy. Refills are not handled by the on-call provider after hours. "
        "Lab results are usually back in a few days; someone from the office will "
        "call if anything needs follow-up. Normal results are not always called "
        "out unless you ask.</p>\n"
        "<h3>After hours</h3>\n"
        "<p>If you have a medical emergency, call 911.</p>\n"
        "<p>For urgent problems after the office is closed, call the main number "
        "and follow the prompts for the on-call service. Routine questions and "
        "refills wait until the next business day.</p>\n"
        "<h3>Forms</h3>\n"
        "<p>School, camp, and work forms need 3 business days when we can. "
        "Same-week requests sometimes work if the chart is simple; "
        "there may be a small form fee posted at the desk.</p>\n"
        % (o["phone"], o["fax"])
    )


def _billing_info(company, domain):
    o = _OFFICE
    return (
        "<h2>Insurance and billing</h2>\n"
        "<p>We file claims for most commercial plans we contract with. "
        "Copays are due at the visit. If you are not sure we are in network, "
        "call the number on your card &mdash; plan directories change more often "
        "than we would like.</p>\n"
        "<h3>Plans we commonly see</h3>\n"
        "<ul>\n"
        "<li>Anthem / Blue Cross Blue Shield (PPO and some HMO products)</li>\n"
        "<li>Aetna</li>\n"
        "<li>Cigna</li>\n"
        "<li>UnitedHealthcare (not all products &mdash; please verify)</li>\n"
        "<li>Medicare (established patients only; see note below)</li>\n"
        "<li>Self-pay</li>\n"
        "</ul>\n"
        "<div class=\"notice\">We are <strong>not accepting new Medicare "
        "patients</strong> right now. If you already see us under Medicare, "
        "nothing changes for you.</div>\n"
        "<p>We are out of network with some Medicaid managed-care plans. "
        "Ask before your visit if that applies to you.</p>\n"
        "<h3>Paying a bill</h3>\n"
        "<p>Statements come from our billing office in the same building. "
        "You can pay by card over the phone at %s (billing line), or by mail "
        "with the stub. Online pay is through the statement instructions when "
        "those are printed; if a link on a paper bill looks wrong, call us "
        "instead of clicking it.</p>\n"
        "<p class=\"muted\">Staff with billing-queue access use the internal "
        "billing workspace (separate from this website). Patients should use "
        "the phone number above.</p>\n"
        "<p>Questions about a claim: have your statement date and the "
        "patient date of birth ready when you call.</p>\n"
        % o["billing_phone"]
    )


CONTACT_PATHS = ("/contact.html", "/contact")


def _contact_form_html():
    return (
        "<h3>Send us a message</h3>\n"
        "<p class=\"muted\">For appointments, refills, and billing questions. "
        "Please do not include insurance numbers, dates of birth, or medical "
        "details. Someone from the front desk reads these during office hours.</p>\n"
        "<form method=\"post\" action=\"/contact.html\" class=\"box\">\n"
        "<p><label>Name<br><input type=\"text\" name=\"name\" size=\"40\" required></label></p>\n"
        "<p><label>Email<br><input type=\"email\" name=\"email\" size=\"40\" required></label></p>\n"
        "<p><label>Message<br><textarea name=\"message\" rows=\"6\" cols=\"50\" required></textarea></label></p>\n"
        "<p><input type=\"submit\" value=\"Send\"></p>\n"
        "</form>\n"
    )


def _contact(company, domain):
    o = _OFFICE
    return (
        "<h2>Contact</h2>\n"
        "<div class=\"box\">\n"
        "<p><strong>%s</strong><br>\n"
        "%s</p>\n"
        "<p>Main desk: %s<br>\n"
        "Billing office: %s<br>\n"
        "Fax: %s</p>\n"
        "</div>\n"
        "%s"
        "<h3>Hours</h3>\n"
        "<table class=\"hours\">\n"
        "<tr><th>Mon &ndash; Thu</th><td>8:00 AM &ndash; 5:00 PM "
        "(lunch 12:00&ndash;1:00)</td></tr>\n"
        "<tr><th>Friday</th><td>8:00 AM &ndash; 3:00 PM "
        "(lunch 12:00&ndash;1:00)</td></tr>\n"
        "<tr><th>Weekend</th><td>Closed</td></tr>\n"
        "</table>\n"
        "<p class=\"muted\">Phones reopen after lunch; if you get voicemail "
        "around noon, leave a message.</p>\n"
        % (company, o["town"], o["phone"], o["billing_phone"], o["fax"],
           _contact_form_html())
    )


def contact_thanks(world=None):
    """Plain thank-you page after a contact-form POST."""
    world = world or {}
    company = world.get("company") or "Example Clinic"
    domain = world.get("domain") or "example.net"
    body = (
        "<h2>Thank you</h2>\n"
        "<div class=\"box\"><p>Thanks, the front desk will get back to you "
        "within one business day.</p>\n"
        "<p><a href=\"/\">Back to the home page</a></p></div>\n"
    )
    html = _shell("Message sent | %s" % company, body, company, domain,
                  active="contact", updated="Apr 28, 2026")
    return html, "text/html; charset=utf-8", 200, "", []


def _hours(company, domain):
    # Kept as its own URL because the original sitemap pointed here.
    return (
        "<h2>Office hours</h2>\n"
        "<table class=\"hours\">\n"
        "<tr><th>Monday &ndash; Thursday</th><td>8:00 AM &ndash; 5:00 PM</td></tr>\n"
        "<tr><th>Lunch</th><td>Closed 12:00 PM &ndash; 1:00 PM</td></tr>\n"
        "<tr><th>Friday</th><td>8:00 AM &ndash; 3:00 PM "
        "(lunch 12:00&ndash;1:00)</td></tr>\n"
        "<tr><th>Saturday</th><td>Closed</td></tr>\n"
        "<tr><th>Sunday</th><td>Closed</td></tr>\n"
        "</table>\n"
        "<p>Holiday closures are posted on the waiting-room board and on the "
        "front door. We are closed major federal holidays; "
        "the afternoon before Thanksgiving we usually close at noon.</p>\n"
        "<p><a href=\"/contact.html\">Full contact information</a></p>\n"
    )


def _privacy(company, domain):
    o = _OFFICE
    return (
        "<h2>Notice of Privacy Practices</h2>\n"
        "<p class=\"muted\">Summary for patients. A full printed copy is "
        "available at the front desk. Last revised March 2024.</p>\n"
        "<p>This notice describes how medical information about you may be "
        "used and disclosed and how you can get access to this information. "
        "Please review it carefully.</p>\n"
        "<h3>How we use your information</h3>\n"
        "<p>We use and disclose health information for treatment, payment, "
        "and health care operations. Examples include sharing information with "
        "a specialist we refer you to, filing a claim with your insurer, "
        "and reviewing charts for quality.</p>\n"
        "<h3>Your rights</h3>\n"
        "<ul>\n"
        "<li>Ask to see or get a copy of your record</li>\n"
        "<li>Ask us to correct information you think is wrong</li>\n"
        "<li>Request limits on certain uses (we will say yes or no in writing)</li>\n"
        "<li>Ask for confidential communications at an alternate address or phone</li>\n"
        "<li>Get a list of certain disclosures</li>\n"
        "<li>Get a paper copy of this notice at any time</li>\n"
        "</ul>\n"
        "<h3>Complaints</h3>\n"
        "<p>If you believe your privacy rights have been violated, you may "
        "file a complaint with our office (ask for the privacy contact at "
        "%s) or with the U.S. Department of Health and Human Services. "
        "We will not retaliate against you for filing a complaint.</p>\n"
        "<p>%s &mdash; %s &mdash; %s</p>\n"
        % (o["phone"], company, o["town"], o["phone"])
    )


def _not_found(company, domain):
    body = (
        "<h2>Page not found</h2>"
        "<div class=\"box\"><p>That page is not on this site. "
        "Try the menu above, or call the front desk if you followed a link "
        "from one of our old handouts.</p></div>"
    )
    return _shell("Not found | %s" % company, body, company, domain, active="")


def _login_form(action="/", err=False, user_label="Username"):
    err_html = (
        '<div class=err>Invalid username or password.</div>\n' if err else ""
    )
    return (
        "%s"
        "<form method=post action=%s>\n"
        "<label>%s</label>\n"
        "<input type=text name=username autocomplete=username required>\n"
        "<label>Password</label>\n"
        "<input type=password name=password autocomplete=current-password required>\n"
        "<button type=submit>Sign in</button>\n"
        "</form>\n"
    ) % (err_html, action, user_label)


def _staff_404():
    # Same stock nginx 404 (server_tokens off) on portal/billing/mail.
    return (
        "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
        "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        "text/html",
        404,
        "",
        [],
    )


def _portal_page(clean, method, body, company, failed=False):
    if clean not in ("/", "/login", "/index.html", "/admin"):
        return _staff_404()
    err = failed or (method == "POST")
    inner = (
        "<h1>Staff portal</h1>\n"
        "<div class=card>\n"
        "<p class=note>%s employee access. Authorized use only.</p>\n"
        "%s"
        "</div>\n"
    ) % (company, _login_form(err=err))
    html = (
        "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>\n"
        "<title>Staff portal — %s</title>\n"
        "<style>body{font-family:system-ui,sans-serif;background:#eef2f1;"
        "max-width:420px;margin:48px auto;padding:0 16px}"
        ".card{background:#fff;border:1px solid #ccd;padding:20px;border-radius:6px}"
        "label{display:block;margin:10px 0 4px}input{width:100%%;padding:8px}"
        "button{margin-top:12px;padding:8px 14px;background:#1e4d4a;color:#fff;border:0}"
        ".err{background:#fdecea;color:#8a1f11;padding:8px;margin-bottom:10px}"
        ".note{color:#555;font-size:14px}</style></head><body>%s</body></html>\n"
    ) % (company, inner)
    return html, "text/html; charset=utf-8", 200, "", []


def _billing_page(clean, method, body, company, failed=False):
    if clean not in ("/", "/login", "/index.html"):
        return _staff_404()
    err = failed or (method == "POST")
    maint = (
        "<div class=card style=\"background:#fff8e6;border-color:#e6d59a\">\n"
        "<strong>Billing portal under maintenance</strong>\n"
        "<p class=note>Scheduled window: Sat 22:00–Sun 02:00 local. "
        "Paper EOBs and phone payments are unaffected. "
        "For status, contact the billing office.</p>\n"
        "</div>\n"
    )
    inner = (
        "<h1>Billing office</h1>\n%s"
        "<div class=card>\n"
        "<p class=note>Staff sign-in (read-only claims queue). "
        "No patient charts are stored on this portal.</p>\n"
        "%s"
        "</div>\n"
    ) % (maint, _login_form(err=err))
    html = (
        "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>\n"
        "<title>Billing — %s</title>\n"
        "<style>body{font-family:system-ui,sans-serif;background:#f4f0ea;"
        "max-width:480px;margin:40px auto;padding:0 16px}"
        ".card{background:#fff;border:1px solid #ccc;padding:16px;border-radius:6px;"
        "margin:12px 0}"
        "label{display:block;margin:10px 0 4px}input{width:100%%;padding:8px}"
        "button{margin-top:12px;padding:8px 14px;background:#6b4f2a;color:#fff;border:0}"
        ".err{background:#fdecea;color:#8a1f11;padding:8px;margin-bottom:10px}"
        ".note{color:#555;font-size:14px}</style></head><body>%s</body></html>\n"
    ) % (company, inner)
    return html, "text/html; charset=utf-8", 200, "", []


def _mail_page(clean, method, body, company, domain, failed=False):
    # Roundcube-ish paths attackers probe
    if clean not in ("/", "/login", "/index.php", "/?_task=login"):
        return _staff_404()
    err = failed or (method == "POST")
    err_html = (
        '<div class=err>Login failed. Check username and password.</div>\n'
        if err else ""
    )
    html = (
        "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>\n"
        "<title>Webmail — %s</title>\n"
        "<style>body{font-family:Arial,sans-serif;background:#f0f0f0;"
        "margin:0}#box{width:360px;margin:80px auto;background:#fff;"
        "border:1px solid #bbb;padding:24px}"
        "h1{font-size:18px;margin:0 0 16px}label{display:block;margin:8px 0 4px;"
        "font-size:13px}input{width:100%%;padding:7px;box-sizing:border-box}"
        "button{margin-top:14px;width:100%%;padding:8px;background:#376e9c;color:#fff;"
        "border:0}.err{background:#fdd;border:1px solid #c99;padding:8px;"
        "margin-bottom:12px;font-size:13px}"
        ".foot{margin-top:16px;font-size:11px;color:#777;text-align:center}"
        "</style></head><body>\n"
        "<div id=box>\n"
        "<h1>%s Webmail</h1>\n%s"
        "<form method=post action=/>\n"
        "<label>Email</label>\n"
        "<input type=text name=username placeholder=\"name@%s\" "
        "autocomplete=username>\n"
        "<label>Password</label>\n"
        "<input type=password name=password autocomplete=current-password>\n"
        "<button type=submit>Login</button>\n"
        "</form>\n"
        "<div class=foot>Roundcube Webmail</div>\n"
        "</div>\n</body></html>\n"
    ) % (company, company, err_html, domain)
    return html, "text/html; charset=utf-8", 200, "", []
