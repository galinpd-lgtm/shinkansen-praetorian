"""Online edition: passive check of a public website by its address.

Rules (never broken):
  * only ordinary GET requests that any visitor or search engine makes;
  * at most 3 requests per check, with pauses; ports 80/443 only;
  * no login attempts, no exploit payloads, no downloading of private data;
  * only public internet addresses (no internal networks).
"""

import http.client
import ipaddress
import re
import socket
import ssl
import time
import urllib.parse

from . import __version__, cards, versions

UA = "BoostWorkers-Praetorian/%s (+https://boostworkers.com; passive check)" % __version__
MAX_BODY = 1_500_000
TIMEOUT = 12          # per request; most sites answer in 1–5 s
FEED_BUDGET = 6       # seconds: if the first answer took longer, the extra feed request is skipped
PAUSE = 1.0


class CheckError(Exception):
    pass


# --- safe fetching -----------------------------------------------------------

def normalize(address):
    address = (address or "").strip()
    if not address:
        raise CheckError("empty address")
    if "://" not in address:
        address = "https://" + address
    u = urllib.parse.urlsplit(address)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise CheckError("only http/https website addresses")
    if u.port not in (None, 80, 443):
        raise CheckError("only ports 80 and 443")
    if u.username or u.password:
        raise CheckError("addresses with passwords are not accepted")
    return u.scheme, u.hostname.lower().rstrip("."), (u.path or "/")


def public_ip(host):
    """Resolve host and return one public IP, or raise."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise CheckError("the address does not exist (DNS)")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise CheckError("internal or reserved network addresses are not checked")
        ips.append(str(ip))
    if not ips:
        raise CheckError("the address does not exist (DNS)")
    return ips[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a fixed IP with the real host name for SNI and certificate."""

    def __init__(self, host, ip, **kw):
        super().__init__(host, 443, **kw)
        self._ip = ip
        self.cert = None
        self.tls_version = None

    def connect(self):
        sock = socket.create_connection((self._ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        self.cert = self.sock.getpeercert()
        self.tls_version = self.sock.version()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, **kw):
        super().__init__(host, 80, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, 80), self.timeout)


def fetch(scheme, host, path):
    """One GET. Returns dict(status, headers, body, cert, tls, tls_error)."""
    ip = public_ip(host)
    tls_error = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = _PinnedHTTPS(host, ip, timeout=TIMEOUT, context=ctx)
    else:
        conn = _PinnedHTTP(host, ip, timeout=TIMEOUT)
    try:
        conn.request("GET", path, headers={
            "User-Agent": UA, "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "identity"})
        r = conn.getresponse()
        body = r.read(MAX_BODY)
        out = {
            "status": r.status,
            "headers": {k.lower(): v for k, v in r.getheaders()},
            "set_cookie": r.headers.get_all("Set-Cookie") or [],
            "body": body.decode("utf-8", "replace"),
            "cert": getattr(conn, "cert", None),
            "tls": getattr(conn, "tls_version", None),
            "tls_error": tls_error,
        }
    except ssl.SSLCertVerificationError as e:
        raise CheckError("the security certificate is not valid: %s" % e.verify_message)
    except (OSError, http.client.HTTPException) as e:
        raise CheckError("the site did not answer: %s" % e.__class__.__name__)
    finally:
        conn.close()
    return out


def fetch_follow(address, max_redirects=4):
    scheme, host, path = normalize(address)
    chain = []
    for _ in range(max_redirects + 1):
        r = fetch(scheme, host, path)
        chain.append("%s://%s%s %s" % (scheme, host, path, r["status"]))
        loc = r["headers"].get("location")
        if r["status"] in (301, 302, 303, 307, 308) and loc:
            nxt = urllib.parse.urljoin("%s://%s%s" % (scheme, host, path), loc)
            scheme, host, path = normalize(nxt)
            time.sleep(PAUSE / 2)
            continue
        r.update(final_scheme=scheme, final_host=host, final_path=path, chain=chain)
        return r
    raise CheckError("too many redirects")


# --- reading the signals ----------------------------------------------------

_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_GEN2 = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.I)
# only files whose ?ver= is the WordPress core version (jQuery etc. carry their own)
_WPVER = re.compile(r"(?:wp-emoji-release\.min\.js|block-library/style(?:\.min)?\.css|wp-embed(?:\.min)?\.js)"
                    r"\?ver=(\d+\.\d+(?:\.\d+)?)", re.I)
_FEEDGEN = re.compile(r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", re.I)

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy",
]


def detect(resp):
    """Find software and versions the site itself shows to every visitor."""
    h = resp["headers"]
    body = resp["body"]
    found = {}

    def add(product, version, evidence):
        cur = found.get(product)
        if cur and cur.get("version") and not version:
            return
        found[product] = {"version": version, "evidence": evidence}

    xp = h.get("x-powered-by", "")
    m = re.search(r"PHP/([\d.]+)", xp, re.I)
    if m:
        add("php", m.group(1), "X-Powered-By: " + xp)
    elif "php" in xp.lower():
        add("php", None, "X-Powered-By: " + xp)

    server = h.get("server", "")
    for prod, pat in (("apache", r"Apache/?([\d.]+)?"), ("nginx", r"nginx/?([\d.]+)?"),
                      ("litespeed", r"LiteSpeed/?([\d.]+)?"), ("openssl", r"OpenSSL/([\d.]+\w?)")):
        m = re.search(pat, server, re.I)
        if m:
            add(prod, m.group(1) if m.lastindex else None, "Server: " + server)
    m = re.search(r"PHP/([\d.]+)", server, re.I)
    if m:
        add("php", m.group(1), "Server: " + server)

    for c in resp.get("set_cookie", []):
        if c.upper().startswith("PHPSESSID="):
            add("php", None, "cookie PHPSESSID")

    gens = _GEN.findall(body) + _GEN2.findall(body)
    for g in gens:
        gl = g.lower()
        for prod in ("wordpress", "joomla", "drupal"):
            if gl.startswith(prod):
                add(prod, versions.fmt(versions.parse(g)) or None, "meta generator: " + g)
    if "wp-content/" in body or "wp-includes/" in body:
        m = _WPVER.search(body)
        add("wordpress", m.group(1) if m else None,
            "WordPress paths" + (" (?ver=%s)" % m.group(1) if m else ""))
    if "/sites/default/files/" in body:
        add("drupal", None, "Drupal paths")
    if "/media/jui/" in body or "/media/system/js/" in body:
        add("joomla", None, "Joomla paths")
    if re.search(r'href=["\'][^"\']+\.php(\?|["\'])', body, re.I):
        add("php", None, "links to .php pages")

    # anything that runs WordPress/Joomla/Drupal runs PHP
    if any(p in found for p in ("wordpress", "joomla", "drupal")) and "php" not in found:
        add("php", None, "CMS written in PHP")
    return found


def basics(resp):
    """Simple hygiene: https, certificate, security headers."""
    h = resp["headers"]
    out = {"https": resp["final_scheme"] == "https", "tls": resp.get("tls"),
           "cert_days_left": None, "missing_headers": []}
    cert = resp.get("cert")
    if cert and cert.get("notAfter"):
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        out["cert_days_left"] = int((exp - time.time()) // 86400)
    out["missing_headers"] = [x for x in SECURITY_HEADERS if x not in h]
    return out


def check(address, src=None, card_list=None):
    """Run the full passive check. Returns a result dict (no HTML)."""
    card_list = card_list if card_list is not None else cards.load_cards()
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    t0 = time.time()
    resp = fetch_follow(address)
    found = detect(resp)

    # one extra, ordinary request: the WordPress feed shows the version
    # (skipped when the site is already slow — keeps each check short)
    if "wordpress" in found and not found["wordpress"]["version"] and time.time() - t0 < FEED_BUDGET:
        time.sleep(PAUSE)
        try:
            feed = fetch(resp["final_scheme"], resp["final_host"], "/feed/")
            m = _FEEDGEN.search(feed["body"])
            if m:
                found["wordpress"] = {"version": m.group(1), "evidence": "RSS feed generator"}
        except CheckError:
            pass

    results = []
    for card in card_list:
        prod = card["product"]
        if prod in found:
            status, detail = cards.assess(card, prod, found[prod]["version"])
            evidence = found[prod]["evidence"]
        else:
            status, detail, evidence = cards.NOT_VISIBLE, "", ""
        results.append({"card": card["id"], "status": status, "detail": detail,
                        "evidence": evidence})

    software = []
    for prod, info in sorted(found.items()):
        item = {"product": prod, "version": info["version"], "evidence": info["evidence"]}
        if src and info["version"]:
            item["eol"] = src.eol(prod, info["version"])
            if prod == "wordpress":
                item["latest"] = src.wordpress_latest()
        software.append(item)

    return {
        "edition": "online",
        "tool_version": __version__,
        "checked_at": started,
        "address": address,
        "final_url": "%s://%s%s" % (resp["final_scheme"], resp["final_host"], resp["final_path"]),
        "redirects": resp["chain"],
        "software": software,
        "cards": results,
        "basics": basics(resp),
        "source_errors": src.errors if src else [],
    }
