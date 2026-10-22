"""Open vulnerability sources, fetched gently and cached for 24 hours.

Only public lists are downloaded. The only data sent out is the name and
version of a library when OSV is asked about it (can be switched off).
"""

import json
import os
import time
import urllib.request

from . import __version__, versions

UA = "BoostWorkers-Praetorian/%s (+https://boostworkers.com)" % __version__
CACHE_DIR = os.environ.get(
    "PRAETORIAN_CACHE", os.path.join(os.path.expanduser("~"), ".cache", "praetorian")
)
TTL = 24 * 3600

ENDOFLIFE = "https://endoflife.date/api/%s.json"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
WP_CORE = "https://api.wordpress.org/core/version-check/1.7/"

# our product names -> endoflife.date product ids
EOL_IDS = {
    "php": "php", "python": "python", "nodejs": "nodejs", "mysql": "mysql",
    "mariadb": "mariadb", "postgresql": "postgresql", "nginx": "nginx",
    "apache": "apache-http-server", "wordpress": "wordpress", "nextcloud": "nextcloud",
    "moodle": "moodle", "joomla": "joomla", "drupal": "drupal", "redis": "redis",
    "openssl": "openssl", "ubuntu": "ubuntu", "debian": "debian",
    "almalinux": "almalinux", "rocky": "rocky-linux", "centos": "centos",
    "litespeed": None, "openssh": None,
}

# our product names -> words used in the CISA KEV catalog
KEV_NAMES = {
    "php": ("php",), "wordpress": ("wordpress",), "apache": ("http server",),
    "nginx": ("nginx",), "mysql": ("mysql",), "openssl": ("openssl",),
    "openssh": ("openssh",), "nextcloud": ("nextcloud",), "moodle": ("moodle",),
    "joomla": ("joomla",), "drupal": ("drupal",), "litespeed": ("litespeed",),
}


class Sources:
    def __init__(self, offline=False, ask_osv=True, pause=0.5):
        self.offline = offline
        self.ask_osv = ask_osv and not offline
        self.pause = pause
        self.errors = []

    # --- helpers -------------------------------------------------------
    def _get(self, url, key, data=None):
        path = os.path.join(CACHE_DIR, key)
        if data is None and os.path.exists(path) and time.time() - os.path.getmtime(path) < TTL:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        if self.offline:
            return None
        try:
            req = urllib.request.Request(url, data=data, headers={"User-Agent": UA})
            if data is not None:
                req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read().decode("utf-8"))
            time.sleep(self.pause)  # be gentle with other people's systems
        except Exception as e:  # network problems must never stop the check
            self.errors.append("%s: %s" % (url, e))
            return None
        if data is None:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(body, f)
        return body

    # --- end of life ---------------------------------------------------
    def eol(self, product, version_text):
        """Return dict with cycle, eol, latest, behind — or None."""
        pid = EOL_IDS.get(product)
        v = versions.parse(version_text)
        if not pid or not v:
            return None
        cycles = self._get(ENDOFLIFE % pid, "eol_%s.json" % pid)
        if not isinstance(cycles, list):
            return None
        c = versions.best_cycle(v, cycles)
        if not c:
            return None
        eol = c.get("eol")
        ended = False
        if eol is True:
            ended = True
        elif isinstance(eol, str):
            ended = eol <= time.strftime("%Y-%m-%d")
        latest = c.get("latest")
        behind = bool(latest and versions.parse(latest) and versions.cmp(v, versions.parse(latest)) < 0)
        return {"cycle": str(c.get("cycle")), "eol": eol, "ended": ended,
                "latest": latest, "behind": behind}

    # --- CISA KEV ------------------------------------------------------
    def kev(self, product, days=365):
        """Recent actively exploited entries for this product (no version matching)."""
        words = KEV_NAMES.get(product)
        if not words:
            return []
        cat = self._get(KEV, "kev.json")
        if not cat:
            return []
        since = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        out = []
        for e in cat.get("vulnerabilities", []):
            name = (e.get("vendorProject", "") + " " + e.get("product", "")).lower()
            if any(w in name for w in words) and e.get("dateAdded", "") >= since:
                out.append({"cve": e.get("cveID"), "name": e.get("vulnerabilityName"),
                            "added": e.get("dateAdded")})
        return out

    # --- OSV (libraries from lock files) -------------------------------
    def osv(self, packages):
        """packages: list of (ecosystem, name, version). Returns {index: [ids]}."""
        if not self.ask_osv or not packages:
            return {}
        found = {}
        for start in range(0, len(packages), 500):
            chunk = packages[start:start + 500]
            q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                             for e, n, v in chunk]}
            res = self._get(OSV_BATCH, "", data=json.dumps(q).encode("utf-8"))
            if not res:
                break
            for i, r in enumerate(res.get("results", [])):
                ids = [x["id"] for x in r.get("vulns", [])]
                if ids:
                    found[start + i] = ids
        return found

    # --- WordPress -----------------------------------------------------
    def wordpress_latest(self):
        res = self._get(WP_CORE, "wp_core.json")
        try:
            return res["offers"][0]["current"]
        except Exception:
            return None
