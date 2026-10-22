"""Local edition: full version inventory of the machine it runs on.

Reads only. Changes nothing. Sends nothing out except (optionally) library
names and versions to OSV, and downloads public lists (endoflife, CISA KEV).
"""

import glob
import json
import os
import platform
import re
import shutil
import subprocess

from . import versions

DEFAULT_PATHS = ["/var/www", "/home", "/srv", "/opt"]
SKIP_DIRS = {"node_modules", ".git", "vendor", "cache", ".cache", "tmp", "proc", "sys",
             "__pycache__", ".npm", ".cpanel", "mail", "logs", ".trash"}
MAX_DEPTH = 6

PHP_CANDIDATES = [
    "/usr/bin/php", "/usr/local/bin/php", "/usr/bin/php[0-9]*",
    "/opt/cpanel/ea-php*/root/usr/bin/php", "/opt/alt/php*/usr/bin/php",
    "/opt/plesk/php/*/bin/php", "/usr/local/lsws/lsphp*/bin/php",
    "/opt/remi/php*/root/usr/bin/php", "/usr/local/php*/bin/php",
]

PHP_PROBE = ('echo PHP_VERSION,"|",PHP_SAPI,"|",'
             '(int)ini_get("session.upload_progress.enabled"),"|",ini_get("post_max_size");')


def run(cmd, timeout=15):
    """Run a command, return combined output or '' (never raises)."""
    exe = cmd[0]
    if os.sep not in exe and not shutil.which(exe):
        return ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + "\n" + p.stderr).strip()
    except Exception:
        return ""


def ver_from(text, pattern=r"(\d+\.\d+(?:\.\d+)?)"):
    m = re.search(pattern, text or "")
    return m.group(1) if m else None


# --- system ------------------------------------------------------------------

def os_info():
    out = {"product": None, "version": None, "pretty": platform.platform()}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            kv = dict(line.rstrip().split("=", 1) for line in f if "=" in line)
        ident = kv.get("ID", "").strip('"').lower()
        out["product"] = {"rocky": "rocky", "almalinux": "almalinux", "ubuntu": "ubuntu",
                          "debian": "debian", "centos": "centos"}.get(ident, ident or None)
        out["version"] = kv.get("VERSION_ID", "").strip('"') or None
        out["pretty"] = kv.get("PRETTY_NAME", "").strip('"') or out["pretty"]
    except OSError:
        pass
    return out


def php_installs():
    seen, out = set(), []
    for pattern in PHP_CANDIDATES:
        for path in sorted(glob.glob(pattern)):
            real = os.path.realpath(path)
            if real in seen or not os.access(real, os.X_OK):
                continue
            seen.add(real)
            res = run([path, "-r", PHP_PROBE])
            parts = res.splitlines()[-1].split("|") if res else []
            if len(parts) >= 4 and versions.parse(parts[0]):
                out.append({"product": "php", "version": parts[0], "path": path,
                            "upload_progress": parts[2] == "1", "post_max_size": parts[3],
                            "note": "settings read from the command-line PHP; the web PHP may differ"})
    return out


def services():
    checks = [
        ("apache", ["httpd", "-v"], r"Apache/(\d+\.\d+\.\d+)"),
        ("apache", ["apache2", "-v"], r"Apache/(\d+\.\d+\.\d+)"),
        ("nginx", ["nginx", "-v"], r"nginx/(\d+\.\d+\.\d+)"),
        ("litespeed", ["/usr/local/lsws/bin/lshttpd", "-v"], r"LiteSpeed/(\d+\.\d+(?:\.\d+)?)"),
        ("mysql", ["mysqld", "--version"], r"Ver (\d+\.\d+\.\d+)(?!.*MariaDB)"),
        ("mariadb", ["mariadbd", "--version"], r"(\d+\.\d+\.\d+)-MariaDB"),
        ("mariadb", ["mysqld", "--version"], r"(\d+\.\d+\.\d+)-MariaDB"),
        ("postgresql", ["postgres", "--version"], r"(\d+\.\d+)"),
        ("postgresql", ["psql", "--version"], r"(\d+\.\d+)"),
        ("redis", ["redis-server", "--version"], r"v=(\d+\.\d+\.\d+)"),
        ("python", ["python3", "--version"], r"(\d+\.\d+\.\d+)"),
        ("nodejs", ["node", "--version"], r"v(\d+\.\d+\.\d+)"),
        ("openssl", ["openssl", "version"], r"OpenSSL (\d+\.\d+\.\d+\w?)"),
        ("openssh", ["ssh", "-V"], r"OpenSSH_(\d+\.\d+)"),
        ("docker", ["docker", "--version"], r"(\d+\.\d+\.\d+)"),
    ]
    out, seen = [], set()
    for product, cmd, pat in checks:
        if product in seen:
            continue
        v = ver_from(run(cmd), pat)
        if v:
            seen.add(product)
            out.append({"product": product, "version": v, "path": cmd[0]})
    return out


# official images record the runtime version in their environment
IMAGE_ENV = {"PHP_VERSION": "php", "NODE_VERSION": "nodejs", "PYTHON_VERSION": "python",
             "NGINX_VERSION": "nginx", "HTTPD_VERSION": "apache", "MARIADB_VERSION": "mariadb",
             "MYSQL_VERSION": "mysql", "PG_VERSION": "postgresql", "REDIS_VERSION": "redis"}


def docker_images():
    """Images of running containers and the runtimes inside them (read-only: image inspect)."""
    res = run(["docker", "ps", "--format", "{{.Image}}"])
    if not res or "permission denied" in res.lower() or "cannot connect" in res.lower():
        return []
    out = []
    for image in sorted(set(x.strip() for x in res.splitlines() if x.strip())):
        env = run(["docker", "image", "inspect", "--format", "{{json .Config.Env}}", image])
        found = False
        try:
            for pair in json.loads(env.splitlines()[0]) if env else []:
                key, _, val = pair.partition("=")
                if key in IMAGE_ENV and versions.parse(val):
                    out.append({"product": IMAGE_ENV[key], "version": val,
                                "path": "docker: " + image, "container": True})
                    found = True
        except (ValueError, IndexError):
            pass
        if not found:
            out.append({"product": "docker-image", "version": None, "path": image, "container": True})
    return out


# --- web applications and libraries -------------------------------------------

APP_FILES = {
    os.path.join("wp-includes", "version.php"): ("wordpress", r"\$wp_version\s*=\s*'([^']+)'"),
    os.path.join("libraries", "src", "Version.php"): ("joomla", None),
    "version.php": (None, None),  # Nextcloud or Moodle, decided by content
    os.path.join("core", "lib", "Drupal.php"): ("drupal", r"const VERSION\s*=\s*'([^']+)'"),
}

LOCK_FILES = ("composer.lock", "package-lock.json", "requirements.txt")


def _read(path, limit=2_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _app_from(root, rel, product, pattern):
    text = _read(os.path.join(root, rel))
    if not text:
        return None
    if product is None:
        m = re.search(r"\$OC_VersionString\s*=\s*'([^']+)'", text)
        if m:
            return {"product": "nextcloud", "version": m.group(1), "path": root}
        m = re.search(r"\$release\s*=\s*'([\d.]+)", text)
        if m and "MOODLE" in text.upper():
            return {"product": "moodle", "version": m.group(1), "path": root}
        return None
    if product == "joomla":
        parts = [re.search(r"%s\s*=\s*(\d+)" % k, text) for k in ("MAJOR_VERSION", "MINOR_VERSION", "PATCH_VERSION")]
        if all(parts):
            return {"product": "joomla", "version": ".".join(p.group(1) for p in parts), "path": root}
        return None
    m = re.search(pattern, text)
    return {"product": product, "version": m.group(1), "path": root} if m else None


def _locks(path, name):
    """Return list of (ecosystem, package, version)."""
    text = _read(path, 20_000_000)
    out = []
    try:
        if name == "composer.lock":
            data = json.loads(text)
            for p in data.get("packages", []) + data.get("packages-dev", []):
                out.append(("Packagist", p["name"], str(p.get("version", "")).lstrip("v")))
        elif name == "package-lock.json":
            data = json.loads(text)
            for key, p in (data.get("packages") or {}).items():
                if key and "node_modules/" in key and p.get("version"):
                    out.append(("npm", key.split("node_modules/")[-1], p["version"]))
        elif name == "requirements.txt":
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
                if m:
                    out.append(("PyPI", m.group(1), m.group(2)))
    except (ValueError, KeyError, TypeError):
        pass
    return out


def scan_paths(paths, max_depth=MAX_DEPTH):
    apps, libs = [], []
    for base in paths:
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(base, followlinks=False):
            depth = root.count(os.sep) - base_depth
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith("_arhiv")]
            if depth >= max_depth:
                dirs[:] = []
            for rel, (product, pattern) in APP_FILES.items():
                head = rel.split(os.sep)[0]
                if (head in dirs or head in files) and os.path.isfile(os.path.join(root, rel)):
                    app = _app_from(root, rel, product, pattern)
                    if app and app not in apps:
                        apps.append(app)
            for name in LOCK_FILES:
                if name in files:
                    for eco, pkg, ver in _locks(os.path.join(root, name), name):
                        libs.append({"ecosystem": eco, "name": pkg, "version": ver,
                                     "file": os.path.join(root, name)})
    return apps, libs


def php_packages():
    """PHP packages from the package manager: [{'manager','name','source','version'}]."""
    out = []
    res = run(["dpkg-query", "-W", "-f", "${Package} ${Version} ${source:Package} ${db:Status-Abbrev}\n"], 30)
    for line in res.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].startswith("ii") and re.fullmatch(r"php\d\.\d", parts[2]):
            out.append({"manager": "dpkg", "name": parts[0], "version": parts[1], "source": parts[2]})
    res = run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"], 30)
    for line in res.splitlines():
        parts = line.split()
        if len(parts) == 2 and re.match(r"^(ea|alt)-php\d+(-php)?-(cli|common|fpm)$", parts[0]):
            out.append({"manager": "rpm", "name": parts[0], "version": parts[1], "source": parts[0]})
    return out


def deb_version_ge(a, b):
    """True/False via dpkg --compare-versions, None when dpkg is missing."""
    if not shutil.which("dpkg"):
        return None
    try:
        return subprocess.run(["dpkg", "--compare-versions", a, "ge", b], timeout=10).returncode == 0
    except Exception:
        return None


def rpm_changelog_has(package, words):
    text = run(["rpm", "-q", "--changelog", package], 30)
    return any(w in text for w in words) if text else None


def collect(paths=None):
    """Everything installed that we can see, without changing anything."""
    paths = paths or DEFAULT_PATHS
    osi = os_info()
    software = []
    if osi["product"]:
        software.append({"product": osi["product"], "version": osi["version"], "path": "/etc/os-release"})
    system = php_installs() + services()
    # distributions (Ubuntu, Debian, RHEL family) patch packages without changing the upstream number
    if osi["product"] in ("ubuntu", "debian", "almalinux", "rocky", "centos", "rhel"):
        for s in system:
            p = s.get("path", "")
            if p.startswith(("/usr/bin", "/usr/sbin")) or os.sep not in p:
                s["distro"] = osi["product"]
    software += system
    software += docker_images()
    apps, libs = scan_paths(paths)
    software += apps
    return {"os": osi, "software": software, "libraries": libs, "paths": paths,
            "packages": php_packages(), "host": platform.node()}
