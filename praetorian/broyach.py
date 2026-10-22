"""Anonymous campaign counter: numbers per 30-minute slot. No addresses, emails or IPs are stored.

File: $PRAETORIAN_DATA/broyach/<YYYY-MM-DD>.json
      {"10:30": {"posetenia": 4, "proverki": 2, "ot": {"facebook.com": 3}}, ...}
"""

import datetime as dt
import json
import os
import threading
import urllib.parse

try:
    import fcntl
except ImportError:
    fcntl = None

_lock = threading.Lock()
SUBITIA = ("posetenia", "proverki", "zaeto", "poshta_zayavki", "poshta_potvardeni", "poshta_izprateni",
           "spodelyane", "otzivi")


def _slot(now=None):
    now = now or dt.datetime.now()
    return now.strftime("%Y-%m-%d"), "%02d:%02d" % (now.hour, 0 if now.minute < 30 else 30)


def _ref_domain(ref):
    try:
        h = (urllib.parse.urlsplit(ref or "").hostname or "").lower()
    except ValueError:
        return ""
    for pre in ("www.", "l.", "lm.", "m.", "mobile."):
        if h.startswith(pre):
            h = h[len(pre):]
    return h[:60]


def zapishi(data_dir, subitie, ref="", kanal=""):
    """Add 1 to an event in the current 30-minute slot. Never raises."""
    try:
        den, slot = _slot()
        p = os.path.join(data_dir, "broyach")
        os.makedirs(p, mode=0o700, exist_ok=True)
        fp = os.path.join(p, den + ".json")
        with _lock, open(fp, "a+", encoding="utf-8") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            txt = f.read()
            d = json.loads(txt) if txt.strip() else {}
            s = d.setdefault(slot, {})
            s[subitie] = s.get(subitie, 0) + 1
            dom = _ref_domain(ref)
            if dom and subitie == "posetenia" and dom != "boostworkers.com":
                ot = s.setdefault("ot", {})
                ot[dom] = ot.get(dom, 0) + 1
            if kanal:
                kn = s.setdefault("kanali", {})
                kn[kanal] = kn.get(kanal, 0) + 1
            f.seek(0)
            f.truncate()
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


RED = ["affected", "check_vendor", "likely", "not_visible", "patched", "not_affected"]


def sait(data_dir, res, via):
    """Galin (22.10): keep the checked sites — domain, time, overall result, how (online / email).
    Not who asked: no IP, no email. Internal only, never published."""
    try:
        host = (urllib.parse.urlsplit(res.get("final_url") or "").hostname or "")[:120]
        st = sorted((c.get("status") for c in res.get("cards", [])), key=lambda s: RED.index(s) if s in RED else 99)
        p = os.path.join(data_dir, "proverki")
        os.makedirs(p, mode=0o700, exist_ok=True)
        rec = {"t": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "sait": host, "rezultat": st[0] if st else "",
               "softuer": sorted({"%s %s" % (s.get("product"), s.get("version") or "") for s in res.get("software", [])})[:12],
               "via": via}
        with _lock, open(os.path.join(p, dt.date.today().isoformat() + ".jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def saitove(data_dir, den=None):
    den = den or dt.date.today().isoformat()
    try:
        with open(os.path.join(data_dir, "proverki", den + ".jsonl"), encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


def cheti(data_dir, den=None):
    den = den or dt.date.today().isoformat()
    try:
        with open(os.path.join(data_dir, "broyach", den + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
