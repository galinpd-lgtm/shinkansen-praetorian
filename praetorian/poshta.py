"""Report by email: request → confirmation link → queue → worker checks → report email.

The web server only stores small JSON files and sends two short emails; the check itself is
done by a separate worker (in our setup: GX10), so a rush of visitors cannot overload the host.

Files (outside the web root):  $PRAETORIAN_DATA/poshta/<id>.json
Statuses: chaka_potvarzhdenie → potvardena → v_rabota → izpratena (or greshka)
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import subprocess
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

OT = os.environ.get("PRAETORIAN_MAIL_FROM", "office@kagami.bg")
OT_IME = os.environ.get("PRAETORIAN_MAIL_NAME", "BoostWorkers Praetorian")
BAZA = os.environ.get("PRAETORIAN_BASE_URL", "https://boostworkers.com/proveri")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
PER_EMAIL_DAY = 3
PER_DAY_ALL = 50              # all confirmation emails in 24 hours, from everybody together
PAZIM_DNI = 90                # emails are kept 3 months, then erased (decision of 10.11.2026)
SAGLASIE_VERSIA = "2026-11-10"   # version of the consent/privacy text shown on the page
POTVARDI_ZA = 24 * 3600
_lock = threading.Lock()

TXT = {
    "bg": {
        "potv_tema": "Потвърдете: отчет за %s",
        "potv_tialo": "Здравейте,\n\nНякой (вероятно вие) поиска безплатна проверка за пробиви на сайта %s с отчет на този имейл.\n\n"
                      "За да я получите, отворете връзката:\n%s\n\nАко не сте били вие — просто изтрийте това писмо; без потвърждение нищо не се изпраща.\n\n"
                      "BoostWorkers Praetorian · https://boostworkers.com/proveri/\nKAGAMI ЕООД, Варна · office@kagami.bg",
        "otchet_tema": "Отчет: %s — проверка за пробиви",
        "otchet_uvod": "Здравейте,\n\nЕто отчета за %s. Пълният отчет е в HTML частта на писмото.\n\n",
        "otchet_kraj": "\n\nИскате ли да го оправим ние? Вижте как: https://boostworkers.com/uslugi/\n"
                       "Проверете и друг сайт: https://boostworkers.com/proveri/\n\nBoostWorkers Praetorian · KAGAMI ЕООД, Варна · office@kagami.bg",
    },
    "en": {
        "potv_tema": "Please confirm: report for %s",
        "potv_tialo": "Hello,\n\nSomeone (probably you) asked for a free breach check of %s with the report sent to this email.\n\n"
                      "To get it, open this link:\n%s\n\nIf it was not you, just delete this email; nothing is sent without confirmation.\n\n"
                      "BoostWorkers Praetorian · https://boostworkers.com/proveri/?lang=en\nKAGAMI Ltd, Varna, Bulgaria · office@kagami.bg",
        "otchet_tema": "Report: %s — breach check",
        "otchet_uvod": "Hello,\n\nHere is the report for %s. The full report is in the HTML part of this email.\n\n",
        "otchet_kraj": "\n\nWant us to fix it? See how: https://en.boostworkers.com/uslugi/\n"
                       "Check another site: https://boostworkers.com/proveri/?lang=en\n\nBoostWorkers Praetorian · KAGAMI Ltd, Varna · office@kagami.bg",
    },
}


def papka(data_dir):
    p = os.path.join(data_dir, "poshta")
    os.makedirs(p, mode=0o700, exist_ok=True)
    return p


def _pat(data_dir, zid):
    if not re.fullmatch(r"[0-9a-f]{32}", zid or ""):
        raise ValueError("bad id")
    return os.path.join(papka(data_dir), zid + ".json")


def cheti(data_dir, zid):
    with open(_pat(data_dir, zid), encoding="utf-8") as f:
        return json.load(f)


def zapishi(data_dir, z):
    p = _pat(data_dir, z["id"])
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(z, f, ensure_ascii=False)
    os.replace(tmp, p)


def validen_email(e):
    return bool(EMAIL_RE.match(e or ""))


def _broi_za_email(data_dir, email):
    """How many requests this email made in the last 24 hours, and how many were made by everybody."""
    h = _hash(email)
    ot = time.time() - 86400
    n = vsichki = 0
    for name in os.listdir(papka(data_dir)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(papka(data_dir), name), encoding="utf-8") as f:
                z = json.load(f)
            if z.get("sazdadena", 0) > ot:
                vsichki += 1
                if z.get("email_hash") == h:
                    n += 1
        except (OSError, ValueError):
            continue
    return n, vsichki


def _hash(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def nova(data_dir, address, email, lang, novini=False, saglasie_tekst=""):
    """Create a request and send the confirmation email. Returns (ok, error_key).
    `address` must already be a bare host name (the caller checks it) — it goes into the email."""
    email = email.strip()
    zalichi_stari(data_dir)
    with _lock:
        moi, vsichki = _broi_za_email(data_dir, email)
        if moi >= PER_EMAIL_DAY:
            return False, "email_limit"
        if vsichki >= PER_DAY_ALL:
            return False, "day_limit"
        z = {"id": secrets.token_hex(16), "token": secrets.token_urlsafe(24), "status": "chaka_potvarzhdenie",
             "address": address, "email": email, "email_hash": _hash(email), "lang": lang,
             "novini": False, "sazdadena": time.time(), "istoria": [["sazdadena", time.time()]],
             # proof of consent: when, and for which text (the box on the page must be ticked to get here)
             "saglasie": {"chas": time.time(), "versia": SAGLASIE_VERSIA, "tekst": saglasie_tekst[:400]}}
        zapishi(data_dir, z)
    link = "%s/potvardi?id=%s&t=%s%s" % (BAZA, z["id"], z["token"], "&lang=en" if lang == "en" else "")
    t = TXT[lang]
    try:
        izprati(email, t["potv_tema"] % address, t["potv_tialo"] % (address, link))
    except Exception as e:  # mail problem must not leave a silent failure
        z["status"], z["greshka"] = "greshka", "potvarzhdenie: %s" % str(e)[:200]
        zapishi(data_dir, z)
        return False, "mail_error"
    return True, ""


def zalichi_stari(data_dir, dni=PAZIM_DNI, sega=None):
    """Retention: requests older than `dni` days lose the email, its hash and the token; the rest
    (site, time, status) stays for statistics. Runs at most once a day. Returns how many were erased."""
    sega = sega or time.time()
    belezhka = os.path.join(papka(data_dir), ".zalichavane")
    try:
        if sega - os.path.getmtime(belezhka) < 86400:
            return 0
    except OSError:
        pass
    n = 0
    with _lock:
        for name in os.listdir(papka(data_dir)):
            if not name.endswith(".json"):
                continue
            try:
                z = cheti(data_dir, name[:-5])
            except (OSError, ValueError):
                continue
            if z.get("email") and sega - z.get("sazdadena", sega) > dni * 86400:
                for k in ("email", "email_hash", "token"):
                    z.pop(k, None)
                if z.get("status") in ("chaka_potvarzhdenie", "potvardena", "v_rabota"):
                    z["status"] = "iztekla"
                z["zalicheno"] = sega
                z.setdefault("istoria", []).append(["zalicheno", sega])
                zapishi(data_dir, z)
                n += 1
        with open(belezhka, "w", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S"))
    return n


def potvardi(data_dir, zid, token):
    """Confirmation link clicked. Returns the request or None."""
    try:
        z = cheti(data_dir, zid)
    except (OSError, ValueError):
        return None
    if not z.get("token") or not hmac.compare_digest(str(z["token"]), str(token or "")):
        return None                         # also: an erased (expired) request has no token any more
    z["_sega"] = False                         # True only the first time the link is opened (for the counter)
    if z["status"] == "chaka_potvarzhdenie":
        if time.time() - z["sazdadena"] > POTVARDI_ZA:
            return None
        z["status"] = "potvardena"
        z["istoria"].append(["potvardena", time.time()])
        z.pop("_sega")
        zapishi(data_dir, z)
        z["_sega"] = True
    return z


def za_rabotnika(data_dir, max_n=5):
    """Confirmed requests for the worker (marks them 'v_rabota'; stale ones are offered again after 15 min)."""
    zalichi_stari(data_dir)                # retention runs with the worker's regular visit (at most once a day)
    out = []
    with _lock:
        for name in sorted(os.listdir(papka(data_dir))):
            if not name.endswith(".json") or len(out) >= max_n:
                continue
            try:
                z = cheti(data_dir, name[:-5])
            except (OSError, ValueError):
                continue
            zastarela = z["status"] == "v_rabota" and time.time() - z.get("vzeta", 0) > 900
            if z["status"] == "potvardena" or zastarela:
                z["status"], z["vzeta"] = "v_rabota", time.time()
                z["istoria"].append(["v_rabota", time.time()])
                zapishi(data_dir, z)
                out.append({"id": z["id"], "address": z["address"], "lang": z["lang"]})
    return out


def rezultat(data_dir, zid, res, html_otchet, text_otchet, greshka=None):
    """Worker result → report email (or an apology if the check failed)."""
    z = cheti(data_dir, zid)
    if z["status"] not in ("v_rabota", "potvardena"):
        return False
    t = TXT[z["lang"]]
    if greshka:
        tialo = t["otchet_uvod"] % z["address"] + greshka + t["otchet_kraj"]
        izprati(z["email"], t["otchet_tema"] % z["address"], tialo)
    else:
        izprati(z["email"], t["otchet_tema"] % z["address"],
                t["otchet_uvod"] % z["address"] + text_otchet + t["otchet_kraj"], html_otchet)
    z["status"] = "izpratena"
    z["istoria"].append(["izpratena", time.time()])
    if res:
        z["rezultat_karti"] = [c.get("status") for c in res.get("cards", [])]
    zapishi(data_dir, z)
    return True


def izprati(do, tema, text, html_=None):
    """Send through the host's own mail server (signed for the sender's domain). No passwords."""
    m = EmailMessage()
    m["From"] = formataddr((OT_IME, OT))
    m["To"] = do
    m["Subject"] = tema
    m["Reply-To"] = OT
    m["Message-ID"] = make_msgid(domain=OT.split("@")[1])
    m.set_content(text)
    if html_:
        m.add_alternative(html_, subtype="html")
    sm = "/usr/sbin/sendmail"
    if os.path.exists(sm):
        r = subprocess.run([sm, "-t", "-i", "-f", OT], input=m.as_bytes(), capture_output=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError("sendmail: %s" % r.stderr.decode("utf-8", "replace")[:200])
        return
    with smtplib.SMTP("localhost", 25, timeout=30) as s:
        s.send_message(m)


def proveri_kluch(data_dir, podaden):
    """Worker key: a file next to the data (never in the code or the repo)."""
    try:
        with open(os.path.join(data_dir, "rabotnik.key"), encoding="utf-8") as f:
            k = f.read().strip()
    except OSError:
        return False
    # compared as bytes: a key with non-Latin characters is simply wrong, not a server error
    return bool(k) and hmac.compare_digest(k.encode("utf-8"), (podaden or "").strip().encode("utf-8", "replace"))
