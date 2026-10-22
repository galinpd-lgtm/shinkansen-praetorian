"""Online edition as a tiny WSGI app (no dependencies).

  GET  /                 form "Check your site"
  POST /                 run the check, show the report
  GET  /api/check?address=example.com&lang=bg   JSON
  POST /otziv            advice / questions / comments -> $PRAETORIAN_DATA/otzivi.jsonl

Limits: 10 checks per visitor per hour; the same site is checked at most
once every 15 minutes (later requests get the saved result); 3 messages per
visitor per hour; a hidden "website" field catches bots.

Run locally:  python -m praetorian.web 8080
"""

import base64
import hashlib
import html
import json
import os
import re
import tempfile
import threading
import time
import urllib.parse

try:
    import fcntl
except ImportError:          # Windows (local tests) — in-process semaphore instead
    fcntl = None

from . import __version__, broyach, cards, page_text, poshta, remote, report
from .sources import Sources

PER_IP_HOUR = 10
SAME_SITE_SECONDS = 15 * 60
_lock = threading.Lock()
_hits = {}      # ip -> [timestamps]
_saved = {}     # host -> (time, result)
_cards = cards.load_cards()

FORM = {
    "bg": ("Провери сайта си за пробиви", "Адрес на сайта", "Провери",
           "Безплатно. Проверяваме само каквото вижда всеки посетител, без атака и без вход. "
           "Отчетът е само за вас. Записваме кои сайтове са проверени (за статистика) — резултатите не публикуваме и не даваме на никого.",
           "Твърде много проверки от вас за последния час. Опитайте по-късно."),
    "en": ("Check your website for breaches", "Website address", "Check",
           "Free. We only look at what every visitor sees — no attack, no login. "
           "The report is for you only. We record which sites were checked (for statistics) — results are never published or shared.",
           "Too many checks from you in the last hour. Please try later."),
}


TRUST_PROXY = os.environ.get("PRAETORIAN_TRUST_PROXY") == "1"


def _client_ip(environ):
    # forwarded headers are easy to fake: use them only behind a proxy we trust
    if TRUST_PROXY:
        fwd = environ.get("HTTP_CF_CONNECTING_IP") or environ.get("HTTP_X_FORWARDED_FOR", "")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
    return environ.get("REMOTE_ADDR", "?")[:64]


def _allowed(ip):
    now = time.time()
    with _lock:
        hits = [t for t in _hits.get(ip, []) if now - t < 3600]
        if len(hits) >= PER_IP_HOUR:
            _hits[ip] = hits
            return False
        hits.append(now)
        _hits[ip] = hits
        if len(_hits) > 50_000:
            _hits.clear()
        return True


# --- at most N checks at the same time, across all server processes ----------
# Each check holds a worker for up to ~25 s. On shared hosting a rush of visitors could
# use up the account's process limit and take down every site on it, so extra visitors
# get "busy, try in a minute" instead.
MAX_PARALLEL = int(os.environ.get("PRAETORIAN_MAX_PARALLEL", "3"))
# a fixed folder shared by all processes (Passenger may give each process its own temp dir)
SLOT_DIR = os.environ.get("PRAETORIAN_SLOTS",
                          os.path.join(os.path.expanduser("~"), "praetorian_danni", "slots") if fcntl
                          else os.path.join(tempfile.gettempdir(), "praetorian_slots"))


class Busy(Exception):
    pass


class _Slot:
    """Non-blocking slot: a file lock per slot (Linux, works across processes), a semaphore elsewhere."""
    _sem = threading.BoundedSemaphore(MAX_PARALLEL)

    def __enter__(self):
        self.f = None
        if fcntl:
            os.makedirs(SLOT_DIR, exist_ok=True)
            for i in range(MAX_PARALLEL):
                f = open(os.path.join(SLOT_DIR, "slot%d" % i), "a")
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.f = f
                    return self
                except OSError:
                    f.close()
            raise Busy()
        if not self._sem.acquire(blocking=False):
            raise Busy()
        return self

    def __exit__(self, *exc):
        if self.f:
            fcntl.flock(self.f, fcntl.LOCK_UN)
            self.f.close()
        else:
            self._sem.release()


BUSY = {"bg": "В момента много хора проверяват сайтовете си. Опитайте пак след минута — или поръчайте отчета на имейл по-долу.",
        "en": "Many people are checking their websites right now. Try again in a minute — or get the report by email below."}


def run_check(address):
    _, host, _ = remote.normalize(address)
    now = time.time()
    with _lock:
        saved = _saved.get(host)
        if saved and now - saved[0] < SAME_SITE_SECONDS:
            return saved[1]
    with _Slot():
        res = remote.check(address, Sources(), _cards)
    with _lock:
        _saved[host] = (now, res)
        if len(_saved) > 5000:
            _saved.clear()
    return res


ERR_BG = {
    "empty address": "Въведете адрес на сайт.",
    "only http/https website addresses": "Само адреси на сайтове (http/https).",
    "only ports 80 and 443": "Само стандартните портове 80 и 443.",
    "addresses with passwords are not accepted": "Адреси с пароли не се приемат.",
    "the address does not exist (DNS)": "Такъв адрес не съществува.",
    "internal or reserved network addresses are not checked": "Адреси във вътрешни мрежи не се проверяват.",
    "too many redirects": "Сайтът пренасочва твърде много пъти.",
}


def _err(msg, lang):
    if lang != "bg":
        return msg
    if msg.startswith("the site did not answer"):
        return "Сайтът не отговори."
    if msg.startswith("the security certificate is not valid"):
        return "Сертификатът за сигурност на сайта не е валиден."
    return ERR_BG.get(msg, msg)


# the only script on the page: show "please wait" while the server works (allowed by its hash in the CSP)
SCRIPT_BODY = ("document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(){"
               "var b=f.querySelector('button');if(b&&b.dataset.wait){b.textContent=b.dataset.wait;"
               "b.style.opacity='.7';setTimeout(function(){b.disabled=true},0);}});});"
               "var s=document.getElementById('share');if(s){s.addEventListener('click',function(){"
               "var d={title:s.dataset.title,text:s.dataset.text,url:s.dataset.url};"
               "if(navigator.share){navigator.share(d).then(function(){try{navigator.sendBeacon(s.dataset.beacon)}catch(e){}}).catch(function(){});}"
               "else if(navigator.clipboard){navigator.clipboard.writeText(d.url).then(function(){s.textContent=s.dataset.copied;});}"
               "});}")
SCRIPT = "<script>%s</script>" % SCRIPT_BODY
SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(SCRIPT_BODY.encode("utf-8")).digest()).decode()
DESC_HTML = {
    "bg": '<meta name="description" content="Безплатна пасивна проверка дали сайтът ви е засегнат от нови пробиви (PHP2Shell и др.) и какво да оправите първо. BoostWorkers Praetorian.">'
          '<link rel="canonical" href="https://boostworkers.com/proveri/">'
          '<meta property="og:title" content="Засегнат ли е сайтът ви от PHP2Shell? Безплатна проверка">'
          '<meta property="og:description" content="Безплатна пасивна проверка за 1 минута и какво да оправите първо. BoostWorkers Praetorian.">'
          '<meta property="og:url" content="https://boostworkers.com/proveri/">'
          '<meta property="og:type" content="website">'
          '<meta property="og:image" content="https://boostworkers.com/assets/praetorian-karta.png">'
          '<meta property="og:image:width" content="1080"><meta property="og:image:height" content="1080">'
          '<meta name="twitter:card" content="summary_large_image">',
    "en": '<meta name="description" content="Free passive check whether your website is affected by new vulnerabilities (PHP2Shell and more) and what to fix first. BoostWorkers Praetorian.">'
          '<link rel="canonical" href="https://boostworkers.com/proveri/?lang=en">'
          '<meta property="og:title" content="Is your website affected by PHP2Shell? Free check">'
          '<meta property="og:description" content="Free passive check in 1 minute and what to fix first. BoostWorkers Praetorian.">'
          '<meta property="og:url" content="https://boostworkers.com/proveri/?lang=en">'
          '<meta property="og:type" content="website">'
          '<meta property="og:image" content="https://boostworkers.com/assets/praetorian-karta.png">'
          '<meta name="twitter:card" content="summary_large_image">',
}
SHARE = {
    "bg": {"btn": "📤 Сподели с приятел", "copied": "✓ Връзката е копирана", "title": "Провери сайта си за пробиви",
           "text": "Безплатна проверка дали сайтът ти е засегнат от новия пробив в PHP (PHP2Shell) — за 1 минута:",
           "or": "или директно:", "url": "https://boostworkers.com/proveri/",
           "after_title": "Помогни и на някой друг",
           "after": "Познаваш ли някого със сайт — фирма, хотел, НПО, лекар, занаятчия? Изпрати му проверката, отнема 1 минута.",
           "after_text": "Току-що проверих сайта си за новия пробив в PHP (PHP2Shell). Безплатно е и отнема 1 минута — провери и твоя:"},
    "en": {"btn": "📤 Share with a friend", "copied": "✓ Link copied", "title": "Check your website for breaches",
           "text": "Free 1-minute check whether your website is affected by the new PHP flaw (PHP2Shell):",
           "or": "or directly:", "url": "https://boostworkers.com/proveri/?lang=en",
           "after_title": "Help someone else too",
           "after": "Know someone with a website — a company, hotel, NGO, doctor, craftsman? Send them the check, it takes 1 minute.",
           "after_text": "I just checked my website for the new PHP flaw (PHP2Shell). It is free and takes 1 minute — check yours:"},
}


SHARE_KANALI = [("Viber", "viber"), ("WhatsApp", "whatsapp"), ("Facebook", "facebook"),
                ("LinkedIn", "linkedin"), ("Telegram", "telegram"), ("Email", "email")]


def share_target(kanal, lang, after):
    t = dict(SHARE[lang])
    if after:
        t["text"] = t["after_text"]
    q = urllib.parse.quote
    msg = t["text"] + " " + t["url"]
    return {
        "viber": "viber://forward?text=" + q(msg),
        "whatsapp": "https://wa.me/?text=" + q(msg),
        "facebook": "https://www.facebook.com/sharer/sharer.php?u=" + q(t["url"]),
        "linkedin": "https://www.linkedin.com/sharing/share-offsite/?url=" + q(t["url"]),
        "telegram": "https://t.me/share/url?url=" + q(t["url"]) + "&text=" + q(t["text"]),
        "email": "mailto:?subject=" + q(t["title"]) + "&body=" + q(msg),
    }.get(kanal)


def share_html(lang, button=True):
    t = dict(SHARE[lang])
    if not button:                      # after a check: personal invitation, the moment people share most
        t["text"] = t["after_text"]
    # each link goes through /s/<channel> on our site: we count the click (anonymously) and redirect
    links = [(n, "%s/s/%s?lang=%s%s" % (poshta.BAZA, k, lang, "" if button else "&a=1")) for n, k in SHARE_KANALI]
    e = html.escape
    btn = ('<button type="button" id="share" data-title="%s" data-text="%s" data-url="%s" data-copied="%s" data-beacon="%s">%s</button>'
           % (e(t["title"]), e(t["text"]), e(t["url"]), e(t["copied"]), e(poshta.BAZA + "/s-native"), e(t["btn"]))) if button else ""
    head = "" if button else '<h2>%s</h2><p>%s</p>' % (e(t["after_title"]), e(t["after"]))
    return (head + '<div class="share">%s<span class="m">%s</span> %s</div>'
            % (btn, e(t["or"]),
               " ".join('<a class="sh" href="%s" rel="noopener" target="_blank">%s</a>' % (e(u), n) for n, u in links)))


WAIT_CHECK = {"bg": "Проверявам… до 30 сек.", "en": "Checking… up to 30 s"}
WAIT_SEND = {"bg": "Изпращам…", "en": "Sending…"}


def _feedback_html(lang, fb_message="", fb_ok=False, base=""):
    t = page_text.FEEDBACK[lang]
    e = html.escape
    if fb_ok:
        body = '<p class="ok">%s</p>' % e(t["thanks"])
    else:
        body = ('<form class="fb" method="post" action="%s/otziv?lang=%s#otziv">'
                '<label>%s<textarea name="message" required maxlength="%d" rows="5"></textarea></label>'
                '<label>%s<input name="name" maxlength="100" autocomplete="name"></label>'
                '<label>%s<input name="email" type="email" maxlength="200" autocomplete="email"></label>'
                '<label class="cb"><input type="checkbox" name="consent" value="1"> %s</label>'
                '<div class="hp" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></div>'
                '<button data-wait="%s">%s</button></form><p class="err">%s</p><p class="m">%s</p>'
                % (e(base), lang, e(t["message"]), FEEDBACK_MAX, e(t["name"]), e(t["email"]), e(t["consent"]),
                   e(WAIT_SEND[lang]), e(t["send"]), e(fb_message), e(t["privacy"])))
    return '<section id="otziv"><h2>%s</h2><p>%s</p>%s</section>' % (e(t["title"]), e(t["intro"]), body)


def _form_page(lang, message="", value="", fb_message="", fb_ok=False, base="", mail_message=""):
    title, label, button, note, _ = FORM[lang]
    other = "en" if lang == "bg" else "bg"
    e = html.escape
    return ('<!doctype html><html lang="%s"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>'
            '%s<style>%s form.chk{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}'
            'input,textarea{flex:1;min-width:220px;padding:12px;font:inherit;font-size:17px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}'
            'button{padding:12px 22px;font-size:17px;background:var(--orange);color:#fff;border:0;border-radius:8px;cursor:pointer}'
            '.err{color:#d64545;font-weight:700}.ok{color:#13a09c;font-weight:700}'
            '.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}'
            '.st{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--orange);border-radius:10px;padding:14px}'
            '.st b{display:block;font-size:18px;margin-bottom:4px}h3{margin:22px 0 6px}'
            'form.fb{display:grid;gap:10px;max-width:640px}form.fb label{display:grid;gap:4px}'
            'form.fb label.cb{display:flex;gap:8px;align-items:flex-start}form.fb label.cb input{flex:none;min-width:0}'
            '.hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}'
            '.share{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 18px}'
            '#share{background:#13a09c;font-weight:700;padding:14px 22px;font-size:18px;width:100%%;max-width:420px}'
            'a.sh{display:inline-block;padding:8px 12px;border:1px solid var(--line);border-radius:99px;text-decoration:none;color:var(--ink);background:var(--card);font-size:15px}'
            '</style></head><body>'
            '<header><div class="w"><div class="m" style="color:#bbb">BoostWorkers · Praetorian</div><h1>%s</h1>'
            '<a href="%s/?lang=%s" style="color:#fff">%s</a></div></header><main class="w">'
            '<form class="chk" method="post" action="%s/?lang=%s"><input name="address" placeholder="example.bg" value="%s" '
            'aria-label="%s" required maxlength="300"><button data-wait="%s">%s</button></form>'
            '<p class="err">%s</p><p class="m">%s</p>%s%s%s%s'
            '<footer>BoostWorkers Praetorian %s · Apache-2.0 · '
            '<a href="https://boostworkers.com">boostworkers.com</a></footer></main>%s</body></html>'
            % (lang, e(title), DESC_HTML[lang], report.CSS, e(title), e(base), other, other.upper(), e(base), lang, e(value), e(label),
               e(WAIT_CHECK[lang]), e(button), e(message), e(note), _poshta_html(lang, base, value, mail_message),
               share_html(lang), page_text.METHOD[lang],
               _feedback_html(lang, fb_message, fb_ok, base), __version__, SCRIPT))


POSHTA = {
    "bg": {"title": "Или: получете отчета на имейл", "intro": "Не искате да чакате? Ще ви изпратим отчета до няколко минути.",
           "address": "Адрес на сайта", "email": "Вашият имейл", "send": "Изпратете ми отчета",
           "consent": "Съгласен/съгласна съм имейлът ми да се ползва за изпращане на този отчет.",
           "novini": "Пишете ми и при нов голям пробив (по желание; може да се откажете с един отговор).",
           "privacy": "Първо ще получите писмо с връзка за потвърждение — без нея нищо не се изпраща. Пазим имейла само за отчета "
                      "(и за новините, ако сте отметнали). Не го даваме на никого. Изтриване: office@kagami.bg.",
           "sent": "Изпратихме писмо за потвърждение на %s. Отворете връзката в него — отчетът идва след това.",
           "bad_email": "Моля, напишете валиден имейл.", "need_consent": "Отметнете съгласието, за да ви изпратим отчета.",
           "email_limit": "За този имейл днес вече има няколко заявки. Опитайте утре.",
           "mail_error": "Не успяхме да изпратим писмото. Пишете ни на office@kagami.bg.",
           "too_many": "Твърде много заявки от вас за последния час. Опитайте по-късно.",
           "ok_title": "Потвърдено!", "ok": "Отчетът за %s ще пристигне на имейла ви до няколко минути. Проверете и папка „Спам“.",
           "bad_link": "Връзката е невалидна или е изтекла (важи 24 часа). Поръчайте отчета отново."},
    "en": {"title": "Or: get the report by email", "intro": "Don't want to wait? We will email you the report within a few minutes.",
           "address": "Website address", "email": "Your email", "send": "Email me the report",
           "consent": "I agree that my email is used to send this report.",
           "novini": "Also write to me when a new big breach comes out (optional; one reply unsubscribes).",
           "privacy": "First you get an email with a confirmation link — nothing is sent without it. We keep the email only for the report "
                      "(and the news, if ticked). We share it with nobody. To delete: office@kagami.bg.",
           "sent": "We sent a confirmation email to %s. Open the link in it — the report follows.",
           "bad_email": "Please enter a valid email.", "need_consent": "Please tick the consent box so we can send the report.",
           "email_limit": "This email already made several requests today. Please try tomorrow.",
           "mail_error": "We could not send the email. Write to office@kagami.bg.",
           "too_many": "Too many requests from you in the last hour. Please try later.",
           "ok_title": "Confirmed!", "ok": "The report for %s will reach your inbox within a few minutes. Check the spam folder too.",
           "bad_link": "The link is invalid or expired (valid for 24 hours). Please request the report again."},
}


def _poshta_html(lang, base, value="", message=""):
    t = POSHTA[lang]
    e = html.escape
    return ('<section id="poshta"><h2>%s</h2><p>%s</p>'
            '<form class="fb" method="post" action="%s/poshta?lang=%s#poshta">'
            '<label>%s<input name="address" placeholder="example.bg" value="%s" required maxlength="300"></label>'
            '<label>%s<input name="email" type="email" required maxlength="200" autocomplete="email"></label>'
            '<label class="cb"><input type="checkbox" name="consent" value="1" required> %s</label>'
            '<label class="cb"><input type="checkbox" name="novini" value="1"> %s</label>'
            '<div class="hp" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></div>'
            '<button data-wait="%s">%s</button></form><p class="err">%s</p><p class="m">%s</p></section>'
            % (e(t["title"]), e(t["intro"]), e(base), lang, e(t["address"]), e(value), e(t["email"]), e(t["consent"]),
               e(t["novini"]), e(WAIT_SEND[lang]), e(t["send"]), e(message), e(t["privacy"])))


def _message_page(lang, base, title, text):
    e = html.escape
    return ('<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="robots" content="noindex"><title>%s</title><style>%s</style></head><body>'
            '<header><div class="w"><div class="m" style="color:#bbb">BoostWorkers · Praetorian</div><h1>%s</h1></div></header>'
            '<main class="w"><p style="font-size:18px">%s</p><p><a href="%s/?lang=%s">%s</a></p>%s</main></body></html>'
            % (lang, e(title), report.CSS, e(title), e(text), e(base), lang,
               e("← Към проверката" if lang == "bg" else "← Back to the check"), share_html(lang, button=False)))


# --- feedback ------------------------------------------------------------------

FEEDBACK_MAX = 3000
FEEDBACK_PER_IP_HOUR = 3
DATA_DIR = os.environ.get("PRAETORIAN_DATA", os.path.join(os.path.expanduser("~"), "praetorian_danni"))
_fb_hits = {}


def _fb_allowed(ip):
    now = time.time()
    with _lock:
        hits = [t for t in _fb_hits.get(ip, []) if now - t < 3600]
        if len(hits) >= FEEDBACK_PER_IP_HOUR:
            _fb_hits[ip] = hits
            return False
        hits.append(now)
        _fb_hits[ip] = hits
        return True


def save_feedback(form, lang):
    """Validate and append one message. Returns (ok, error_text)."""
    t = page_text.FEEDBACK[lang]
    first = lambda k: form.get(k, [""])[0].strip()
    if first("website"):          # honeypot filled in: a bot; pretend success, keep nothing
        return True, ""
    message = first("message")[:FEEDBACK_MAX]
    if not message:
        return False, t["empty"]
    email = first("email")[:200]
    if email and first("consent") != "1":
        return False, t["need_consent"]
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "lang": lang, "message": message,
           "name": first("name")[:100], "email": email, "consent": bool(email)}
    try:
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        with _lock, open(os.path.join(DATA_DIR, "otzivi.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        return False, t["error"]
    return True, ""


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    lang = "en" if qs.get("lang", ["bg"])[0] == "en" else "bg"
    headers = [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
               ("X-Frame-Options", "DENY"),
               ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src '%s'; connect-src 'self'; form-action 'self'" % SCRIPT_HASH)]

    base = environ.get("SCRIPT_NAME", "").rstrip("/")
    if method == "GET" and base and path == "":
        q = environ.get("QUERY_STRING", "")
        start_response("301 Moved Permanently", [("Location", base + "/" + ("?" + q if q else "")),
                                                 ("Content-Length", "0")])
        return [b""]

    def send(status, body, ctype="text/html; charset=utf-8", index=False):
        data = body.encode("utf-8")
        robots = [] if index else [("X-Robots-Tag", "noindex")]   # only the public form page is indexed
        start_response(status, [("Content-Type", ctype), ("Content-Length", str(len(data)))] + headers + robots)
        return [data]

    # --- worker API (GX10): take the queue, give back results -----------------------
    if path.rstrip("/").endswith("/api/rabotnik/opashka") or path.rstrip("/").endswith("/api/rabotnik/rezultat"):
        if not poshta.proveri_kluch(DATA_DIR, environ.get("HTTP_X_PRAETORIAN_KEY")):
            return send("403 Forbidden", json.dumps({"error": "key"}), "application/json")
        if path.rstrip("/").endswith("/opashka"):
            return send("200 OK", json.dumps(poshta.za_rabotnika(DATA_DIR), ensure_ascii=False), "application/json; charset=utf-8")
        try:
            size = min(int(environ.get("CONTENT_LENGTH") or 0), 2_000_000)
            d = json.loads(environ["wsgi.input"].read(size).decode("utf-8"))
            z = poshta.cheti(DATA_DIR, d["id"])
            res = d.get("rezultat")
            if res:
                ok = poshta.rezultat(DATA_DIR, z["id"], res, report.page(res, z["lang"], _cards,
                                     extra_html=share_html(z["lang"], button=False)), report.text(res, z["lang"], _cards))
                if ok:
                    broyach.zapishi(DATA_DIR, "poshta_izprateni")
                    broyach.sait(DATA_DIR, res, "imeil")
            else:
                ok = poshta.rezultat(DATA_DIR, z["id"], None, None, None,
                                     greshka=_err(str(d.get("greshka") or "check failed"), z["lang"]))
        except Exception as ex:
            return send("400 Bad Request", json.dumps({"error": str(ex)[:200]}), "application/json")
        return send("200 OK", json.dumps({"ok": ok}), "application/json")

    if path.rstrip("/").endswith("/api/rabotnik/broyach"):
        if not poshta.proveri_kluch(DATA_DIR, environ.get("HTTP_X_PRAETORIAN_KEY")):
            return send("403 Forbidden", json.dumps({"error": "key"}), "application/json")
        den = qs.get("den", [""])[0] or None
        if den and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", den):
            den = None
        return send("200 OK", json.dumps({"broyach": broyach.cheti(DATA_DIR, den), "saitove": broyach.saitove(DATA_DIR, den)},
                                         ensure_ascii=False), "application/json; charset=utf-8")

    ms = re.search(r"/s/([a-z]+)$", path.rstrip("/"))
    if ms:                                                  # share click: count, then go to the channel
        cel = share_target(ms.group(1), lang, qs.get("a", [""])[0] == "1")
        if not cel:
            return send("404 Not Found", "")
        broyach.zapishi(DATA_DIR, "spodelyane", kanal=ms.group(1))
        start_response("302 Found", [("Location", cel), ("Content-Length", "0"), ("X-Robots-Tag", "noindex")])
        return [b""]
    if path.rstrip("/").endswith("/s-native"):              # the phone share sheet (counted by a beacon)
        broyach.zapishi(DATA_DIR, "spodelyane", kanal="telefon")
        return send("204 No Content", "")

    if path.rstrip("/").endswith("/potvardi"):
        z = poshta.potvardi(DATA_DIR, qs.get("id", [""])[0], qs.get("t", [""])[0])
        t = POSHTA[lang]
        if not z:
            return send("200 OK", _message_page(lang, base, "Praetorian", t["bad_link"]))
        broyach.zapishi(DATA_DIR, "poshta_potvardeni")
        return send("200 OK", _message_page(lang, base, t["ok_title"], t["ok"] % z["address"]))

    if path.rstrip("/").endswith("/api/check"):
        address = qs.get("address", [""])[0]
        if not _allowed(_client_ip(environ)):
            return send("429 Too Many Requests", json.dumps({"error": "rate limit"}), "application/json")
        try:
            res = run_check(address)
        except remote.CheckError as e:
            return send("400 Bad Request", json.dumps({"error": str(e)}), "application/json")
        except Busy:
            return send("503 Service Unavailable", json.dumps({"error": "busy, try again in a minute"}), "application/json")
        return send("200 OK", json.dumps(res, ensure_ascii=False), "application/json; charset=utf-8")

    if method == "POST":
        try:
            size = min(int(environ.get("CONTENT_LENGTH") or 0), 20000)
        except ValueError:
            size = 0
        ctype = environ.get("CONTENT_TYPE", "")
        if not ctype.startswith("application/x-www-form-urlencoded"):
            return send("415 Unsupported Media Type", _form_page(lang, base=base))
        form = urllib.parse.parse_qs(environ["wsgi.input"].read(size).decode("utf-8", "replace"))

        if path.rstrip("/").endswith("/poshta"):
            t = POSHTA[lang]
            first = lambda k: form.get(k, [""])[0].strip()
            address, email = first("address"), first("email")
            if first("website"):                         # honeypot: a bot
                return send("200 OK", _message_page(lang, base, "Praetorian", t["sent"] % ""))
            if not _fb_allowed("m:" + _client_ip(environ)):
                return send("429 Too Many Requests", _form_page(lang, base=base, value=address, mail_message=t["too_many"]))
            try:
                remote.normalize(address)
            except remote.CheckError as ex:
                return send("200 OK", _form_page(lang, base=base, value=address, mail_message=_err(str(ex), lang)))
            if not poshta.validen_email(email):
                return send("200 OK", _form_page(lang, base=base, value=address, mail_message=t["bad_email"]))
            if first("consent") != "1":
                return send("200 OK", _form_page(lang, base=base, value=address, mail_message=t["need_consent"]))
            ok, kl = poshta.nova(DATA_DIR, address, email, lang, novini=first("novini") == "1")
            if not ok:
                return send("200 OK", _form_page(lang, base=base, value=address, mail_message=t[kl]))
            broyach.zapishi(DATA_DIR, "poshta_zayavki")
            return send("200 OK", _message_page(lang, base, "Praetorian", t["sent"] % email))

        if path.rstrip("/").endswith("/otziv"):
            if not _fb_allowed(_client_ip(environ)):
                return send("429 Too Many Requests", _form_page(lang, fb_message=page_text.FEEDBACK[lang]["too_many"], base=base))
            ok, err = save_feedback(form, lang)
            if ok:
                broyach.zapishi(DATA_DIR, "otzivi")
            return send("200 OK", _form_page(lang, fb_message=err, fb_ok=ok, base=base))

        address = form.get("address", [""])[0].strip()
        if not _allowed(_client_ip(environ)):
            return send("429 Too Many Requests", _form_page(lang, FORM[lang][4], address, base=base))
        try:
            res = run_check(address)
        except remote.CheckError as e:
            return send("200 OK", _form_page(lang, _err(str(e), lang), address, base=base))
        except Busy:
            broyach.zapishi(DATA_DIR, "zaeto")
            return send("200 OK", _form_page(lang, BUSY[lang], address, base=base))
        broyach.zapishi(DATA_DIR, "proverki")
        broyach.sait(DATA_DIR, res, "onlain")
        return send("200 OK", report.page(res, lang, _cards, back_url=base + "/?lang=" + lang,
                                              extra_html=share_html(lang, button=False)))

    if method == "GET" and path in ("", "/"):
        broyach.zapishi(DATA_DIR, "posetenia", ref=environ.get("HTTP_REFERER", ""))
    return send("200 OK", _form_page(lang, base=base), index=(method == "GET"))


if __name__ == "__main__":
    import sys
    from wsgiref.simple_server import make_server
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print("http://127.0.0.1:%d" % port)
    make_server("127.0.0.1", port, app).serve_forever()
