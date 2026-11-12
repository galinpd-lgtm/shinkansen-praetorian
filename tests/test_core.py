import unittest

from praetorian import cards, remote, report, versions, local


class Versions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(versions.parse("PHP/7.4.33-nmm1"), (7, 4, 33))
        self.assertIsNone(versions.parse("nginx"))

    def test_cmp(self):
        self.assertEqual(versions.cmp((8, 4), (8, 4, 0)), 0)
        self.assertEqual(versions.cmp((8, 4, 26), (8, 4, 27)), -1)


class Cards(unittest.TestCase):
    card = cards.load_cards()[0]

    def a(self, v):
        return cards.assess(self.card, "php", v)[0]

    def test_php2shell(self):
        self.assertEqual(self.a("8.4.26"), cards.AFFECTED)
        self.assertEqual(self.a("8.4.27"), cards.PATCHED)
        self.assertEqual(self.a("8.2.35"), cards.PATCHED)
        self.assertEqual(self.a("8.5.11"), cards.AFFECTED)
        self.assertEqual(self.a("7.4.33"), cards.VENDOR)
        self.assertEqual(self.a("8.1.2"), cards.VENDOR)
        self.assertEqual(self.a("5.3.29"), cards.NOT_AFFECTED)
        self.assertEqual(self.a("8.6.0"), cards.PATCHED)
        self.assertEqual(self.a(None), cards.LIKELY)

    def test_other_product(self):
        self.assertEqual(cards.assess(self.card, "nginx", "1.2")[0], cards.NOT_AFFECTED)


class Detect(unittest.TestCase):
    def resp(self, headers=None, body="", cookies=None):
        return {"headers": headers or {}, "body": body, "set_cookie": cookies or []}

    def test_powered_by(self):
        f = remote.detect(self.resp({"x-powered-by": "PHP/8.4.26"}))
        self.assertEqual(f["php"]["version"], "8.4.26")

    def test_wordpress_implies_php(self):
        body = '<meta name="generator" content="WordPress 6.0.3" /><script src="/wp-includes/js/x.js?ver=6.0.3">'
        f = remote.detect(self.resp(body=body))
        self.assertEqual(f["wordpress"]["version"], "6.0.3")
        self.assertIn("php", f)
        self.assertIsNone(f["php"]["version"])

    def test_static(self):
        self.assertEqual(remote.detect(self.resp({"server": "LiteSpeed"}, "<html>hi</html>")),
                         {"litespeed": {"version": None, "evidence": "Server: LiteSpeed"}})


class Safety(unittest.TestCase):
    def test_internal_blocked(self):
        for addr in ("http://127.0.0.1", "http://localhost", "http://10.0.0.1", "http://169.254.169.254",
                     "http://[::1]", "http://192.168.1.1"):
            with self.assertRaises(remote.CheckError):
                s, h, p = remote.normalize(addr)
                remote.public_ip(h)

    def test_ports_and_schemes(self):
        for addr in ("ftp://example.com", "http://example.com:8080", "http://u:p@example.com"):
            with self.assertRaises(remote.CheckError):
                remote.normalize(addr)


class Reports(unittest.TestCase):
    def test_render(self):
        rep = {"edition": "online", "tool_version": "t", "checked_at": "now", "final_url": "https://x",
               "software": [{"product": "php", "version": "8.4.26", "evidence": "<b>"}],
               "cards": [{"card": "2026-10-php2shell", "status": cards.AFFECTED, "detail": "", "evidence": "<x>"}],
               "basics": {"https": True, "cert_days_left": 50, "missing_headers": []}}
        for lang in ("bg", "en"):
            h = report.page(rep, lang)
            self.assertNotIn("<x>", h)
            self.assertIn("PHP2Shell", h)
            self.assertTrue(report.text(rep, lang))

    def test_compare(self):
        b = {"software": [{"product": "php", "version": "8.4.26", "path": "/p"}],
             "cards": [{"card": "c", "status": "affected", "evidence": "e"}]}
        a = {"software": [{"product": "php", "version": "8.4.27", "path": "/p"}],
             "cards": [{"card": "c", "status": "patched", "evidence": "e"}]}
        d = local.compare(b, a)
        self.assertEqual(d["software"][0]["after"], "8.4.27")
        self.assertEqual(d["cards"][0]["after"], "patched")


class Popravki2026_11_10(unittest.TestCase):
    """С1–С4 (10.11.2026): honest request count, no visitor path, safe email, consent and retention."""

    def test_visitor_path_is_dropped(self):
        from praetorian import remote
        self.assertEqual(remote.normalize("example.com/.env"), ("https", "example.com", "/"))
        self.assertEqual(remote.normalize("http://example.com/wp-login.php?x=1"), ("http", "example.com", "/"))
        self.assertEqual(remote.normalize("https://example.com/en/", keep_path=True)[2], "/en/")

    def test_request_count_matches_the_text(self):
        from praetorian import remote, page_text
        calls = []
        def fake(scheme, host, path, deadline=None):
            calls.append(path)
            n = len(calls)
            if n <= remote.MAX_REDIRECTS:
                return {"status": 302, "headers": {"location": "/r%d" % n}, "set_cookie": [], "body": "", "cert": None, "tls": None}
            return {"status": 200, "headers": {}, "set_cookie": [], "body": "<html>wp-content/</html>", "cert": None, "tls": None}
        old, oldsleep = remote.fetch, remote.time.sleep
        remote.fetch, remote.time.sleep = fake, lambda s: None
        try:
            remote.check("example.com/secret-path", None, [])
        finally:
            remote.fetch, remote.time.sleep = old, oldsleep
        self.assertEqual(calls[0], "/")                       # never the path typed by the visitor
        self.assertLessEqual(len(calls), 6)
        self.assertEqual(len(calls), 6)                       # worst case: 1 + 4 redirects + feed
        for lang in ("bg", "en"):
            self.assertIn("6", page_text.METHOD[lang])
            self.assertNotIn("3 ordinary requests, with", page_text.METHOD[lang])
            self.assertNotIn("Най-много 3", page_text.METHOD[lang])

    def test_email_text_consent_and_limits(self):
        import tempfile, os
        from praetorian import poshta
        d = tempfile.mkdtemp()
        sent = []
        old = poshta.izprati
        poshta.izprati = lambda do, tema, text, html_=None: sent.append((do, tema, text))
        try:
            ok, _ = poshta.nova(d, "example.com", "a@b.bg", "bg", novini=True, saglasie_tekst="Съгласен съм")
            self.assertTrue(ok)
            zid = [f[:-5] for f in os.listdir(poshta.papka(d)) if f.endswith(".json")][0]
            z = poshta.cheti(d, zid)
            self.assertFalse(z["novini"])                     # no news list exists, so nothing is collected for it
            self.assertEqual(z["saglasie"]["versia"], poshta.SAGLASIE_VERSIA)
            self.assertEqual(z["saglasie"]["tekst"], "Съгласен съм")
            self.assertGreater(z["saglasie"]["chas"], 0)
            for lang in ("bg", "en"):
                self.assertNotIn("безплатна", poshta.TXT[lang]["otchet_kraj"])
                self.assertNotIn("free", poshta.TXT[lang]["otchet_kraj"])
                self.assertIn("boostworkers.com/uslugi/", poshta.TXT[lang]["otchet_kraj"])
            oldcap = poshta.PER_DAY_ALL
            poshta.PER_DAY_ALL = 3
            try:
                poshta.nova(d, "example.com", "c@d.bg", "bg")
                poshta.nova(d, "example.com", "e@f.bg", "bg")
                self.assertEqual(poshta.nova(d, "example.com", "g@h.bg", "bg"), (False, "day_limit"))
            finally:
                poshta.PER_DAY_ALL = oldcap
        finally:
            poshta.izprati = old

    def test_form_takes_only_an_existing_host(self):
        import io, tempfile
        from praetorian import web, poshta, remote
        d = tempfile.mkdtemp()
        sent = []
        old = (poshta.izprati, remote.public_ip, web.DATA_DIR)
        poshta.izprati = lambda do, tema, text, html_=None: sent.append((do, tema, text))
        web.DATA_DIR = d
        def post(address):
            body = ("address=%s&email=a%%40b.bg&consent=1&novini=1" % address).encode()
            env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/poshta", "QUERY_STRING": "lang=bg", "REMOTE_ADDR": "198.51.100.%d" % (len(sent) + 7),
                   "CONTENT_TYPE": "application/x-www-form-urlencoded", "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
            return b"".join(web.app(env, lambda s, h: None)).decode("utf-8")
        try:
            remote.public_ip = lambda host: "93.184.216.34"
            post("example.com/KUPETE-EVTINO-TUK")
            self.assertEqual(len(sent), 1)
            self.assertNotIn("KUPETE", sent[0][1] + sent[0][2])   # the visitor's text never reaches the email
            self.assertIn("example.com", sent[0][1])
            def nyama(host):
                raise remote.CheckError("the address does not exist (DNS)")
            remote.public_ip = nyama
            post("nyama-takav-sait.example")
            self.assertEqual(len(sent), 1)                        # no email for a site that does not exist
            page = b"".join(web.app({"REQUEST_METHOD": "GET", "PATH_INFO": "/", "QUERY_STRING": ""}, lambda s, h: None)).decode("utf-8")
            self.assertNotIn('name="novini"', page)
            self.assertIn("3 месеца", page)
        finally:
            poshta.izprati, remote.public_ip, web.DATA_DIR = old

    def test_retention_three_months(self):
        import tempfile, os, json, time
        from praetorian import poshta, web
        d = tempfile.mkdtemp()
        old = poshta.izprati
        poshta.izprati = lambda *a, **k: None
        try:
            poshta.nova(d, "example.com", "a@b.bg", "bg")
        finally:
            poshta.izprati = old
        zid = [f[:-5] for f in os.listdir(poshta.papka(d)) if f.endswith(".json")][0]
        self.assertEqual(poshta.zalichi_stari(d, sega=time.time() + 80 * 86400), 0)
        os.remove(os.path.join(poshta.papka(d), ".zalichavane"))
        self.assertEqual(poshta.zalichi_stari(d, sega=time.time() + 91 * 86400), 1)
        z = poshta.cheti(d, zid)
        self.assertNotIn("email", z); self.assertNotIn("email_hash", z); self.assertNotIn("token", z)
        self.assertEqual(z["address"], "example.com")             # the statistics stay
        self.assertIsNone(poshta.potvardi(d, zid, ""))             # an erased request cannot be confirmed
        self.assertEqual(poshta.zalichi_stari(d, sega=time.time() + 92 * 86400), 0)   # once a day at most
        with open(os.path.join(d, "otzivi.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"time": "2026-07-01T10:00:00", "lang": "bg", "message": "стар", "name": "Иван", "email": "i@x.bg", "consent": True}, ensure_ascii=False) + "\n")
            f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "lang": "bg", "message": "нов", "name": "Мария", "email": "m@x.bg", "consent": True}, ensure_ascii=False) + "\n")
        self.assertEqual(web.zalichi_otzivi(d), 1)
        recs = [json.loads(x) for x in open(os.path.join(d, "otzivi.jsonl"), encoding="utf-8").read().splitlines()]
        self.assertEqual((recs[0]["name"], recs[0]["email"], recs[0]["message"]), ("", "", "стар"))
        self.assertEqual(recs[1]["name"], "Мария")

    def test_small_defects(self):
        """С10: bad port → clear error; total time budget; key with other alphabets; confirmation counted once."""
        import tempfile, os, time
        from praetorian import remote, poshta
        for addr in ("example.com:abc", "example.com:99999", "http://[::1"):
            with self.assertRaises(remote.CheckError):
                remote.normalize(addr)
        with self.assertRaises(remote.CheckError):
            remote.fetch("https", "example.com", "/", deadline=time.time() - 1)     # no time left → no request at all
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "rabotnik.key"), "w", encoding="utf-8") as f:
            f.write("s3cret-key\n")
        self.assertFalse(poshta.proveri_kluch(d, "ключ"))
        self.assertTrue(poshta.proveri_kluch(d, "s3cret-key"))
        old = poshta.izprati
        poshta.izprati = lambda *a, **k: None
        try:
            poshta.nova(d, "example.com", "a@b.bg", "bg")
        finally:
            poshta.izprati = old
        zid = [f[:-5] for f in os.listdir(poshta.papka(d)) if f.endswith(".json")][0]
        tok = poshta.cheti(d, zid)["token"]
        self.assertTrue(poshta.potvardi(d, zid, tok)["_sega"])
        self.assertFalse(poshta.potvardi(d, zid, tok)["_sega"])                      # second opening: same page, not counted
        self.assertNotIn("_sega", poshta.cheti(d, zid))


if __name__ == "__main__":
    unittest.main()


class Packages(unittest.TestCase):
    def test_vendor_packages(self):
        from praetorian import inventory
        card = cards.load_cards()[0]
        inv = {"os": {"product": "ubuntu", "version": "24.04"}, "packages": [
            {"manager": "dpkg", "name": "php8.3-fpm", "version": "8.3.6-0ubuntu0.24.04.12", "source": "php8.3"},
            {"manager": "rpm", "name": "ea-php84-php-cli", "version": "8.4.26-1", "source": "ea-php84-php-cli"}]}
        old_ge, old_rpm = inventory.deb_version_ge, inventory.rpm_changelog_has
        try:
            inventory.deb_version_ge = lambda a, b: a >= b
            inventory.rpm_changelog_has = lambda p, w: True
            res = local.package_results(card, inv)
        finally:
            inventory.deb_version_ge, inventory.rpm_changelog_has = old_ge, old_rpm
        self.assertEqual([r["status"] for r in res], [cards.AFFECTED, cards.PATCHED])


class Feedback(unittest.TestCase):
    def setUp(self):
        import tempfile
        from praetorian import web
        self.web = web
        self.dir = tempfile.mkdtemp()
        web.DATA_DIR = self.dir
        web._fb_hits.clear()

    def post(self, body, ip="9.9.9.9"):
        import io
        out = {}
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/otziv", "QUERY_STRING": "lang=bg",
               "wsgi.input": io.BytesIO(body.encode()), "CONTENT_LENGTH": str(len(body.encode())),
               "CONTENT_TYPE": "application/x-www-form-urlencoded", "REMOTE_ADDR": ip}
        page = b"".join(self.web.app(env, lambda s, h: out.update(s=s))).decode()
        return out["s"], page

    def lines(self):
        import os
        p = os.path.join(self.dir, "otzivi.jsonl")
        return open(p, encoding="utf-8").read().splitlines() if os.path.exists(p) else []

    def test_flow(self):
        s, p = self.post("message=%D0%97%D0%B4%D1%80%D0%B0%D0%B2%D0%B5%D0%B9")
        self.assertIn("Благодарим", p)
        self.assertEqual(len(self.lines()), 1)
        s, p = self.post("message=x&website=spam", ip="1.1.1.2")   # honeypot
        self.assertEqual(len(self.lines()), 1)
        s, p = self.post("message=x&email=a%40b.bg", ip="1.1.1.3")  # no consent
        self.assertIn("съгласието", p)
        self.assertEqual(len(self.lines()), 1)
        for _ in range(3):
            s, p = self.post("message=y", ip="1.1.1.4")
        self.assertEqual(self.post("message=y", ip="1.1.1.4")[0], "429 Too Many Requests")

    def test_page_has_method(self):
        import io
        out = {}
        env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "QUERY_STRING": "lang=en", "REMOTE_ADDR": "1"}
        page = b"".join(self.web.app(env, lambda s, h: out.update(s=s))).decode()
        self.assertIn("the method", page)
        self.assertIn("Advice, questions and comments", page)

    def test_unknown_address_is_404(self):
        out = {}
        env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/no-such-page", "QUERY_STRING": "lang=en",
               "SCRIPT_NAME": "/proveri", "REMOTE_ADDR": "1"}
        page = b"".join(self.web.app(env, lambda s, h: out.update(s=s, h=dict(h)))).decode()
        self.assertTrue(out["s"].startswith("404"))
        self.assertEqual(out["h"].get("X-Robots-Tag"), "noindex")
        self.assertIn("This page does not exist.", page)


class Priorities(unittest.TestCase):
    def test_list(self):
        rep = {"cards": [{"card": "2026-10-php2shell", "status": cards.LIKELY}],
               "software": [{"product": "wordpress", "version": "5.7.20", "latest": "7.1.3", "eol": {"ended": False}}],
               "basics": {"https": True, "cert_days_left": 10, "missing_headers": ["strict-transport-security"]}}
        todo = report.priorities(rep, "bg")
        self.assertEqual(len(todo), 4)
        self.assertIn("5.7.20", todo[1])
        self.assertEqual(report.priorities({"cards": [], "software": [], "basics": {"https": True, "missing_headers": []}}), [])


class Parallel(unittest.TestCase):
    def test_cap(self):
        import tempfile
        from praetorian import web
        web.SLOT_DIR = tempfile.mkdtemp()
        held = [web._Slot().__enter__() for _ in range(web.MAX_PARALLEL)]
        with self.assertRaises(web.Busy):
            web._Slot().__enter__()
        for s in held:
            s.__exit__(None, None, None)
        s = web._Slot().__enter__()
        s.__exit__(None, None, None)


class Poshta(unittest.TestCase):
    def test_flow(self):
        import tempfile, json, io
        from praetorian import poshta, web
        d = tempfile.mkdtemp()
        sent = []
        poshta.izprati = lambda do, tema, text, html_=None: sent.append((do, tema, bool(html_)))
        ok, _ = poshta.nova(d, "example.com", "a@b.bg", "bg")
        self.assertTrue(ok)
        self.assertEqual(sent[-1][0], "a@b.bg")
        zid = [f[:-5] for f in __import__("os").listdir(poshta.papka(d)) if f.endswith(".json")][0]
        z = poshta.cheti(d, zid)
        self.assertIsNone(poshta.potvardi(d, zid, "wrong"))
        self.assertEqual(poshta.potvardi(d, zid, z["token"])["status"], "potvardena")
        q = poshta.za_rabotnika(d)
        self.assertEqual(q[0]["address"], "example.com")
        self.assertEqual(poshta.za_rabotnika(d), [])           # already taken
        self.assertTrue(poshta.rezultat(d, zid, {"cards": []}, "<html></html>", "txt"))
        self.assertTrue(sent[-1][2])                           # report has HTML
        self.assertEqual(poshta.cheti(d, zid)["status"], "izpratena")
        for _ in range(3):
            poshta.nova(d, "example.com", "x@y.bg", "bg")
        self.assertEqual(poshta.nova(d, "example.com", "x@y.bg", "bg"), (False, "email_limit"))

    def test_key(self):
        import tempfile, os
        from praetorian import poshta
        d = tempfile.mkdtemp()
        self.assertFalse(poshta.proveri_kluch(d, "abc"))
        open(os.path.join(d, "rabotnik.key"), "w").write("s3cret\n")
        self.assertTrue(poshta.proveri_kluch(d, "s3cret"))
        self.assertFalse(poshta.proveri_kluch(d, "nope"))


class Broyach(unittest.TestCase):
    def test_counts(self):
        import tempfile
        from praetorian import broyach
        d = tempfile.mkdtemp()
        broyach.zapishi(d, "posetenia", ref="https://l.facebook.com/l.php?u=x")
        broyach.zapishi(d, "posetenia", ref="https://www.linkedin.com/feed/")
        broyach.zapishi(d, "spodelyane", kanal="viber")
        s = list(broyach.cheti(d).values())[0]
        self.assertEqual(s["posetenia"], 2)
        self.assertEqual(s["ot"], {"facebook.com": 1, "linkedin.com": 1})
        self.assertEqual(s["kanali"], {"viber": 1})
