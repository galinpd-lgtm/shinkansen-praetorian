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
