"""Evaluate a local inventory against breach cards and open sources."""

import time

from . import __version__, cards, inventory


def check(paths=None, src=None, card_list=None):
    card_list = card_list if card_list is not None else cards.load_cards()
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    inv = inventory.collect(paths)

    software = []
    for item in inv["software"]:
        s = dict(item)
        if src and s.get("version"):
            s["eol"] = src.eol(s["product"], s["version"])
            kev = src.kev(s["product"])
            if kev:
                s["kev_recent"] = kev[:10]
            if s["product"] == "wordpress":
                s["latest"] = src.wordpress_latest()
        software.append(s)

    results = []
    for card in card_list:
        hits = [s for s in software if s["product"] == card["product"]]
        if not hits:
            results.append({"card": card["id"], "status": cards.NOT_AFFECTED,
                            "detail": "software not found", "evidence": ""})
        for s in hits:
            status, detail = cards.assess(card, s["product"], s.get("version"))
            if s.get("distro") and status == cards.AFFECTED:
                status = cards.VENDOR
                detail = ("%s package: the fix may be backported; update with the system updates "
                          "and check the package changelog" % s["distro"])
            results.append({"card": card["id"], "status": status, "detail": detail,
                            "evidence": "%s %s (%s)" % (s["product"], s.get("version"), s.get("path"))})
        results += package_results(card, inv)

    libs = inv["libraries"]
    if src and libs:
        found = src.osv([(x["ecosystem"], x["name"], x["version"]) for x in libs])
        for i, ids in found.items():
            libs[i]["vulns"] = ids
    vulnerable_libs, seen = [], set()
    for x in libs:
        k = (x["ecosystem"], x["name"], x["version"])
        if x.get("vulns") and k not in seen:
            seen.add(k)
            vulnerable_libs.append(x)

    return {
        "edition": "local",
        "tool_version": __version__,
        "checked_at": started,
        "host": inv["host"],
        "os": inv["os"],
        "paths": inv["paths"],
        "software": software,
        "cards": results,
        "libraries_total": len(libs),
        "libraries_vulnerable": vulnerable_libs,
        "source_errors": src.errors if src else [],
    }


def package_results(card, inv):
    """Exact answer from the package manager, where the card knows the vendor fix."""
    out = []
    if card.get("product") != "php":
        return out
    osi = inv.get("os") or {}
    deb_fixed = card.get("vendor_fixed_deb", {}).get("%s:%s" % (osi.get("product"), osi.get("version")), {})
    seen = set()
    for p in inv.get("packages", []):
        if p["manager"] == "dpkg":
            if p["source"] in seen:
                continue
            seen.add(p["source"])
            fixed = deb_fixed.get(p["source"])
            if not fixed:
                status, detail = cards.VENDOR, "no vendor fix listed for this distribution yet"
            else:
                ok = inventory.deb_version_ge(p["version"], fixed)
                status = cards.LIKELY if ok is None else (cards.PATCHED if ok else cards.AFFECTED)
                detail = "vendor fix " + fixed
        else:
            has = inventory.rpm_changelog_has(p["name"], card["cve"])
            status = cards.LIKELY if has is None else (cards.PATCHED if has else cards.AFFECTED)
            detail = "package changelog %s the CVE" % ("mentions" if has else "does not mention")
        out.append({"card": card["id"], "status": status, "detail": detail,
                    "evidence": "package %s %s" % (p["name"], p["version"])})
    return out


def compare(before, after):
    """'Before -> after' difference between two reports of the same target."""
    def key(s):
        return (s["product"], s.get("path") or s.get("evidence") or "")

    b = {key(s): s.get("version") for s in before.get("software", [])}
    a = {key(s): s.get("version") for s in after.get("software", [])}
    changes = []
    for k in sorted(set(b) | set(a)):
        if b.get(k) != a.get(k):
            changes.append({"product": k[0], "where": k[1], "before": b.get(k), "after": a.get(k)})

    def card_status(rep):
        return {(c["card"], c.get("evidence", "")): c["status"] for c in rep.get("cards", [])}

    cb, ca = card_status(before), card_status(after)
    card_changes = [{"card": k[0], "where": k[1], "before": cb.get(k), "after": ca.get(k)}
                    for k in sorted(set(cb) | set(ca)) if cb.get(k) != ca.get(k)]
    return {"software": changes, "cards": card_changes,
            "before_at": before.get("checked_at"), "after_at": after.get("checked_at")}
