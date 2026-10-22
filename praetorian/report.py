"""Human reports in Bulgarian and English: plain text and one self-contained HTML page."""

import html

from . import cards as C
from . import versions

STATUS = {
    "bg": {C.AFFECTED: "ЗАСЕГНАТ", C.PATCHED: "поправен", C.VENDOR: "зависи от хостинга",
           C.LIKELY: "вероятно засегнат", C.NOT_AFFECTED: "не е засегнат",
           C.NOT_VISIBLE: "не личи отвън"},
    "en": {C.AFFECTED: "AFFECTED", C.PATCHED: "patched", C.VENDOR: "depends on your host",
           C.LIKELY: "likely affected", C.NOT_AFFECTED: "not affected",
           C.NOT_VISIBLE: "not visible from outside"},
}
COLOR = {C.AFFECTED: "#d64545", C.VENDOR: "#e08a1e", C.LIKELY: "#e08a1e",
         C.PATCHED: "#13a09c", C.NOT_AFFECTED: "#13a09c", C.NOT_VISIBLE: "#6b7685"}

T = {
    "bg": {
        "title_online": "Проверка на сайт за пробиви",
        "title_local": "Опис на версиите и проверка за пробиви",
        "checked": "Проверено", "address": "Адрес", "host": "Машина",
        "cards": "Известни пробиви", "software": "Какво се вижда", "basics": "Основна защита",
        "libs": "Библиотеки с известни слабости",
        "product": "Софтуер", "version": "Версия", "where": "Откъде / къде",
        "support": "Поддръжка", "ended": "без поддръжка", "ok": "поддържа се",
        "behind": "има по-нова", "latest": "последна", "unknown": "не личи",
        "what": "Какво е", "fix": "Какво да направиш", "temp": "Временни мерки",
        "letter": "Писмо до хостинга (копирай)", "sources": "Източници",
        "https": "HTTPS", "cert": "Сертификатът изтича след (дни)",
        "missing": "Липсващи защитни заглавки", "none": "няма", "yes": "да", "no": "НЕ",
        "kev": "Активно използвани слабости в този софтуер през последната година (CISA)",
        "online_note": "Проверката е пасивна: видяхме само каквото вижда всеки посетител. "
                       "Точният отговор за PHP и пакетите дава хостингът или версията за сваляне.",
        "local_note": "Описът е направен на самата машина. Нищо не е променено и нищо не е изпратено, "
                      "освен имената и версиите на библиотеките към OSV (ако не е изключено).",
        "help": "Искате да го направим ние? BoostWorkers поправя и наблюдава — boostworkers.com",
        "diff": "Преди → след",
        "distro": "пакет на %s — кръпките идват със системните обновления",
    },
    "en": {
        "title_online": "Website breach check",
        "title_local": "Version inventory and breach check",
        "checked": "Checked", "address": "Address", "host": "Machine",
        "cards": "Known breaches", "software": "What is visible", "basics": "Basic protection",
        "libs": "Libraries with known vulnerabilities",
        "product": "Software", "version": "Version", "where": "Seen from / location",
        "support": "Support", "ended": "end of life", "ok": "supported",
        "behind": "newer available", "latest": "latest", "unknown": "not visible",
        "what": "What it is", "fix": "What to do", "temp": "Temporary measures",
        "letter": "Letter to your host (copy)", "sources": "Sources",
        "https": "HTTPS", "cert": "Certificate expires in (days)",
        "missing": "Missing security headers", "none": "none", "yes": "yes", "no": "NO",
        "kev": "Actively exploited flaws in this software during the last year (CISA)",
        "online_note": "This check is passive: we saw only what every visitor sees. "
                       "The exact answer for PHP and packages comes from your host or the downloadable edition.",
        "local_note": "The inventory was made on the machine itself. Nothing was changed and nothing was sent, "
                      "except library names and versions to OSV (unless switched off).",
        "help": "Want us to do it? BoostWorkers fixes and monitors — boostworkers.com",
        "diff": "Before → after",
        "distro": "%s package — fixes arrive with the system updates",
    },
}


def _support(s, t):
    e = s.get("eol")
    if s.get("distro"):
        return t["distro"] % s["distro"]
    parts = []
    if e:
        parts.append(t["ended"] if e["ended"] else t["ok"])
        if e.get("behind") and e.get("latest") and not s.get("latest"):
            parts.append("%s %s: %s" % (t["behind"], t["latest"], e["latest"]))
    newest = s.get("latest")
    v, n = versions.parse(s.get("version")), versions.parse(newest)
    if v and n and versions.cmp(v, n) < 0:
        parts.append("%s: %s" % (t["latest"], newest))
    return ", ".join(parts)


def text(rep, lang="bg", card_list=None):
    t = T[lang]
    cmap = {c["id"]: c for c in (card_list or C.load_cards())}
    lines = []
    title = t["title_online"] if rep["edition"] == "online" else t["title_local"]
    lines.append("== %s ==" % title)
    target = rep.get("final_url") or rep.get("host")
    lines.append("%s: %s   %s: %s" % (t["address"] if rep["edition"] == "online" else t["host"],
                                     target, t["checked"], rep["checked_at"]))
    lines.append("")
    lines.append("-- %s --" % t["cards"])
    for r in rep["cards"]:
        card = cmap.get(r["card"], {})
        lines.append("  [%s] %s %s  %s" % (STATUS[lang][r["status"]], card.get("name", r["card"]),
                                          " ".join(card.get("cve", [])), r.get("evidence", "")))
        if r["status"] in (C.AFFECTED, C.VENDOR, C.LIKELY) and card:
            lines.append("      -> " + card["text"][lang]["fix"])
    lines.append("")
    lines.append("-- %s --" % t["software"])
    for s in rep["software"]:
        lines.append("  %-14s %-12s %s  %s" % (s["product"], s.get("version") or t["unknown"],
                                               _support(s, t), s.get("path") or s.get("evidence", "")))
    if rep["edition"] == "online":
        b = rep["basics"]
        lines.append("")
        lines.append("-- %s --" % t["basics"])
        lines.append("  %s: %s" % (t["https"], t["yes"] if b["https"] else t["no"]))
        if b.get("cert_days_left") is not None:
            lines.append("  %s: %s" % (t["cert"], b["cert_days_left"]))
        lines.append("  %s: %s" % (t["missing"], ", ".join(b["missing_headers"]) or t["none"]))
    else:
        lines.append("")
        lines.append("-- %s: %d / %d --" % (t["libs"], len(rep["libraries_vulnerable"]),
                                            rep["libraries_total"]))
        for x in rep["libraries_vulnerable"][:50]:
            lines.append("  %s %s %s: %s" % (x["ecosystem"], x["name"], x["version"], ", ".join(x["vulns"][:5])))
    lines.append("")
    lines.append(t["online_note"] if rep["edition"] == "online" else t["local_note"])
    lines.append(t["help"])
    return "\n".join(lines)


CSS = """:root{--ink:#1c2533;--mute:#6b7685;--line:#e3e7ee;--bg:#f6f8fb;--card:#fff;--dark:#151515;--orange:#fc6a3e}
@media (prefers-color-scheme:dark){:root{--ink:#e6ebf2;--mute:#9aa6b6;--line:#2a3547;--bg:#0d1522;--card:#142033}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 Montserrat,"Segoe UI",system-ui,sans-serif}
header{background:var(--dark);color:#fff;padding:28px 16px}.w{max-width:960px;margin:0 auto;padding:0 16px}header .w{padding:0}
h1{margin:6px 0;font-size:clamp(22px,4.5vw,32px)}h2{font-size:20px;margin:28px 0 10px}
.b{display:inline-block;color:#fff;font-weight:700;font-size:13px;padding:3px 10px;border-radius:99px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--dark);color:#fff}.tw{overflow-x:auto}.m{color:var(--mute);font-size:14px}
pre{white-space:pre-wrap;background:var(--bg);border:1px solid var(--line);padding:10px;border-radius:8px;font-size:14px}
footer{color:var(--mute);font-size:13px;margin:30px 0}a{color:var(--orange)}"""


def page(rep, lang="bg", card_list=None, diff=None):
    t = T[lang]
    e = html.escape
    cmap = {c["id"]: c for c in (card_list or C.load_cards())}
    online = rep["edition"] == "online"
    title = t["title_online"] if online else t["title_local"]
    target = rep.get("final_url") or rep.get("host", "")
    out = ['<!doctype html><html lang="%s"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           '<meta name="robots" content="noindex"><title>%s</title><style>%s</style></head><body>'
           % (lang, e(title), CSS)]
    out.append('<header><div class="w"><div class="m" style="color:#bbb">BoostWorkers</div>'
               '<h1>%s</h1><div>%s · %s: %s</div></div></header><main class="w">'
               % (e(title), e(target), e(t["checked"]), e(rep["checked_at"])))

    out.append("<h2>%s</h2>" % e(t["cards"]))
    for r in rep["cards"]:
        card = cmap.get(r["card"], {})
        tx = card.get("text", {}).get(lang, {})
        out.append('<div class="card"><span class="b" style="background:%s">%s</span> '
                   '<b>%s</b> <span class="m">%s · CVSS %s</span>'
                   % (COLOR[r["status"]], e(STATUS[lang][r["status"]]), e(card.get("name", r["card"])),
                      e(" ".join(card.get("cve", []))), e(card.get("cvss", ""))))
        if r.get("evidence"):
            out.append('<div class="m">%s</div>' % e(r["evidence"]))
        if tx:
            out.append("<p><b>%s:</b> %s</p>" % (e(t["what"]), e(tx["what"])))
            if r["status"] in (C.AFFECTED, C.VENDOR, C.LIKELY):
                out.append("<p><b>%s:</b> %s</p>" % (e(t["fix"]), e(tx["fix"])))
                out.append("<p><b>%s:</b></p><ul>%s</ul>" % (e(t["temp"]), "".join("<li>%s</li>" % e(x) for x in tx["temp"])))
                out.append("<p><b>%s:</b></p><pre>%s</pre>" % (e(t["letter"]), e(tx["hosting_letter"])))
            out.append('<div class="m">%s: %s</div>' % (e(t["sources"]), " · ".join(
                '<a href="%s" rel="noopener">%s</a>' % (e(s), e(s.split("/")[2])) for s in card.get("sources", []))))
        out.append("</div>")

    out.append("<h2>%s</h2><div class='tw'><table><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>"
               % (e(t["software"]), e(t["product"]), e(t["version"]), e(t["support"]), e(t["where"])))
    for s in rep["software"]:
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(s["product"]), e(s.get("version") or t["unknown"]), e(_support(s, t)),
            e(s.get("path") or s.get("evidence", ""))))
        if s.get("kev_recent"):
            out.append('<tr><td></td><td colspan="3" class="m">%s: %s</td></tr>' % (
                e(t["kev"]), e(", ".join(k["cve"] for k in s["kev_recent"]))))
    out.append("</table></div>")

    if online:
        b = rep["basics"]
        out.append("<h2>%s</h2><div class='card'>%s: <b>%s</b><br>" % (
            e(t["basics"]), e(t["https"]), e(t["yes"] if b["https"] else t["no"])))
        if b.get("cert_days_left") is not None:
            out.append("%s: <b>%s</b><br>" % (e(t["cert"]), b["cert_days_left"]))
        out.append("%s: %s</div>" % (e(t["missing"]), e(", ".join(b["missing_headers"]) or t["none"])))
    else:
        out.append("<h2>%s: %d / %d</h2>" % (e(t["libs"]), len(rep["libraries_vulnerable"]), rep["libraries_total"]))
        if rep["libraries_vulnerable"]:
            out.append("<div class='tw'><table>")
            for x in rep["libraries_vulnerable"][:200]:
                out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    e(x["ecosystem"]), e(x["name"]), e(x["version"]), e(", ".join(x["vulns"][:8]))))
            out.append("</table></div>")

    if diff:
        out.append("<h2>%s</h2><div class='tw'><table>" % e(t["diff"]))
        for d in diff["software"] + diff["cards"]:
            out.append("<tr><td>%s</td><td>%s</td><td>%s → %s</td></tr>" % (
                e(d.get("product") or d.get("card")), e(d["where"]), e(str(d["before"])), e(str(d["after"]))))
        out.append("</table></div>")

    out.append('<p class="m">%s</p><p><b>%s</b></p>' % (e(t["online_note"] if online else t["local_note"]), e(t["help"])))
    out.append('<footer>BoostWorkers Praetorian %s · Apache-2.0</footer></main></body></html>' % e(rep["tool_version"]))
    return "".join(out)
