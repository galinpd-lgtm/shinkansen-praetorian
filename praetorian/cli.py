"""Command line.

  praetorian site example.com            passive check of a website
  praetorian server [--path /var/www]    full version inventory of this machine
  praetorian compare before.json after.json
"""

import argparse
import json
import sys
import time

from . import __version__, cards, local, remote, report
from .sources import Sources


def _save(rep, prefix, lang, diff=None):
    stamp = time.strftime("%Y-%m-%d_%H%M")
    jpath = "%s_%s.json" % (prefix, stamp)
    hpath = "%s_%s.html" % (prefix, stamp)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    with open(hpath, "w", encoding="utf-8") as f:
        f.write(report.page(rep, lang, diff=diff))
    return jpath, hpath


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(prog="praetorian", description="BoostWorkers Praetorian " + __version__)
    p.add_argument("--lang", choices=["bg", "en"], default="bg")
    p.add_argument("--offline", action="store_true", help="use only the breach cards and the cache")
    p.add_argument("--no-osv", action="store_true", help="do not send library names to OSV")
    p.add_argument("--out", default="praetorian", help="file name prefix for the JSON and HTML report")
    sub = p.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("site", help="passive check of a public website")
    s1.add_argument("address")
    s2 = sub.add_parser("server", help="version inventory of this machine")
    s2.add_argument("--path", action="append", help="folder with websites/apps (repeatable)")
    s3 = sub.add_parser("compare", help="before -> after")
    s3.add_argument("before")
    s3.add_argument("after")
    a = p.parse_args(argv)

    src = Sources(offline=a.offline, ask_osv=not a.no_osv)
    if a.cmd == "site":
        try:
            rep = remote.check(a.address, src)
        except remote.CheckError as e:
            print("error:", e)
            return 2
    elif a.cmd == "server":
        rep = local.check(a.path, src)
    else:
        with open(a.before, encoding="utf-8") as f:
            before = json.load(f)
        with open(a.after, encoding="utf-8") as f:
            after = json.load(f)
        diff = local.compare(before, after)
        jpath, hpath = _save(after, a.out + "_compare", a.lang, diff=diff)
        print(json.dumps(diff, ensure_ascii=False, indent=2))
        print("\n->", hpath)
        return 0

    print(report.text(rep, a.lang))
    jpath, hpath = _save(rep, a.out, a.lang)
    print("\n->", jpath, "\n->", hpath)
    worst = {c["status"] for c in rep["cards"]}
    return 1 if cards.AFFECTED in worst else 0


if __name__ == "__main__":
    sys.exit(main())
