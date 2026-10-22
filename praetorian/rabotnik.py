"""Worker for "report by email": takes confirmed requests from the web server, checks, returns results.

  PRAETORIAN_SERVER=https://boostworkers.com/proveri  python -m praetorian.rabotnik

The key is read from ~/.config/praetorian/rabotnik.key (same value as $PRAETORIAN_DATA/rabotnik.key
on the web server). Checks run one by one, with pauses; internal network addresses are refused
by remote.py exactly as on the web.
"""

import json
import os
import sys
import time
import urllib.request

from . import cards, remote
from .sources import Sources

SERVER = os.environ.get("PRAETORIAN_SERVER", "https://boostworkers.com/proveri").rstrip("/")
KEY_FILE = os.environ.get("PRAETORIAN_KEY_FILE", os.path.expanduser("~/.config/praetorian/rabotnik.key"))
UA = "BoostWorkers-Praetorian-worker"


def _req(method, path, body=None):
    with open(KEY_FILE, encoding="utf-8") as f:
        key = f.read().strip()
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    r = urllib.request.Request(SERVER + path, data=data, method=method,
                               headers={"X-Praetorian-Key": key, "User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    queue = _req("GET", "/api/rabotnik/opashka")
    if not queue:
        return 0
    card_list = cards.load_cards()
    for z in queue:
        try:
            res = remote.check(z["address"], Sources(), card_list)
            body = {"id": z["id"], "rezultat": res}
        except remote.CheckError as e:
            body = {"id": z["id"], "greshka": str(e)}
        except Exception as e:  # never leave a request hanging silently
            body = {"id": z["id"], "greshka": "the site did not answer: %s" % e.__class__.__name__}
        otg = _req("POST", "/api/rabotnik/rezultat", body)
        print(time.strftime("%Y-%m-%d %H:%M"), z["id"][:8], z["address"], "ok" if otg.get("ok") else otg)
        time.sleep(2)                                   # gentle with other people's sites
    return 0


if __name__ == "__main__":
    sys.exit(main())
