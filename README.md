# BoostWorkers Praetorian

**Free breach checks for websites and servers.** When a big new vulnerability comes out, Praetorian tells a website owner — in plain words — whether they are affected and what to do.

*[Български — по-долу](#български)*

Two editions, one engine and the same "breach cards":

| | **Online** — check by address | **Local** — full version inventory |
|---|---|---|
| Who runs it | anyone, for any public website | the owner, on their own server |
| What it sees | only what every visitor sees (passive) | everything installed: OS, PHP/Python/Node, web server, databases, WordPress/Joomla/Drupal/Moodle/Nextcloud, Docker images, libraries in `composer.lock` / `package-lock.json` / `requirements.txt` |
| Compares with | breach cards | breach cards + [endoflife.date](https://endoflife.date) + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) + [OSV](https://osv.dev) |
| Your data | only the address | **stays on your machine** |

## Quick start

Python 3.9+ and nothing else (standard library only).

```bash
git clone https://github.com/galinpd-lgtm/shinkansen-praetorian
cd shinkansen-praetorian

# passive check of a website
python -m praetorian site example.com

# inventory of this server (read-only)
python -m praetorian server --path /var/www --path /home

# English report, no network at all, or no library lookups
python -m praetorian --lang en server
python -m praetorian --offline server
python -m praetorian --no-osv server

# before -> after (after you fixed something)
python -m praetorian compare praetorian_2026-10-22_0900.json praetorian_2026-10-23_0900.json
```

Each run writes a JSON file (for machines) and an HTML report (for people). Exit code `1` means "affected by a known breach".

## What it never does

- no login attempts, no exploit payloads, no port scans, no load (pauses between requests);
- the online edition makes at most 3 ordinary GET requests and refuses internal network addresses;
- the local edition only reads: it changes nothing, uploads nothing; the only data sent out is library names and versions to OSV (`--no-osv` switches this off).

## Breach cards

One JSON file per incident in [`praetorian/cards/`](praetorian/cards). The first one is **PHP2Shell** (CVE-2026-109618, CVE-2026-109619, 21 Oct 2026). A card says which software and versions are affected, which versions fix it, how to fix it, temporary measures and a ready letter to the hosting company — in Bulgarian and English. Pull requests with new cards are welcome; every claim needs a primary source.

Notes on accuracy:
- Linux distributions (Ubuntu, Debian, RHEL family) patch packages without changing the version number. For those Praetorian says "depends on your vendor" instead of "affected".
- The online check can only say "likely" when a site hides its PHP version — the exact answer comes from your host or from the local edition.

## Run the online edition yourself

```bash
python -m praetorian.web 8080      # http://127.0.0.1:8080
```

`praetorian.web:app` is a plain WSGI app (works with Passenger, gunicorn, uWSGI). Built-in limits: 10 checks per visitor per hour, each site at most once per 15 minutes.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Made in Varna by [BoostWorkers](https://boostworkers.com) (KAGAMI Ltd). Need it fixed and watched for you? That is what we do.

---

## Български

**Безплатна проверка за пробиви на сайтове и сървъри.** Когато излезе нов голям пробив, Praetorian казва на собственика на прост език дали е засегнат и какво да направи.

- **Онлайн:** пасивна проверка по адрес, само каквото вижда всеки посетител.
- **На вашия сървър:** пълен опис на версиите (ОС, PHP, уеб сървър, бази, WordPress и др., Docker, библиотеки). Сравнява се с картите на пробива, датите за край на поддръжката, каталога на CISA и OSV. Данните остават при вас.

```bash
python -m praetorian site example.bg
python -m praetorian server --path /home
```

Отчетът е на български по подразбиране (`--lang en` за английски). Ако искате ние да го поправим и наблюдаваме — [boostworkers.com](https://boostworkers.com).
