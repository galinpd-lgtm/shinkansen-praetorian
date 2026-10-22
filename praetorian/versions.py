"""Version parsing and comparison (no external dependencies)."""

import re

_NUM = re.compile(r"\d+(?:\.\d+)*")


def parse(text):
    """Return the leading dotted version as a tuple of ints, or None.

    '8.4.26' -> (8, 4, 26); 'PHP/7.4.33-nmm1' -> (7, 4, 33); 'nginx' -> None
    """
    if not text:
        return None
    m = _NUM.search(str(text))
    if not m:
        return None
    return tuple(int(p) for p in m.group(0).split("."))


def fmt(v):
    return ".".join(str(p) for p in v) if v else ""


def cmp(a, b):
    """Compare two version tuples, padding with zeros."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def branch_of(v, size=2):
    return v[:size]


def in_branch(v, branch):
    """True when version v belongs to branch string like '8.4'."""
    b = parse(branch)
    return b is not None and v[: len(b)] == b


def best_cycle(v, cycles):
    """Pick the most specific endoflife.date cycle that matches version v."""
    best = None
    for c in cycles:
        cv = parse(str(c.get("cycle", "")))
        if cv and v[: len(cv)] == cv:
            if best is None or len(cv) > len(parse(str(best["cycle"]))):
                best = c
    return best
