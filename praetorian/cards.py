"""Breach cards: one JSON file per incident, shared by both editions."""

import json
import os

from . import versions

CARDS_DIR = os.path.join(os.path.dirname(__file__), "cards")

# Statuses (same words in both editions)
AFFECTED = "affected"          # version is known and vulnerable
PATCHED = "patched"            # version is known and fixed
VENDOR = "check_vendor"        # branch has no official fix: depends on the vendor package
LIKELY = "likely"              # software is present, version not visible
NOT_AFFECTED = "not_affected"  # version is older than the first affected one or other software
NOT_VISIBLE = "not_visible"    # nothing visible from outside


def load_cards(directory=CARDS_DIR):
    cards = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            with open(os.path.join(directory, name), encoding="utf-8") as f:
                cards.append(json.load(f))
    return cards


def assess(card, product, version_text):
    """Assess one software version against one card.

    Returns (status, detail).
    """
    if product != card["product"]:
        return NOT_AFFECTED, ""
    v = versions.parse(version_text)
    if not v:
        return LIKELY, "version unknown"
    low = versions.parse(card.get("min_affected", "0"))
    if low and versions.cmp(v, low) < 0:
        return NOT_AFFECTED, "older than the first affected version"
    for branch, fixed in card.get("fixed", {}).items():
        if versions.in_branch(v, branch):
            if versions.cmp(v, versions.parse(fixed)) >= 0:
                return PATCHED, "fixed in " + fixed
            return AFFECTED, "fixed in " + fixed
    below = versions.parse(card.get("vendor_only_below", "0"))
    if below and versions.cmp(v[: len(below)], below) < 0:
        return VENDOR, "no official release for this branch"
    # newer branch than any listed fix: treat as patched
    newest = max((versions.parse(b) for b in card.get("fixed", {})), default=None)
    if newest and versions.cmp(v[: len(newest)], newest) > 0:
        return PATCHED, "newer branch"
    return LIKELY, "branch not listed"
