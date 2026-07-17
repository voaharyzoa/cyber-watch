"""Tagging léger par mots-clés pour les items non-vulnérabilité (news,
updates, threat intel). Permet de filtrer/router les notifications sans
dépendre d'un vrai modèle NLP.
"""
from __future__ import annotations

import re

from cyberwatch.core.models import WatchItem

KEYWORD_TAGS: dict[str, tuple[str, ...]] = {
    "ransomware": ("ransomware", "rançongiciel", "lockbit", "conti", "revil"),
    "supply-chain": ("supply chain", "supply-chain", "chaîne d'approvisionnement"),
    "phishing": ("phishing", "hameçonnage", "spear-phishing"),
    "apt": ("apt", "advanced persistent threat", "nation-state", "état-nation"),
    "data-breach": ("data breach", "fuite de données", "leaked database"),
    "0day": ("zero-day", "0-day", "0day"),
    "ddos": ("ddos", "denial of service", "déni de service"),
    "malware": ("malware", "trojan", "backdoor", "rootkit", "botnet"),
    "critical-infra": ("scada", "ics", "critical infrastructure", "infrastructure critique"),
}


def classify(item: WatchItem) -> WatchItem:
    text = f"{item.title} {item.summary or ''}".lower()
    new_tags = set(item.tags)
    for tag, keywords in KEYWORD_TAGS.items():
        if any(re.search(re.escape(kw), text) for kw in keywords):
            new_tags.add(tag)
    item.tags = sorted(new_tags)
    return item


def classify_batch(items: list[WatchItem]) -> list[WatchItem]:
    return [classify(i) for i in items]
