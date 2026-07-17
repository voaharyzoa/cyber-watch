"""Normalisation et enrichissement des scores CVSS.

Ne s'applique qu'aux WatchItem de type VULNERABILITY : les autres types
(news, updates, threat intel) n'ont pas de notion de CVSS.
"""
from __future__ import annotations

from cyberwatch.core.models import ItemType, Severity, WatchItem

# mots-clés indiquant une exploitation active, utile pour prioriser même
# quand le score CVSS brut ne le reflète pas encore (0-day fraîche par ex.)
EXPLOITED_KEYWORDS = (
    "exploited in the wild",
    "actively exploited",
    "exploitation détectée",
    "zero-day",
    "0-day",
    "kev catalog",
)


def enrich(item: WatchItem) -> WatchItem:
    if item.type != ItemType.VULNERABILITY:
        return item

    if item.severity is None:
        item.severity = Severity.from_cvss(item.cvss_score)

    text = f"{item.title} {item.summary or ''}".lower()
    if any(kw in text for kw in EXPLOITED_KEYWORDS):
        item.exploited_in_wild = True
        # une vuln activement exploitée est traitée comme critique côté
        # notification temps réel, même si le CVSS brut est plus bas
        if item.severity and item.severity.rank < Severity.CRITICAL.rank:
            item.tags.append("exploited-boost")

    return item


def enrich_batch(items: list[WatchItem]) -> list[WatchItem]:
    return [enrich(i) for i in items]
