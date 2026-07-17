"""Déduplication approximative cross-source.

La dédup exacte (même source + même URL) est déjà gérée par `Database.upsert`
via l'ID (hash source+url). Ici on gère le cas où la MÊME actualité/CVE est
reprise par PLUSIEURS sources avec des titres légèrement différents
(ex: une CVE citée par NVD ET par ZDI, une news reprise par The Hacker News
ET BleepingComputer).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rapidfuzz import fuzz

from cyberwatch.core.database import Database
from cyberwatch.core.models import WatchItem


def find_near_duplicates(
    items: list[WatchItem],
    db: Database,
    threshold: float = 0.85,
    lookback_hours: int = 48,
) -> list[WatchItem]:
    """Retire de `items` ceux qui recoupent fortement un item déjà en base
    récemment (même CVE, ou titre très similaire). Les CVE partagées entre
    deux WatchItem distincts (ex: NVD + ZDI sur la même faille) sont
    considérées comme des doublons de contenu, pas de simples doublons
    d'URL, donc on les fusionne côté notification plutôt que de les
    dupliquer dans le flux utilisateur.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    existing = db.all_titles_since(since)
    if not existing:
        return items

    existing_titles = [t for _, t in existing]

    unique: list[WatchItem] = []
    for item in items:
        # priorité 1 : recoupement par CVE déjà connue et déjà notifiée
        if item.cve_ids and _cve_already_covered(item.cve_ids, db):
            item.tags.append("duplicate-cve")
            continue

        # priorité 2 : similarité de titre (news reprises telles quelles)
        best_score = max(
            (fuzz.token_sort_ratio(item.title, t) / 100 for t in existing_titles),
            default=0.0,
        )
        if best_score >= threshold:
            item.tags.append("near-duplicate")
            continue

        unique.append(item)
        existing_titles.append(item.title)  # évite les doublons intra-batch aussi

    return unique


def _cve_already_covered(cve_ids: list[str], db: Database) -> bool:
    """Vérifie si une des CVE de l'item est déjà couverte par un item
    existant en base (peu importe la source)."""
    with db.engine.connect() as conn:
        from sqlalchemy import select

        from cyberwatch.core.database import watch_items

        rows = conn.execute(
            select(watch_items.c.cve_ids).where(watch_items.c.cve_ids.is_not(None))
        ).all()
    import json

    for (raw,) in rows:
        try:
            existing_cves = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            continue
        if set(existing_cves) & set(cve_ids):
            return True
    return False
