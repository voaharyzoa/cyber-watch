"""Compile les WatchItem en attente sur une période et les envoie groupés.

Sépare le "signal fort" (vulnérabilités critiques, threat intel) qui part
en temps réel, du "bruit de fond" utile (news, updates, advisories vendors)
qui part en digest pour ne pas noyer les alertes importantes.
"""
from __future__ import annotations

import logging
from datetime import datetime

from cyberwatch.core.database import Database
from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.notifiers.base import BaseNotifier

log = logging.getLogger(__name__)


class DigestBuilder:
    def __init__(self, db: Database, notifiers: dict[str, BaseNotifier]) -> None:
        self.db = db
        self.notifiers = notifiers

    def build_and_send(
        self,
        types: list[ItemType],
        channels: list[str],
        title: str | None = None,
    ) -> int:
        rows = self.db.pending_digest(types=types)
        if not rows:
            log.info("Digest: rien à envoyer pour %s", [t.value for t in types])
            return 0

        items = [self._row_to_item(r) for r in rows]
        digest_title = title or f"Veille cyber - {datetime.now().strftime('%d/%m/%Y')}"

        for channel in channels:
            notifier = self.notifiers.get(channel)
            if not notifier:
                log.warning("Notifier '%s' non configuré, digest ignoré pour ce canal", channel)
                continue
            notifier.send_digest(items, digest_title)

        self.db.mark_notified([i.id for i in items], channel="digest")
        log.info("Digest envoyé: %d items sur %d canaux", len(items), len(channels))
        return len(items)

    @staticmethod
    def _row_to_item(row: dict) -> WatchItem:
        import json

        return WatchItem(
            id=row["id"],
            source=row["source"],
            type=ItemType(row["type"]),
            title=row["title"],
            url=row["url"],
            published_at=row["published_at"],
            fetched_at=row["fetched_at"],
            summary=row["summary"],
            cve_ids=json.loads(row["cve_ids"]) if row["cve_ids"] else [],
            cvss_score=row["cvss_score"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
        )
