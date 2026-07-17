"""Persistance SQLite (via SQLAlchemy Core) pour tous les WatchItem.

Une seule table `watch_items` pour vulnérabilités + news + updates + intel,
avec un index sur (type, published_at) pour requêter facilement par flux.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    select,
)
from sqlalchemy.engine import Engine

from cyberwatch.core.models import ItemType, Severity, WatchItem

log = logging.getLogger(__name__)

metadata = MetaData()

watch_items = Table(
    "watch_items",
    metadata,
    Column("id", String(24), primary_key=True),
    Column("source", String(64), nullable=False),
    Column("type", String(32), nullable=False),
    Column("title", Text, nullable=False),
    Column("url", Text, nullable=False),
    Column("published_at", DateTime(timezone=True), nullable=False),
    Column("fetched_at", DateTime(timezone=True), nullable=False),
    Column("summary", Text, nullable=True),
    Column("severity", String(16), nullable=True),
    Column("cve_ids", Text, nullable=True),           # JSON list
    Column("cvss_score", Float, nullable=True),
    Column("cvss_vector", String(128), nullable=True),
    Column("tags", Text, nullable=True),               # JSON list
    Column("affected_products", Text, nullable=True),  # JSON list
    Column("exploited_in_wild", Boolean, default=False),
    Column("raw", Text, nullable=True),                # JSON dump
    Column("notified_realtime", Boolean, default=False),
    Column("notified_digest", Boolean, default=False),
    Index("ix_watch_items_type_published", "type", "published_at"),
    Index("ix_watch_items_severity", "severity"),
)


class Database:
    def __init__(self, db_path: str | Path = "data/watch.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(f"sqlite:///{self.db_path}", future=True)
        metadata.create_all(self.engine)

    def exists(self, item_id: str) -> bool:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(watch_items.c.id).where(watch_items.c.id == item_id)
            ).first()
            return row is not None

    def upsert(self, item: WatchItem) -> bool:
        """Insère un WatchItem s'il n'existe pas déjà. Retourne True si nouveau."""
        if self.exists(item.id):
            return False

        payload = {
            "id": item.id,
            "source": item.source,
            "type": item.type.value,
            "title": item.title,
            "url": item.url,
            "published_at": item.published_at,
            "fetched_at": item.fetched_at,
            "summary": item.summary,
            "severity": item.severity.value if item.severity else None,
            "cve_ids": json.dumps(item.cve_ids),
            "cvss_score": item.cvss_score,
            "cvss_vector": item.cvss_vector,
            "tags": json.dumps(item.tags),
            "affected_products": json.dumps(item.affected_products),
            "exploited_in_wild": item.exploited_in_wild,
            "raw": json.dumps(item.raw) if item.raw else None,
            "notified_realtime": False,
            "notified_digest": False,
        }
        with self.engine.begin() as conn:
            conn.execute(watch_items.insert().values(**payload))
        return True

    def bulk_upsert(self, items: Iterable[WatchItem]) -> list[WatchItem]:
        """Insère une liste de WatchItem, retourne uniquement les nouveaux."""
        new_items = []
        for item in items:
            if self.upsert(item):
                new_items.append(item)
        return new_items

    def pending_realtime(self, min_severity: Severity = Severity.HIGH) -> list[dict]:
        """Items critiques/high pas encore notifiés en temps réel."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(watch_items).where(
                    watch_items.c.notified_realtime.is_(False),
                    watch_items.c.severity.in_(
                        [s.value for s in Severity if s.rank >= min_severity.rank]
                    ),
                )
            ).mappings().all()
        return [dict(r) for r in rows]

    def pending_digest(self, types: Optional[list[ItemType]] = None) -> list[dict]:
        """Items pas encore inclus dans un digest, filtrés par type si fourni."""
        stmt = select(watch_items).where(watch_items.c.notified_digest.is_(False))
        if types:
            stmt = stmt.where(watch_items.c.type.in_([t.value for t in types]))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [dict(r) for r in rows]

    def mark_notified(self, item_ids: list[str], channel: str) -> None:
        column = {
            "realtime": watch_items.c.notified_realtime,
            "digest": watch_items.c.notified_digest,
        }[channel]
        if not item_ids:
            return
        with self.engine.begin() as conn:
            conn.execute(
                watch_items.update()
                .where(watch_items.c.id.in_(item_ids))
                .values(**{column.name: True})
            )

    def recent(self, limit: int = 50, item_type: Optional[ItemType] = None) -> list[dict]:
        stmt = select(watch_items).order_by(watch_items.c.published_at.desc()).limit(limit)
        if item_type:
            stmt = stmt.where(watch_items.c.type == item_type.value)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [dict(r) for r in rows]

    def all_titles_since(self, since: datetime) -> list[tuple[str, str]]:
        """Retourne (id, title) pour la dédup approximative cross-source."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(watch_items.c.id, watch_items.c.title).where(
                    watch_items.c.fetched_at >= since
                )
            ).all()
        return [(r[0], r[1]) for r in rows]
