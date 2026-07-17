"""Source générique d'actualités cybersécurité (The Hacker News,
BleepingComputer, etc.) - factorisable à n'importe quel flux RSS d'actu.
"""
from __future__ import annotations

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class HackerNewsSecSource(BaseSource):
    item_type = ItemType.SECURITY_NEWS

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.feed_url = self.params["feed_url"]  # obligatoire, pas de défaut générique

    def fetch(self) -> list[WatchItem]:
        entries = parse_feed(self.feed_url)
        items: list[WatchItem] = []
        for entry in entries:
            items.append(
                WatchItem(
                    source=self.name,
                    type=self.item_type,
                    title=entry.title,
                    url=entry.link,
                    published_at=entry.published_at,
                    summary=strip_html(entry.summary)[:500],
                    cve_ids=entry.cve_ids,  # une news cite parfois des CVE, utile pour le cross-link
                    tags=["news"],
                )
            )
        return items
