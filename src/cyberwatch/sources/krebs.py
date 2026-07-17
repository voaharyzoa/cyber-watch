"""Source Krebs on Security - actu cyber d'investigation, via RSS."""
from __future__ import annotations

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class KrebsSource(BaseSource):
    item_type = ItemType.SECURITY_NEWS

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.feed_url = self.params.get("feed_url", "https://krebsonsecurity.com/feed/")

    def fetch(self) -> list[WatchItem]:
        entries = parse_feed(self.feed_url)
        return [
            WatchItem(
                source=self.name,
                type=self.item_type,
                title=entry.title,
                url=entry.link,
                published_at=entry.published_at,
                summary=strip_html(entry.summary)[:500],
                cve_ids=entry.cve_ids,
                tags=["news", "investigation"],
            )
            for entry in entries
        ]
