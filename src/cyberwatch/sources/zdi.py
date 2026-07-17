"""Source ZDI (Zero Day Initiative) - advisories publiés, via RSS."""
from __future__ import annotations

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class ZdiSource(BaseSource):
    item_type = ItemType.VULNERABILITY

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.feed_url = self.params.get(
            "feed_url", "https://www.zerodayinitiative.com/rss/published/"
        )

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
                    cve_ids=entry.cve_ids,
                    tags=["zdi"],
                )
            )
        return items
