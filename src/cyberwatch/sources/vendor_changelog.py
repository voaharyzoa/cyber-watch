"""Source de mises à jour produit pour les vendors qui publient un flux
RSS de changelog/PSIRT dédié (ex: Cisco PSIRT, Fortinet PSIRT). Une seule
instance peut agréger plusieurs flux vendors via `params.feeds`.
"""
from __future__ import annotations

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class VendorChangelogSource(BaseSource):
    item_type = ItemType.PRODUCT_UPDATE

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        # liste de {"name": ..., "url": ...}
        self.feeds: list[dict] = self.params.get("feeds", [])

    def fetch(self) -> list[WatchItem]:
        items: list[WatchItem] = []
        for feed in self.feeds:
            vendor_name = feed.get("name", self.name)
            url = feed.get("url")
            if not url:
                continue
            for entry in parse_feed(url):
                items.append(
                    WatchItem(
                        source=self.name,
                        type=self.item_type,
                        title=f"[{vendor_name}] {entry.title}",
                        url=entry.link,
                        published_at=entry.published_at,
                        summary=strip_html(entry.summary)[:500],
                        cve_ids=entry.cve_ids,
                        affected_products=[vendor_name],
                        tags=["vendor-changelog", vendor_name],
                    )
                )
        return items
