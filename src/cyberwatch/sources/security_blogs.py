"""Source générique pour les blogs sécurité vendors (Talos, Google TAG,
Unit42, etc.). Utilisée à la fois pour `advisory_vendor` et `threat_intel`
selon ce qui est déclaré dans sources.yaml pour chaque instance.
"""
from __future__ import annotations

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class SecurityBlogsSource(BaseSource):
    # valeur par défaut, écrasée dynamiquement par le scheduler à partir
    # du `type:` déclaré dans sources.yaml pour cette instance précise
    item_type = ItemType.ADVISORY_VENDOR

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.feed_url = self.params["feed_url"]

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
                tags=["vendor-blog"],
            )
            for entry in entries
        ]
