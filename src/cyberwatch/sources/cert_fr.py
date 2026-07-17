"""Source CERT-FR - avis et alertes de sécurité, via RSS."""
from __future__ import annotations

from cyberwatch.core.models import ItemType, Severity, WatchItem
from cyberwatch.parsers.rss_parser import parse_feed, strip_html
from cyberwatch.sources.base import BaseSource


class CertFrSource(BaseSource):
    item_type = ItemType.VULNERABILITY

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.feed_url = self.params.get(
            "feed_url", "https://www.cert.ssi.gouv.fr/avis/feed/"
        )
        self.alerte_feed_url = self.params.get(
            "alerte_feed_url", "https://www.cert.ssi.gouv.fr/alerte/feed/"
        )

    def fetch(self) -> list[WatchItem]:
        items: list[WatchItem] = []
        # les "alertes" CERT-FR sont plus critiques que les simples "avis"
        for feed_url, is_alerte in (
            (self.alerte_feed_url, True),
            (self.feed_url, False),
        ):
            for entry in parse_feed(feed_url):
                items.append(
                    WatchItem(
                        source=self.name,
                        type=self.item_type,
                        title=entry.title,
                        url=entry.link,
                        published_at=entry.published_at,
                        summary=strip_html(entry.summary)[:500],
                        cve_ids=entry.cve_ids,
                        severity=Severity.CRITICAL if is_alerte else None,
                        tags=["cert-fr", "alerte" if is_alerte else "avis"],
                    )
                )
        return items
