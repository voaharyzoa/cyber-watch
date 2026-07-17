"""Source MSRC (Microsoft) - bulletins de sécurité, via API CVRF publique."""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.sources.base import BaseSource


class MsrcSource(BaseSource):
    item_type = ItemType.VULNERABILITY

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.api_url = self.params.get(
            "api_url", "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
        )

    def fetch(self) -> list[WatchItem]:
        resp = requests.get(
            self.api_url, headers={"Accept": "application/json"}, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()

        items: list[WatchItem] = []
        for entry in data.get("value", [])[:5]:  # les 5 bulletins mensuels les + récents
            cvrf_id = entry.get("ID")
            title = entry.get("DocumentTitle", cvrf_id)
            if not cvrf_id:
                continue
            items.append(
                WatchItem(
                    source=self.name,
                    type=self.item_type,
                    title=f"MSRC: {title}",
                    url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cvrf_id}",
                    published_at=self._parse_date(entry.get("InitialReleaseDate")),
                    summary=f"Bulletin de sécurité Microsoft {cvrf_id}",
                    tags=["microsoft", "patch-tuesday"],
                )
            )
        return items

    @staticmethod
    def _parse_date(value: str | None) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
