"""Source NVD (National Vulnerability Database) via l'API officielle 2.0."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.sources.base import BaseSource

log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NistNvdSource(BaseSource):
    item_type = ItemType.VULNERABILITY

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        api_key_env = self.params.get("api_key_env", "NVD_API_KEY")
        self.api_key = os.getenv(api_key_env)
        self.results_per_page = self.params.get("results_per_page", 100)
        self.min_cvss = self.params.get("min_cvss", 0.0)
        # NVD ne fournit pas de "depuis maintenant" -> on interroge une fenêtre glissante
        self.lookback_hours = self.params.get("lookback_hours", 6)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _call_api(self, params: dict) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def fetch(self) -> list[WatchItem]:
        since = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        params = {
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": self.results_per_page,
        }
        data = self._call_api(params)

        items: list[WatchItem] = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            summary = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), None
            )

            metrics = cve.get("metrics", {})
            cvss_score, cvss_vector = self._extract_cvss(metrics)

            if cvss_score is not None and cvss_score < self.min_cvss:
                continue

            affected = sorted(
                {
                    conf.get("criteria", "")
                    for config in cve.get("configurations", [])
                    for node in config.get("nodes", [])
                    for conf in node.get("cpeMatch", [])
                    if conf.get("criteria")
                }
            )[:20]  # on limite pour ne pas exploser le stockage

            items.append(
                WatchItem(
                    source=self.name,
                    type=self.item_type,
                    title=f"{cve_id}: {(summary or '')[:120]}",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=self._parse_date(cve.get("published")),
                    summary=summary,
                    cve_ids=[cve_id],
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_products=affected,
                    raw={"cve_id": cve_id},
                )
            )
        return items

    @staticmethod
    def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                return cvss_data.get("baseScore"), cvss_data.get("vectorString")
        return None, None

    @staticmethod
    def _parse_date(value: str | None) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)
