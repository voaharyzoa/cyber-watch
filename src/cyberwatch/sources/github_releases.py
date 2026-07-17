"""Source de mises à jour produit : releases GitHub des repos suivis
(ex: kubernetes/kubernetes, openssl/openssl...). Utile pour la veille
"mise à jour" indépendamment de toute CVE associée.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import requests

from cyberwatch.core.models import ItemType, WatchItem
from cyberwatch.sources.base import BaseSource

log = logging.getLogger(__name__)


class GithubReleasesSource(BaseSource):
    item_type = ItemType.PRODUCT_UPDATE

    def __init__(self, name: str, params: dict | None = None) -> None:
        super().__init__(name, params)
        self.repos: list[str] = self.params.get("repos", [])
        token_env = self.params.get("token_env", "GITHUB_TOKEN")
        self.token = os.getenv(token_env)

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def fetch(self) -> list[WatchItem]:
        items: list[WatchItem] = []
        for repo in self.repos:
            items.extend(self._fetch_repo(repo))
        return items

    def _fetch_repo(self, repo: str) -> list[WatchItem]:
        url = f"https://api.github.com/repos/{repo}/releases"
        try:
            resp = requests.get(
                url, headers=self._headers(), params={"per_page": 5}, timeout=20
            )
            resp.raise_for_status()
        except requests.RequestException:
            log.exception("[%s] échec GitHub Releases pour %s", self.name, repo)
            return []

        items: list[WatchItem] = []
        for release in resp.json():
            if release.get("draft"):
                continue
            tag = release.get("tag_name", "")
            body = (release.get("body") or "")[:800]
            items.append(
                WatchItem(
                    source=self.name,
                    type=self.item_type,
                    title=f"{repo} {tag}"
                    + (" (pre-release)" if release.get("prerelease") else ""),
                    url=release.get("html_url", ""),
                    published_at=self._parse_date(release.get("published_at")),
                    summary=body,
                    affected_products=[repo],
                    tags=["github-release", repo.split("/")[0]],
                    raw={"repo": repo, "tag": tag},
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
