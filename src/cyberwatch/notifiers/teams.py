"""Notifier Microsoft Teams via Incoming Webhook (MessageCard)."""
from __future__ import annotations

import logging
import os

import requests

from cyberwatch.core.models import WatchItem
from cyberwatch.notifiers.base import BaseNotifier

log = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "critical": "FF0000",
    "high": "FF8C00",
    "medium": "FFD700",
    "low": "2E8B57",
    "info": "808080",
}


class TeamsNotifier(BaseNotifier):
    channel_name = "teams"

    def __init__(self, webhook_url_env: str = "TEAMS_WEBHOOK_URL") -> None:
        self.webhook_url = os.getenv(webhook_url_env)
        if not self.webhook_url:
            log.warning("TEAMS_WEBHOOK_URL non configuré, notifications Teams désactivées")

    def _post(self, card: dict) -> None:
        if not self.webhook_url:
            return
        try:
            requests.post(self.webhook_url, json=card, timeout=10)
        except requests.RequestException:
            log.exception("Échec d'envoi Teams")

    def send_realtime(self, item: WatchItem) -> None:
        color = SEVERITY_COLOR.get(item.severity.value if item.severity else "info", "808080")
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": item.title,
            "title": item.title,
            "text": (item.summary or "")[:500],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "Voir la source",
                    "targets": [{"os": "default", "uri": item.url}],
                }
            ],
        }
        self._post(card)

    def send_digest(self, items: list[WatchItem], title: str) -> None:
        if not items:
            return
        text_lines = [f"- [{i.title}]({i.url}) _(via {i.source})_" for i in items[:25]]
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": title,
            "title": f"{title} ({len(items)} éléments)",
            "text": "\n\n".join(text_lines),
        }
        self._post(card)
