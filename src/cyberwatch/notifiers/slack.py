"""Notifier Slack via Incoming Webhook."""
from __future__ import annotations

import logging
import os

import requests

from cyberwatch.core.models import WatchItem
from cyberwatch.notifiers.base import BaseNotifier

log = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "ℹ️",
}

TYPE_LABEL = {
    "vulnerability": "Vulnérabilité",
    "security_news": "Actu sécu",
    "product_update": "Mise à jour",
    "threat_intel": "Threat Intel",
    "advisory_vendor": "Advisory vendor",
}


class SlackNotifier(BaseNotifier):
    channel_name = "slack"

    def __init__(self, webhook_url_env: str = "SLACK_WEBHOOK_URL") -> None:
        self.webhook_url = os.getenv(webhook_url_env)
        if not self.webhook_url:
            log.warning("SLACK_WEBHOOK_URL non configuré, notifications Slack désactivées")

    def _post(self, text: str) -> None:
        if not self.webhook_url:
            return
        try:
            requests.post(self.webhook_url, json={"text": text}, timeout=10)
        except requests.RequestException:
            log.exception("Échec d'envoi Slack")

    def send_realtime(self, item: WatchItem) -> None:
        emoji = SEVERITY_EMOJI.get(item.severity.value if item.severity else "info", "ℹ️")
        exploited = " ⚠️ *exploitée activement*" if item.exploited_in_wild else ""
        cve_str = f" ({', '.join(item.cve_ids)})" if item.cve_ids else ""
        text = (
            f"{emoji} *[{TYPE_LABEL.get(item.type.value, item.type.value)}]*{cve_str}{exploited}\n"
            f"*{item.title}*\n"
            f"{item.summary[:300] if item.summary else ''}\n"
            f"<{item.url}|Voir la source> · via {item.source}"
        )
        self._post(text)

    def send_digest(self, items: list[WatchItem], title: str) -> None:
        if not items:
            return
        lines = [f"*{title}* — {len(items)} éléments\n"]
        by_type: dict[str, list[WatchItem]] = {}
        for item in items:
            by_type.setdefault(item.type.value, []).append(item)
        for type_key, type_items in by_type.items():
            lines.append(f"\n*{TYPE_LABEL.get(type_key, type_key)}* ({len(type_items)})")
            for item in type_items[:15]:
                lines.append(f"• <{item.url}|{item.title}> _(via {item.source})_")
        self._post("\n".join(lines))
