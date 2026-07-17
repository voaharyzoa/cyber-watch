"""Interface commune à tous les notifiers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from cyberwatch.core.models import WatchItem


class BaseNotifier(ABC):
    channel_name: str

    @abstractmethod
    def send_realtime(self, item: WatchItem) -> None:
        """Notification immédiate pour un item critique (vuln HIGH/CRITICAL,
        threat intel majeure)."""
        raise NotImplementedError

    @abstractmethod
    def send_digest(self, items: list[WatchItem], title: str) -> None:
        """Envoi groupé (quotidien/hebdo) pour news, updates, advisories
        vendors — évite le bruit d'une notif par item."""
        raise NotImplementedError
