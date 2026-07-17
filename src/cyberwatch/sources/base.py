"""Classe abstraite pour toutes les sources de veille."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from cyberwatch.core.models import ItemType, WatchItem

log = logging.getLogger(__name__)


class BaseSource(ABC):
    """Toute source doit déclarer son `item_type` et implémenter `fetch()`.

    `item_type` sert à router correctement l'item vers le bon enrichissement
    (CVSS pour les vulnérabilités, tagging pour le reste) et vers le bon
    canal de notification (temps réel vs digest).
    """

    name: str
    item_type: ItemType

    def __init__(self, name: str, params: dict[str, Any] | None = None) -> None:
        self.name = name
        self.params = params or {}

    @abstractmethod
    def fetch(self) -> list[WatchItem]:
        """Récupère les nouveaux items depuis la source. Ne doit pas lever
        d'exception fatale : les erreurs réseau ponctuelles sont catchées
        et loguées, pour ne pas bloquer les autres sources du cycle."""
        raise NotImplementedError

    def safe_fetch(self) -> list[WatchItem]:
        try:
            items = self.fetch()
            log.info("[%s] %d items récupérés", self.name, len(items))
            return items
        except Exception:
            log.exception("[%s] échec de la récupération", self.name)
            return []
