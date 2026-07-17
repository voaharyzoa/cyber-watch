"""Utilitaire commun de parsing RSS/Atom pour toutes les sources feedparser."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterable

import feedparser

log = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class FeedEntry:
    """Wrapper léger et normalisé autour d'une entrée feedparser."""

    def __init__(self, raw_entry) -> None:
        self._raw = raw_entry

    @property
    def title(self) -> str:
        return getattr(self._raw, "title", "").strip()

    @property
    def link(self) -> str:
        return getattr(self._raw, "link", "").strip()

    @property
    def summary(self) -> str:
        # summary ou description selon les flux
        return (getattr(self._raw, "summary", "") or "").strip()

    @property
    def published_at(self) -> datetime:
        for field in ("published_parsed", "updated_parsed"):
            struct = getattr(self._raw, field, None)
            if struct:
                return datetime(*struct[:6], tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    @property
    def cve_ids(self) -> list[str]:
        text = f"{self.title} {self.summary}"
        return sorted(set(m.upper() for m in CVE_PATTERN.findall(text)))

    @property
    def raw_dict(self) -> dict:
        return dict(self._raw)


def parse_feed(url: str, timeout: int = 15) -> list[FeedEntry]:
    """Télécharge et parse un flux RSS/Atom. Retourne une liste vide en cas
    d'échec, en loguant l'erreur (ne jamais lever pour ne pas casser un
    cycle de fetch complet)."""
    try:
        parsed = feedparser.parse(url)
        if parsed.bozo and not parsed.entries:
            log.warning("Flux malformé ou inaccessible: %s (%s)", url, parsed.bozo_exception)
            return []
        return [FeedEntry(e) for e in parsed.entries]
    except Exception:
        log.exception("Erreur lors du parsing du flux %s", url)
        return []


def strip_html(text: str) -> str:
    """Nettoyage basique HTML -> texte, pour des résumés lisibles en notif."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean
