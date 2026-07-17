"""Modèles de données du projet.

Le concept central n'est plus uniquement `Advisory` (CVE) mais un
`WatchItem` générique qui couvre toute la veille technologique :
vulnérabilités, actualités, mises à jour produits et threat intel.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ItemType(str, Enum):
    VULNERABILITY = "vulnerability"      # CVE / advisory avec score CVSS
    SECURITY_NEWS = "security_news"      # actualité cyber générale
    PRODUCT_UPDATE = "product_update"    # release notes / changelog
    THREAT_INTEL = "threat_intel"        # campagnes, IOC, groupes APT
    ADVISORY_VENDOR = "advisory_vendor"  # advisory/blog sécu vendor, non-CVE


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"  # pas de notion de gravité (news, updates)

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    @property
    def rank(self) -> int:
        """Plus haut = plus grave, pour trier / filtrer facilement."""
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


def make_item_id(source: str, url: str) -> str:
    """ID stable pour dédup exacte (source + url)."""
    raw = f"{source}:{url}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


@dataclass
class WatchItem:
    """Unité de veille : une vulnérabilité, une news, une release, une intel."""

    source: str
    type: ItemType
    title: str
    url: str
    published_at: datetime

    id: str = ""
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    summary: Optional[str] = None
    severity: Optional[Severity] = None
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploited_in_wild: bool = False
    raw: Optional[dict[str, Any]] = None  # payload brut, utile pour debug/re-parsing

    def __post_init__(self) -> None:
        if not self.id:
            self.id = make_item_id(self.source, self.url)
        if self.severity is None and self.type == ItemType.VULNERABILITY:
            self.severity = Severity.from_cvss(self.cvss_score)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "source": self.source,
            "type": self.type.value,
            "title": self.title,
            "url": self.url,
            "published_at": self.published_at.isoformat(),
            "fetched_at": self.fetched_at.isoformat(),
            "summary": self.summary,
            "severity": self.severity.value if self.severity else None,
            "cve_ids": list(self.cve_ids),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "tags": list(self.tags),
            "affected_products": list(self.affected_products),
            "exploited_in_wild": self.exploited_in_wild,
        }
        return d


# Alias métier pour la lisibilité côté sources "vulnérabilité"
Advisory = WatchItem
CVE = WatchItem
