"""Orchestration du projet : charge sources.yaml, instancie les sources,
lance les cycles de fetch (via APScheduler, un job par source avec son
propre intervalle), enrichit, dédup, stocke et notifie.
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

import yaml
from apscheduler.schedulers.blocking import BlockingScheduler

from cyberwatch.core.database import Database
from cyberwatch.core.models import ItemType, Severity, WatchItem
from cyberwatch.enrichment import classifier, cvss_scorer, dedup
from cyberwatch.notifiers.base import BaseNotifier
from cyberwatch.notifiers.digest import DigestBuilder
from cyberwatch.notifiers.email import EmailNotifier
from cyberwatch.notifiers.slack import SlackNotifier
from cyberwatch.notifiers.teams import TeamsNotifier
from cyberwatch.sources.base import BaseSource

log = logging.getLogger(__name__)

# module -> classe, pour instancier dynamiquement depuis sources.yaml
SOURCE_CLASS_MAP = {
    "nist_nvd": ("cyberwatch.sources.nist_nvd", "NistNvdSource"),
    "zdi": ("cyberwatch.sources.zdi", "ZdiSource"),
    "cert_fr": ("cyberwatch.sources.cert_fr", "CertFrSource"),
    "msrc": ("cyberwatch.sources.msrc", "MsrcSource"),
    "hacker_news_sec": ("cyberwatch.sources.hacker_news_sec", "HackerNewsSecSource"),
    "krebs": ("cyberwatch.sources.krebs", "KrebsSource"),
    "security_blogs": ("cyberwatch.sources.security_blogs", "SecurityBlogsSource"),
    "github_releases": ("cyberwatch.sources.github_releases", "GithubReleasesSource"),
    "vendor_changelog": ("cyberwatch.sources.vendor_changelog", "VendorChangelogSource"),
}


def _load_source_class(module_key: str):
    module_path, class_name = SOURCE_CLASS_MAP[module_key]
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class Scheduler:
    def __init__(self, config_path: str | Path = "config/sources.yaml") -> None:
        self.config_path = Path(config_path)
        self.config = self._load_config()

        db_path = self.config.get("database", {}).get("path", "data/watch.db")
        self.db = Database(db_path)
        self.dedup_threshold = self.config.get("database", {}).get(
            "dedup_similarity_threshold", 0.85
        )

        self.sources: list[BaseSource] = self._build_sources()
        self.notifiers: dict[str, BaseNotifier] = self._build_notifiers()
        self.digest_builder = DigestBuilder(self.db, self.notifiers)

        self.notif_config = self.config.get("notifications", {})

    def _load_config(self) -> dict[str, Any]:
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _build_sources(self) -> list[BaseSource]:
        sources: list[BaseSource] = []
        for entry in self.config.get("sources", []):
            if not entry.get("enabled", True):
                continue
            module_key = entry["module"]
            cls = _load_source_class(module_key)
            instance = cls(name=entry["name"], params=entry.get("params", {}))
            # certaines classes (security_blogs) sont réutilisées pour
            # plusieurs types différents -> on force le type déclaré en yaml
            declared_type = entry.get("type")
            if declared_type:
                instance.item_type = ItemType(declared_type)
            instance._interval = entry.get("interval", instance.default_interval if hasattr(instance, "default_interval") else 3600)
            sources.append(instance)
        return sources

    def _build_notifiers(self) -> dict[str, BaseNotifier]:
        return {
            "slack": SlackNotifier(),
            "teams": TeamsNotifier(),
            "email": EmailNotifier(),
        }

    # --- cycle de fetch pour une source ---------------------------------

    def run_source_cycle(self, source: BaseSource) -> None:
        raw_items = source.safe_fetch()
        if not raw_items:
            return

        # enrichissement : CVSS pour les vulns, tags mots-clés pour le reste
        items = cvss_scorer.enrich_batch(raw_items)
        items = classifier.classify_batch(items)

        # dédup approximative cross-source avant stockage
        items = dedup.find_near_duplicates(items, self.db, threshold=self.dedup_threshold)

        new_items = self.db.bulk_upsert(items)
        log.info("[%s] %d nouveaux items stockés", source.name, len(new_items))

        self._dispatch_realtime(new_items)

    def _dispatch_realtime(self, items: list[WatchItem]) -> None:
        realtime_cfg = self.notif_config.get("realtime", {})
        min_severity = Severity(realtime_cfg.get("min_severity", "high"))
        realtime_types = {ItemType(t) for t in realtime_cfg.get("types", ["vulnerability"])}
        channels = realtime_cfg.get("channels", ["slack"])

        to_notify = [
            item
            for item in items
            if item.type in realtime_types
            and item.severity is not None
            and item.severity.rank >= min_severity.rank
        ]
        for item in to_notify:
            for channel in channels:
                notifier = self.notifiers.get(channel)
                if notifier:
                    notifier.send_realtime(item)
            self.db.mark_notified([item.id], channel="realtime")

    # --- cycles globaux ---------------------------------------------------

    def run_once(self) -> None:
        for source in self.sources:
            self.run_source_cycle(source)

    def send_digest_now(self) -> None:
        digest_cfg = self.notif_config.get("digest", {})
        types = [ItemType(t) for t in digest_cfg.get("types", [])]
        channels = digest_cfg.get("channels", ["email"])
        self.digest_builder.build_and_send(types=types, channels=channels)

    def start(self) -> None:
        scheduler = BlockingScheduler()

        for source in self.sources:
            interval = getattr(source, "_interval", 3600)
            scheduler.add_job(
                self.run_source_cycle,
                "interval",
                seconds=interval,
                args=[source],
                id=f"source::{source.name}",
                next_run_time=None,  # démarre après le premier intervalle ; utiliser datetime.now() pour lancer tout de suite
                max_instances=1,
                coalesce=True,
            )
            log.info("Job planifié: %s toutes les %ds", source.name, interval)

        digest_cfg = self.notif_config.get("digest", {})
        if digest_cfg:
            hour, minute = (digest_cfg.get("time", "08:00")).split(":")
            trigger_kwargs = {"hour": int(hour), "minute": int(minute)}
            if digest_cfg.get("frequency") == "weekly":
                trigger_kwargs["day_of_week"] = "mon"
            scheduler.add_job(
                self.send_digest_now,
                "cron",
                id="digest",
                **trigger_kwargs,
            )
            log.info("Digest planifié: %s", trigger_kwargs)

        # premier passage immédiat pour ne pas attendre le premier intervalle
        self.run_once()

        try:
            scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            log.info("Arrêt du scheduler.")
