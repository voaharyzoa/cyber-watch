"""Point d'entrée CLI: cyberwatch [run|once|digest]."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from cyberwatch.core.scheduler import Scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cyberwatch")


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(prog="cyberwatch")
    parser.add_argument(
        "command",
        choices=["run", "once", "digest"],
        help="run: démarre le scheduler en continu | once: exécute un cycle unique | digest: envoie le digest maintenant",
    )
    parser.add_argument(
        "--config",
        default="config/sources.yaml",
        type=Path,
        help="Chemin vers sources.yaml",
    )
    args = parser.parse_args()

    scheduler = Scheduler(config_path=args.config)

    if args.command == "run":
        log.info("Démarrage du scheduler en continu...")
        scheduler.start()
    elif args.command == "once":
        log.info("Exécution d'un cycle unique sur toutes les sources...")
        scheduler.run_once()
    elif args.command == "digest":
        log.info("Envoi du digest...")
        scheduler.send_digest_now()


if __name__ == "__main__":
    sys.exit(main())
