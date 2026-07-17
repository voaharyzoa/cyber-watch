"""Notifier Email via SMTP - principalement utilisé pour les digests."""
from __future__ import annotations

import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cyberwatch.core.models import WatchItem
from cyberwatch.notifiers.base import BaseNotifier

log = logging.getLogger(__name__)

TYPE_LABEL = {
    "vulnerability": "Vulnérabilités",
    "security_news": "Actualités sécurité",
    "product_update": "Mises à jour produits",
    "threat_intel": "Threat Intelligence",
    "advisory_vendor": "Advisories vendors",
}

# couleurs en hex fixes : les clients email (Outlook notamment) ne
# supportent pas les variables CSS, donc pas de var(--...) ici
TYPE_COLOR = {
    "vulnerability": "#791f1f",
    "security_news": "#444441",
    "product_update": "#3c3489",
    "threat_intel": "#0c447c",
    "advisory_vendor": "#085041",
}

SEVERITY_STYLE = {
    "critical": {"border": "#E24B4A", "bg": "#FCEBEB", "badge_bg": "#F7C1C1", "badge_text": "#791f1f"},
    "high": {"border": "#EF9F27", "bg": "#FAEEDA", "badge_bg": "#FAC775", "badge_text": "#633806"},
    "medium": {"border": "#EF9F27", "bg": "#FAEEDA", "badge_bg": "#FAC775", "badge_text": "#633806"},
    "low": {"border": "#97C459", "bg": "#EAF3DE", "badge_bg": "#C0DD97", "badge_text": "#27500A"},
    "info": {"border": "#B4B2A9", "bg": "#F1EFE8", "badge_bg": "#D3D1C7", "badge_text": "#444441"},
}


class EmailNotifier(BaseNotifier):
    channel_name = "email"

    def __init__(self) -> None:
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.sender = os.getenv("DIGEST_FROM_EMAIL", self.smtp_user or "")
        self.recipients = [
            r.strip() for r in os.getenv("NOTIFY_EMAIL_TO", "").split(",") if r.strip()
        ]
        if not all([self.smtp_host, self.smtp_user, self.smtp_password, self.recipients]):
            log.warning("Config SMTP incomplète, notifications email désactivées")

    def _send(self, subject: str, html_body: str) -> None:
        if not all([self.smtp_host, self.smtp_user, self.smtp_password, self.recipients]):
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.sender, self.recipients, msg.as_string())
        except Exception:
            log.exception("Échec d'envoi email")

    def send_realtime(self, item: WatchItem) -> None:
        # l'email n'est utilisé qu'en digest par défaut (voir sources.yaml),
        # mais on garde la possibilité de l'utiliser en temps réel aussi
        self._send(
            subject=f"[CyberWatch] Alerte: {item.title}",
            html_body=self._render_items([item]),
        )

    def send_digest(self, items: list[WatchItem], title: str) -> None:
        if not items:
            return
        self._send(subject=f"[CyberWatch] {title}", html_body=self._render_items(items, title))

    @classmethod
    def _render_items(cls, items: list[WatchItem], title: str = "") -> str:
        """Bulletin HTML avec CSS inline et layout en table, pour un rendu
        correct dans Outlook/Gmail/Apple Mail. Les vulnérabilités reçoivent
        un badge de sévérité coloré ; les autres types sont listés en
        sections groupées pour un scan visuel rapide."""
        by_type: dict[str, list[WatchItem]] = {}
        for item in items:
            by_type.setdefault(item.type.value, []).append(item)

        # ordre d'affichage : signal fort d'abord
        type_order = ["vulnerability", "threat_intel", "advisory_vendor", "product_update", "security_news"]
        ordered_types = [t for t in type_order if t in by_type] + [
            t for t in by_type if t not in type_order
        ]

        sections = []
        for type_key in ordered_types:
            type_items = by_type[type_key]
            color = TYPE_COLOR.get(type_key, "#444441")
            sections.append(
                f'<tr><td style="padding:20px 24px 10px;">'
                f'<div style="font-size:13px;font-weight:bold;color:{color};'
                f'text-transform:uppercase;letter-spacing:0.5px;">'
                f"{TYPE_LABEL.get(type_key, type_key)} ({len(type_items)})</div></td></tr>"
            )
            for item in type_items:
                sections.append(cls._render_item_row(item))

        header_date = datetime.now().strftime("%d/%m/%Y")
        html = f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
       style="max-width:640px;margin:0 auto;font-family:Arial,Helvetica,sans-serif;
              background:#ffffff;border:1px solid #e2e2e2;border-radius:8px;">
  <tr>
    <td style="background:#1a1a2e;padding:20px 24px;border-radius:8px 8px 0 0;">
      <div style="color:#ffffff;font-size:18px;font-weight:bold;">
        {title or 'CyberWatch — Bulletin de veille'}
      </div>
      <div style="color:#9ca3af;font-size:13px;margin-top:4px;">
        {header_date} · {len(items)} nouveaux éléments
      </div>
    </td>
  </tr>
  {''.join(sections)}
  <tr>
    <td style="background:#f5f5f5;padding:14px 24px;font-size:11px;color:#888;
               text-align:center;border-radius:0 0 8px 8px;">
      Généré automatiquement par CyberWatch
    </td>
  </tr>
</table>
"""
        return html

    @staticmethod
    def _render_item_row(item: WatchItem) -> str:
        cve_str = f" ({', '.join(item.cve_ids)})" if item.cve_ids else ""
        source_str = f"via {item.source}"

        if item.type.value == "vulnerability" and item.severity:
            style = SEVERITY_STYLE.get(item.severity.value, SEVERITY_STYLE["info"])
            cvss_str = f" · CVSS {item.cvss_score}" if item.cvss_score else ""
            exploited = (
                ' · <span style="font-weight:bold;">exploitée activement</span>'
                if item.exploited_in_wild
                else ""
            )
            return f"""
  <tr>
    <td style="padding:0 24px 8px;">
      <div style="border-left:4px solid {style['border']};background:{style['bg']};
                  border-radius:0 6px 6px 0;padding:10px 14px;">
        <span style="font-size:11px;font-weight:bold;color:{style['badge_text']};
                     background:{style['badge_bg']};padding:2px 8px;border-radius:10px;">
          {item.severity.value.upper()}{cvss_str}
        </span>
        <div style="font-size:14px;font-weight:bold;color:#1a1a1a;margin-top:6px;">
          <a href="{item.url}" style="color:#1a1a1a;text-decoration:none;">
            {item.title}{cve_str}
          </a>
        </div>
        <div style="font-size:12px;color:#555;margin-top:4px;">
          {source_str}{exploited}
        </div>
      </div>
    </td>
  </tr>"""

        return f"""
  <tr>
    <td style="padding:0 24px;">
      <div style="font-size:13px;color:#1a1a1a;padding:6px 0;border-bottom:1px solid #eee;">
        ▸ <a href="{item.url}" style="color:#0c447c;text-decoration:none;">{item.title}</a>
        <span style="color:#888;font-size:12px;"> — {source_str}</span>
      </div>
    </td>
  </tr>"""