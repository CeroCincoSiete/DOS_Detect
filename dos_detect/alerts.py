"""Módulo de alertas externas vía webhook (Discord / Slack / genérico)."""
from __future__ import annotations

import threading

import requests

from .config import WebhookConfig
from .detector import Alert


def _is_discord(url: str) -> bool:
    return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url


def _is_slack(url: str) -> bool:
    return "hooks.slack.com" in url


def _payload_discord(alert: Alert, pcap_path: str | None) -> dict:
    color = 0xE74C3C  # rojo crítico
    fields = [
        {"name": "IP atacante", "value": f"`{alert.src_ip}`", "inline": True},
        {"name": "Tasa medida", "value": f"{alert.rate:.0f} pkt/s", "inline": True},
        {"name": "Umbral", "value": f"{alert.threshold} pkt/s ({alert.window}s)", "inline": True},
        {"name": "Mitigación sugerida", "value": f"```bash\n{alert.mitigation}\n```", "inline": False},
    ]
    if pcap_path:
        fields.append({"name": "Forense", "value": f"`{pcap_path}`", "inline": False})
    return {
        "username": "DoS_Detect",
        "embeds": [
            {
                "title": f"🚨 Ataque detectado: {alert.label}",
                "color": color,
                "fields": fields,
                "timestamp": None,
            }
        ],
    }


def _payload_slack(alert: Alert, pcap_path: str | None) -> dict:
    text = (
        f"*🚨 DoS_Detect - Ataque detectado*\n"
        f"• *Tipo*: {alert.label}\n"
        f"• *IP*: `{alert.src_ip}`\n"
        f"• *Tasa*: {alert.rate:.0f} pkt/s (umbral {alert.threshold})\n"
        f"• *Mitigación*: `{alert.mitigation}`\n"
    )
    if pcap_path:
        text += f"• *Forense*: `{pcap_path}`\n"
    return {"text": text}


def _payload_generic(alert: Alert, pcap_path: str | None) -> dict:
    return {
        "tool": "DoS_Detect",
        "level": "critical",
        "attack_type": alert.attack_type,
        "label": alert.label,
        "src_ip": alert.src_ip,
        "rate_pps": alert.rate,
        "threshold_pps": alert.threshold,
        "window_seconds": alert.window,
        "mitigation": alert.mitigation,
        "pcap": pcap_path,
        "timestamp": alert.timestamp,
    }


class WebhookNotifier:
    """Envío no-bloqueante (thread por alerta)."""

    def __init__(self, cfg: WebhookConfig):
        self.cfg = cfg

    def send(self, alert: Alert, pcap_path: str | None = None) -> None:
        if not self.cfg.enabled or not self.cfg.url:
            return
        threading.Thread(target=self._do_send, args=(alert, pcap_path), daemon=True).start()

    def _do_send(self, alert: Alert, pcap_path: str | None) -> None:
        url = self.cfg.url or ""
        try:
            if _is_discord(url):
                payload = _payload_discord(alert, pcap_path)
            elif _is_slack(url):
                payload = _payload_slack(alert, pcap_path)
            else:
                payload = _payload_generic(alert, pcap_path)
            requests.post(url, json=payload, timeout=self.cfg.timeout)
        except Exception:  # noqa: BLE001 - no queremos que un webhook caído tumbar la app
            pass
