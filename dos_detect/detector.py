"""Motor de detección DoS/DDoS.

Mantiene ventanas deslizantes (sliding windows) de eventos por IP y tipo,
y emite alertas cuando las tasas cruzan los umbrales configurados.
Diseñado para ser thread-safe: el sniffer lo alimenta desde un hilo,
la TUI lee snapshots desde otro.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple

from .config import Config


ATTACK_TYPES = ("syn_flood", "icmp_flood", "udp_flood", "http_get_flood")

# Nombres amigables para UI y alertas
ATTACK_LABELS = {
    "syn_flood": "SYN Flood (TCP)",
    "icmp_flood": "ICMP Flood (Ping)",
    "udp_flood": "UDP Flood",
    "http_get_flood": "HTTP GET Flood (L7)",
}


@dataclass
class Alert:
    timestamp: float
    attack_type: str
    src_ip: str
    rate: float          # paquetes/s medidos
    threshold: int
    window: int
    mitigation: str = ""
    label: str = ""

    def as_row(self) -> tuple:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (
            ts,
            self.label or ATTACK_LABELS.get(self.attack_type, self.attack_type),
            self.src_ip,
            f"{self.rate:.0f} pkt/s",
            str(self.threshold),
            self.mitigation,
        )


@dataclass
class Metrics:
    """Snapshot de métricas para la UI."""

    total_packets: int = 0
    packets_per_sec: float = 0.0
    by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    active_alerts: int = 0
    top_talkers: list = field(default_factory=list)  # [(ip, count), ...]


class Detector:
    """Núcleo de detección y agregación de métricas."""

    def __init__(self, config: Config):
        self.cfg = config
        self._lock = threading.RLock()

        # Ventanas deslizantes: (ip, attack_type) -> deque[timestamps]
        self._events: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

        # Contadores globales
        self._total_packets = 0
        self._proto_counts: Dict[str, int] = defaultdict(int)
        self._ip_counts: Dict[str, int] = defaultdict(int)

        # Rate estimator: paquetes en el último segundo
        self._recent_packets: Deque[float] = deque(maxlen=10000)

        # Cooldown por (ip, attack_type)
        self._last_alert: Dict[Tuple[str, str], float] = {}

        # Buffer de alertas para la UI
        self._alerts_log: Deque[Alert] = deque(maxlen=200)

        # Log de tráfico (paquetes crudos) para el panel
        self._traffic_log: Deque[str] = deque(maxlen=300)

        # Callback opcional (alerta -> None) - lo usa la app para forense/webhook
        self.on_alert = None  # type: ignore

    # ---------------------------------------------------------------
    # Ingesta de eventos desde el sniffer
    # ---------------------------------------------------------------
    def record(
        self, attack_type: str | None, src_ip: str, proto: str, summary: str = ""
    ) -> None:
        """Registra un paquete. `attack_type` puede ser None (tráfico normal)."""
        now = time.time()
        with self._lock:
            self._total_packets += 1
            self._proto_counts[proto] += 1
            self._ip_counts[src_ip] += 1
            self._recent_packets.append(now)

            if summary:
                self._traffic_log.append(f"{time.strftime('%H:%M:%S')}  {summary}")

            if attack_type and attack_type in ATTACK_TYPES:
                dq = self._events[(src_ip, attack_type)]
                dq.append(now)
                # Poda ventana
                cutoff = now - self.cfg.window_seconds
                while dq and dq[0] < cutoff:
                    dq.popleft()

                # Evalúa umbral
                threshold = getattr(self.cfg.thresholds, attack_type)
                # tasa por segundo = eventos_en_ventana / ventana
                rate = len(dq) / self.cfg.window_seconds
                if rate >= threshold:
                    self._maybe_fire(attack_type, src_ip, rate, threshold)

    # ---------------------------------------------------------------
    def _maybe_fire(
        self, attack_type: str, src_ip: str, rate: float, threshold: int
    ) -> None:
        now = time.time()
        key = (src_ip, attack_type)
        last = self._last_alert.get(key, 0.0)
        if now - last < self.cfg.cooldown_seconds:
            return
        self._last_alert[key] = now

        from .mitigation import suggest_mitigation

        alert = Alert(
            timestamp=now,
            attack_type=attack_type,
            src_ip=src_ip,
            rate=rate,
            threshold=threshold,
            window=self.cfg.window_seconds,
            mitigation=suggest_mitigation(src_ip),
            label=ATTACK_LABELS.get(attack_type, attack_type),
        )
        self._alerts_log.appendleft(alert)
        cb = self.on_alert
        if cb:
            try:
                cb(alert)
            except Exception:  # noqa: BLE001 - callback no debe tumbar el detector
                pass

    # ---------------------------------------------------------------
    # Snapshots para la TUI (thread-safe)
    # ---------------------------------------------------------------
    def metrics_snapshot(self) -> Metrics:
        with self._lock:
            now = time.time()
            # pps = paquetes en el último segundo
            one_sec_ago = now - 1.0
            pps = sum(1 for t in self._recent_packets if t >= one_sec_ago)
            top = sorted(self._ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
            return Metrics(
                total_packets=self._total_packets,
                packets_per_sec=float(pps),
                by_protocol=dict(self._proto_counts),
                active_alerts=len(self._alerts_log),
                top_talkers=top,
            )

    def recent_alerts(self, limit: int = 20) -> list[Alert]:
        with self._lock:
            return list(list(self._alerts_log)[:limit])

    def recent_traffic(self, limit: int = 50) -> list[str]:
        with self._lock:
            data = list(self._traffic_log)
        return data[-limit:]
