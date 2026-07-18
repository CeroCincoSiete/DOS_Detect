"""Módulo forense: guarda paquetes involucrados en un ataque a .pcap.

Mantiene un buffer circular por (ip, tipo) que se descarga al disparo
de la alerta correspondiente.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, Tuple

try:
    from scapy.all import wrpcap  # type: ignore
    SCAPY_OK = True
except Exception:  # noqa: BLE001
    SCAPY_OK = False

from .config import ForensicsConfig


class ForensicsRecorder:
    """Buffer circular de paquetes por (src_ip, attack_type) para volcar a pcap."""

    def __init__(self, cfg: ForensicsConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._buffers: Dict[Tuple[str, str], Deque] = defaultdict(
            lambda: deque(maxlen=cfg.max_packets)
        )
        os.makedirs(cfg.output_dir, exist_ok=True)

    def stash(self, src_ip: str, attack_type: str, packet) -> None:
        if not self.cfg.enabled or packet is None:
            return
        with self._lock:
            self._buffers[(src_ip, attack_type)].append(packet)

    def dump(self, src_ip: str, attack_type: str) -> str | None:
        """Vuelca los paquetes acumulados a un .pcap y devuelve la ruta."""
        if not self.cfg.enabled or not SCAPY_OK:
            return None
        with self._lock:
            pkts = list(self._buffers.get((src_ip, attack_type), []))
        if not pkts:
            return None
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_ip = src_ip.replace(":", "_")
        fname = f"attack_{attack_type}_{safe_ip}_{ts}.pcap"
        path = Path(self.cfg.output_dir) / fname
        try:
            wrpcap(str(path), pkts)
        except Exception:  # noqa: BLE001
            return None
        return str(path)
