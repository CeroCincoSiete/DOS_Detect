"""Simulador de tráfico para probar la detección sin privilegios de red.

Genera eventos sintéticos para cada tipo de ataque y tráfico normal,
alimentando al Detector desde un hilo dedicado.
"""
from __future__ import annotations

import random
import threading
import time

from .detector import Detector, ATTACK_TYPES, ATTACK_LABELS
from .forensics import ForensicsRecorder


class TrafficSimulator:
    """Simulador de tráfico y ataques para modo --sim."""

    def __init__(self, detector: Detector, forensics: ForensicsRecorder, scenarios: list[str]):
        self.detector = detector
        self.forensics = forensics
        self.scenarios = scenarios
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def _runner():
            while not self._stop.is_set():
                # Tráfico normal para ambientar
                self._send_normal_traffic(5)
                # Ataque de turno
                self._send_random_attack()
                # Pausa
                time.sleep(random.uniform(8, 15))
        self._thread = threading.Thread(target=_runner, name="dos-simulator", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _send_normal_traffic(self, count: int):
        for _ in range(count):
            src = f"192.168.1.{random.randint(2, 254)}"
            proto = random.choice(["TCP", "UDP", "ICMP"])
            summary = f"{proto} {src} -> 10.0.0.1"
            self.detector.record(None, src, proto, summary)
            time.sleep(random.uniform(0.01, 0.1))

    def _send_random_attack(self):
        scenario = random.choice(self.scenarios)
        src = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        rate = random.randint(2, 5) * getattr(self.detector.cfg.thresholds, scenario)
        duration = random.uniform(2, 5)
        label = ATTACK_LABELS.get(scenario, scenario)
        print(f"[sim] lanzando {label} desde {src} (~{rate} pkt/s)")
        start = time.time()
        while time.time() - start < duration and not self._stop.is_set():
            # Generar paquetes sintéticos para el detector
            proto = {
                "syn_flood": "TCP-SYN",
                "icmp_flood": "ICMP",
                "udp_flood": "UDP",
                "http_get_flood": "HTTP",
            }.get(scenario, "OTHER")
            summary = f"{label} {src} -> 192.168.1.1"
            self.detector.record(scenario, src, proto, summary)
            # Forense (simulado, no hay paquete scapy real)
            self.forensics.stash(src, scenario, None)
            time.sleep(1 / rate)
