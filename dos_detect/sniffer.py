"""Captura de paquetes en vivo (scapy) + clasificación básica hacia el Detector.

Errores tratados:
- Falta de privilegios root (PermissionError / OSError).
- Interfaz inexistente: lista las disponibles y prompt interactivo.
- Scapy no disponible: aviso claro y fallback opcional a modo simulación.
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Callable, Optional

try:
    from scapy.all import sniff, get_if_list  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    from scapy.packet import Raw  # type: ignore
    SCAPY_OK = True
    SCAPY_ERR = None
except Exception as e:  # noqa: BLE001
    SCAPY_OK = False
    SCAPY_ERR = str(e)

from .detector import Detector
from .forensics import ForensicsRecorder


class NoPrivilegesError(RuntimeError):
    pass


class InterfaceError(RuntimeError):
    pass


def list_interfaces() -> list[str]:
    if not SCAPY_OK:
        return []
    try:
        return list(get_if_list())
    except Exception:  # noqa: BLE001
        return []


def _classify(pkt) -> tuple[Optional[str], str, str, str]:
    """Devuelve (attack_type|None, src_ip, proto, summary)."""
    if IP not in pkt:
        return None, "?", "OTHER", pkt.summary() if hasattr(pkt, "summary") else str(pkt)

    ip = pkt[IP]
    src = ip.src

    if TCP in pkt:
        tcp = pkt[TCP]
        # SYN sin ACK => intento de conexión (half-open cuando no completa)
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            return "syn_flood", src, "TCP-SYN", f"TCP-SYN {src} -> {ip.dst}:{tcp.dport}"
        # HTTP GET Flood (L7): puerto 80 + payload que empieza con "GET "
        if tcp.dport == 80 and Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)[:4]
                if payload.startswith(b"GET "):
                    return "http_get_flood", src, "HTTP", f"HTTP GET {src} -> {ip.dst}"
            except Exception:  # noqa: BLE001
                pass
        return None, src, "TCP", f"TCP {src} -> {ip.dst}:{tcp.dport}"

    if UDP in pkt:
        udp = pkt[UDP]
        return "udp_flood", src, "UDP", f"UDP {src} -> {ip.dst}:{udp.dport}"

    if ICMP in pkt:
        icmp = pkt[ICMP]
        # type 8 = echo-request (ping)
        if int(icmp.type) == 8:
            return "icmp_flood", src, "ICMP", f"ICMP echo {src} -> {ip.dst}"
        return None, src, "ICMP", f"ICMP type={icmp.type} {src} -> {ip.dst}"

    return None, src, "IP", f"IP {src} -> {ip.dst}"


class LiveSniffer:
    """Sniffer scapy corriendo en un hilo dedicado."""

    def __init__(
        self,
        detector: Detector,
        forensics: ForensicsRecorder,
        interface: str | None = None,
        bpf_filter: str = "",
    ):
        self.detector = detector
        self.forensics = forensics
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -----------------------------------------------------------------
    def _handle(self, pkt) -> None:
        attack, src, proto, summary = _classify(pkt)
        self.detector.record(attack, src, proto, summary)
        if attack:
            self.forensics.stash(src, attack, pkt)

    # -----------------------------------------------------------------
    def start(self) -> None:
        if not SCAPY_OK:
            raise RuntimeError(f"scapy no disponible: {SCAPY_ERR}")
        # Chequeo de privilegios en Linux (root / CAP_NET_RAW)
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise NoPrivilegesError(
                "Se requieren privilegios de root (o CAP_NET_RAW) para capturar en vivo. "
                "Ejecuta con: sudo python main.py --live"
            )

        available = list_interfaces()
        if self.interface and self.interface not in available:
            raise InterfaceError(
                f"Interfaz '{self.interface}' no disponible. Disponibles: {', '.join(available) or 'ninguna'}"
            )

        def _runner():
            try:
                sniff(
                    iface=self.interface if self.interface else None,
                    filter=self.bpf_filter or None,
                    prn=self._handle,
                    store=False,
                    stop_filter=lambda _p: self._stop.is_set(),
                )
            except PermissionError as e:
                print(f"[sniffer] permisos insuficientes: {e}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"[sniffer] error: {e}", file=sys.stderr)

        self._thread = threading.Thread(target=_runner, name="dos-sniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
