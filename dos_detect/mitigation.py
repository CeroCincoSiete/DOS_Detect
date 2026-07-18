"""Sugerencias de mitigación (iptables / ufw)."""
from __future__ import annotations

import ipaddress


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def suggest_mitigation(src_ip: str) -> str:
    """Devuelve un comando listo para copiar-pegar que bloquea la IP."""
    if not _valid_ip(src_ip):
        return "# IP inválida, no se puede sugerir bloqueo automático"
    # Preferimos iptables (más universal en servidores Linux)
    return (
        f"sudo iptables -A INPUT -s {src_ip} -j DROP   "
        f"# alternativa ufw:  sudo ufw deny from {src_ip}"
    )
