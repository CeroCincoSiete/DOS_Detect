"""Cargador de configuración YAML con validación y defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Thresholds:
    syn_flood: int = 100
    icmp_flood: int = 200
    udp_flood: int = 500
    http_get_flood: int = 50


@dataclass
class ForensicsConfig:
    enabled: bool = True
    output_dir: str = "./forensics"
    max_packets: int = 2000


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str | None = None
    timeout: int = 5


@dataclass
class SimulationConfig:
    enabled: bool = False
    scenarios: list[str] = field(
        default_factory=lambda: ["syn_flood", "icmp_flood", "udp_flood", "http_get_flood"]
    )


@dataclass
class Config:
    interface: str | None = None
    bpf_filter: str = ""
    window_seconds: int = 5
    cooldown_seconds: int = 30
    thresholds: Thresholds = field(default_factory=Thresholds)
    forensics: ForensicsConfig = field(default_factory=ForensicsConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        p = Path(path)
        if not p.exists():
            # Silencioso: usar defaults
            return cls()
        try:
            with p.open("r", encoding="utf-8") as f:
                raw: dict[str, Any] = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"config.yaml inválido: {e}") from e

        cfg = cls(
            interface=raw.get("interface"),
            bpf_filter=raw.get("bpf_filter", "") or "",
            window_seconds=int(raw.get("window_seconds", 5)),
            cooldown_seconds=int(raw.get("cooldown_seconds", 30)),
            thresholds=Thresholds(**(raw.get("thresholds") or {})),
            forensics=ForensicsConfig(**(raw.get("forensics") or {})),
            webhook=WebhookConfig(**(raw.get("webhook") or {})),
            simulation=SimulationConfig(**(raw.get("simulation") or {})),
        )
        # Asegura directorio forense
        os.makedirs(cfg.forensics.output_dir, exist_ok=True)
        return cfg
