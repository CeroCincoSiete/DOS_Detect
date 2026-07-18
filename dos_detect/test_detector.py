""""Tests unitarios del motor de detección (no requieren red ni root)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Import path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dos_detect.config import Config, ForensicsConfig, WebhookConfig
from dos_detect.detector import Detector
from dos_detect.forensics import ForensicsRecorder
from dos_detect.mitigation import suggest_mitigation


def _make_detector(**overrides) -> Detector:
    cfg = Config()
    # Bajamos los umbrales para hacer el test rápido y determinista
    cfg.window_seconds = 1
    cfg.cooldown_seconds = 10
    cfg.thresholds.syn_flood = 5
    cfg.thresholds.icmp_flood = 5
    cfg.thresholds.udp_flood = 5
    cfg.thresholds.http_get_flood = 5
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return Detector(cfg)


def test_syn_flood_triggers_alert():
    det = _make_detector()
    for _ in range(10):
        det.record("syn_flood", "1.2.3.4", "TCP-SYN")
    alerts = det.recent_alerts()
    assert len(alerts) == 1
    a = alerts[0]
    assert a.attack_type == "syn_flood"
    assert a.src_ip == "1.2.3.4"
    assert a.rate >= 5


def test_below_threshold_no_alert():
    det = _make_detector()
    for _ in range(3):
        det.record("udp_flood", "9.9.9.9", "UDP")
    assert det.recent_alerts() == []


def test_all_attack_types():
    det = _make_detector()
    for attack in ("syn_flood", "icmp_flood", "udp_flood", "http_get_flood"):
        for _ in range(10):
            det.record(attack, f"src-{attack}", attack.split("_")[0].upper())
    types = {a.attack_type for a in det.recent_alerts()}
    assert types == {"syn_flood", "icmp_flood", "udp_flood", "http_get_flood"}


def test_cooldown_prevents_spam():
    det = _make_detector()
    det.cfg.cooldown_seconds = 30
    for _ in range(20):
        det.record("icmp_flood", "8.8.8.8", "ICMP")
    for _ in range(20):
        det.record("icmp_flood", "8.8.8.8", "ICMP")
    # Debido al cooldown, sólo una alerta
    same = [a for a in det.recent_alerts() if a.src_ip == "8.8.8.8"]
    assert len(same) == 1


def test_metrics_snapshot_counts():
    det = _make_detector()
    for _ in range(50):
        det.record(None, "10.0.0.1", "TCP")
    m = det.metrics_snapshot()
    assert m.total_packets == 50
    assert m.by_protocol.get("TCP") == 50
    assert m.top_talkers[0][0] == "10.0.0.1"


def test_alert_callback_invoked():
    det = _make_detector()
    received = []
    det.on_alert = lambda a: received.append(a)
    for _ in range(10):
        det.record("syn_flood", "5.5.5.5", "TCP-SYN")
    assert len(received) == 1
    assert received[0].src_ip == "5.5.5.5"


def test_mitigation_command_format():
    cmd = suggest_mitigation("1.2.3.4")
    assert "iptables" in cmd and "1.2.3.4" in cmd and "DROP" in cmd
    assert "ufw" in cmd
    bad = suggest_mitigation("not-an-ip")
    assert "IP inválida" in bad


def test_forensics_stash_without_scapy_ok():
    """Aunque scapy esté disponible, si no hay paquetes reales, dump devuelve None."""
    rec = ForensicsRecorder(ForensicsConfig(enabled=True, output_dir="/tmp/dos_forensics_test", max_packets=10))
    assert rec.dump("1.1.1.1", "syn_flood") is None


if __name__ == "__main__":
    # Runner mínimo sin pytest
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    fails = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except Exception:  # noqa: BLE001
            fails += 1
            print(f"  ✗ {t.__name__}")
            traceback.print_exc()
    print(f"
{len(tests) - fails}/{len(tests)} tests OK")
    sys.exit(1 if fails else 0)
"
