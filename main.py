"""DoS_Detect - Entry point.

Uso:
    python main.py --sim                  # Modo simulación (no requiere root)
    sudo python main.py --live             # Modo captura real (requiere root)
    sudo python main.py --live -i eth0     # Especifica interfaz
    python main.py --sim --headless        # Modo consola sin TUI (útil para tests/CI)
    python main.py --list-interfaces       # Listar interfaces disponibles

Configuración: config.yaml (opcional). Si no existe, se usan defaults.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

# Permite ejecutar como script: python main.py
sys.path.insert(0, str(Path(__file__).parent))

from dos_detect.alerts import WebhookNotifier
from dos_detect.config import Config
from dos_detect.detector import Detector
from dos_detect.forensics import ForensicsRecorder
from dos_detect.simulator import TrafficSimulator


console = Console()


BANNER = r"""
[bold #7aa2f7]
   ____        ____    ____       _            _
  |  _ \  ___ / ___|  |  _ \  ___| |_ ___  ___| |_
  | | | |/ _ \___ \  | | | |/ _ \ __/ _ \/ __| __|
  | |_| | (_) |__) | | |_| |  __/ ||  __/ (__| |_
  |____/ \___/____/  |____/ \___|\__\___|\___|\__|
[/bold #7aa2f7]
[dim]        Blue Team · Network DoS/DDoS Monitor  v1.0[/dim]
"""


def _print_banner() -> None:
    console.print(BANNER)


def _print_root_notice() -> None:
    console.print(
        Panel.fit(
            "[bold #ff8080]⚠  Modo LIVE requiere privilegios de root / CAP_NET_RAW[/]\n\n"
            "Ejecuta con:  [bold]sudo python main.py --live[/]\n"
            "O prueba sin privilegios con:  [bold]python main.py --sim[/]",
            border_style="#ff8080",
            title="Privilegios insuficientes",
        )
    )


def _print_interfaces(interfaces: list[str]) -> None:
    console.print(
        Panel(
            "\n".join(f"  • [bold]{i}[/]" for i in interfaces) or "[dim](ninguna detectada)[/dim]",
            title="Interfaces disponibles",
            border_style="#7aa2f7",
        )
    )


# ---------------------------------------------------------------------------
def _choose_interface(available: list[str]) -> str | None:
    """Prompt interactivo cuando la interfaz configurada no existe."""
    if not available:
        console.print("[bold #ff8080]No se detectaron interfaces de red.[/]")
        return None
    _print_interfaces(available)
    try:
        ans = input("Elige una interfaz (enter = default): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return ans or None


# ---------------------------------------------------------------------------
def _install_alert_wiring(detector: Detector, cfg: Config, forensics: ForensicsRecorder) -> None:
    """Conecta el detector con el módulo forense y los webhooks."""
    notifier = WebhookNotifier(cfg.webhook)

    def on_alert(alert):
        pcap_path = forensics.dump(alert.src_ip, alert.attack_type)
        notifier.send(alert, pcap_path=pcap_path)

    detector.on_alert = on_alert


# ---------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)

    # Overrides CLI
    if args.interface:
        cfg.interface = args.interface
    if args.webhook_url:
        cfg.webhook.enabled = True
        cfg.webhook.url = args.webhook_url

    detector = Detector(cfg)
    forensics = ForensicsRecorder(cfg.forensics)
    _install_alert_wiring(detector, cfg, forensics)

    mode = "sim" if args.sim else "live"

    # Fuente de tráfico
    stopper = None
    if args.sim:
        sim = TrafficSimulator(detector, forensics, cfg.simulation.scenarios)
        sim.start()
        stopper = sim.stop
        console.print("[bold #7aa2f7]▶ Simulador de tráfico iniciado (sin privilegios de red)[/]")
    else:
        from dos_detect.sniffer import (
            LiveSniffer,
            list_interfaces,
            NoPrivilegesError,
            InterfaceError,
            SCAPY_OK,
            SCAPY_ERR,
        )

        if not SCAPY_OK:
            console.print(f"[bold #ff8080]Scapy no disponible:[/] {SCAPY_ERR}")
            return 2

        # Interfaz: valida o pregunta
        available = list_interfaces()
        if cfg.interface and cfg.interface not in available:
            console.print(f"[bold #ff8080]Interfaz '{cfg.interface}' no encontrada.[/]")
            cfg.interface = _choose_interface(available)

        try:
            sniffer = LiveSniffer(detector, forensics, cfg.interface, cfg.bpf_filter)
            sniffer.start()
            stopper = sniffer.stop
            console.print(
                f"[bold #7aa2f7]▶ Captura en vivo iniciada (iface={cfg.interface or 'default'})[/]"
            )
        except NoPrivilegesError:
            _print_root_notice()
            return 13
        except InterfaceError as e:
            console.print(f"[bold #ff8080]{e}[/]")
            return 3

    # Frontend
    if args.headless:
        return _run_headless(detector)
    else:
        from dos_detect.tui import DoSDetectApp

        app = DoSDetectApp(detector, mode=mode)
        try:
            app.run()
        finally:
            if stopper:
                stopper()
        return 0


def _run_headless(detector: Detector) -> int:
    """Modo sin TUI: imprime métricas y alertas por stdout (útil para CI/logs)."""
    console.print("[bold #7aa2f7]Modo headless (Ctrl+C para salir)[/]")
    last_alert_ts = 0.0
    try:
        while True:
            m = detector.metrics_snapshot()
            console.print(
                f"[dim]{time.strftime('%H:%M:%S')}[/] "
                f"pps=[bold]{m.packets_per_sec:.0f}[/] "
                f"total=[bold]{m.total_packets}[/] "
                f"protos={dict(m.by_protocol)} "
                f"alerts=[bold #ff8080]{m.active_alerts}[/]"
            )
            for a in detector.recent_alerts(limit=5):
                if a.timestamp > last_alert_ts:
                    last_alert_ts = a.timestamp
                    console.print(
                        f"  [bold #ff5c5c]🚨 {a.label}[/] "
                        f"src=[bold]{a.src_ip}[/] "
                        f"rate=[bold]{a.rate:.0f} pkt/s[/] "
                        f"(umbral {a.threshold})  → {a.mitigation}"
                    )
            time.sleep(1.0)
    except KeyboardInterrupt:
        console.print("\n[dim]Detenido por el usuario.[/]")
        return 0


# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="dos_detect",
        description="Herramienta Blue Team para detección de ataques DoS/DDoS.",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--live", action="store_true", help="Captura real (requiere root).")
    src.add_argument("--sim", action="store_true", help="Modo simulación (sin privilegios).")

    ap.add_argument("-i", "--interface", help="Interfaz de red (ej. eth0, wlan0).")
    ap.add_argument("--config", default="config.yaml", help="Ruta al archivo config.yaml.")
    ap.add_argument("--webhook-url", help="Override URL del webhook (Discord/Slack/genérico).")
    ap.add_argument("--headless", action="store_true", help="Sin TUI (stdout).")
    ap.add_argument("--list-interfaces", action="store_true", help="Lista interfaces y sale.")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _print_banner()

    if args.list_interfaces:
        try:
            from dos_detect.sniffer import list_interfaces

            _print_interfaces(list_interfaces())
        except Exception as e:  # noqa: BLE001
            console.print(f"[bold #ff8080]Error listando interfaces:[/] {e}")
        return 0

    # Default a --sim si no se especifica nada (más amigable)
    if not args.live and not args.sim:
        args.sim = True
        console.print("[dim](usando --sim por defecto; usa --live con sudo para captura real)[/dim]")

    def _sigint(_sig, _frm):
        console.print("\n[dim]Cerrando...[/]")
        os._exit(0)

    signal.signal(signal.SIGINT, _sigint)

    try:
        return run(args)
    except Exception as e:  # noqa: BLE001
        console.print(f"[bold #ff8080]Error fatal:[/] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
