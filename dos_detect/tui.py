"""Interfaz de terminal (TUI) con Textual.

Layout:
- Header con título y modo
- Fila superior: métricas en vivo (pps, total, protocolos, top talkers)
- Panel central: Alertas Recientes (tabla que se ilumina en rojo)
- Panel inferior: Log de tráfico continuo
- Footer con atajos

La TUI corre en el hilo principal (asyncio) y consulta al Detector cada 500 ms
via un timer, sin bloquear al sniffer/simulador que corren en hilos aparte.
"""
from __future__ import annotations

import time

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Log, Static

from .detector import Detector, ATTACK_LABELS


CSS = """
Screen {
    background: #0b0f14;
}

#top {
    height: 9;
    padding: 0 1;
}

.metric-card {
    background: #111826;
    border: round #1f2a3a;
    padding: 1 2;
    width: 1fr;
    height: 100%;
    color: #cfd8e3;
}

.metric-title {
    color: #7aa2f7;
    text-style: bold;
}

.metric-value {
    color: #e0e7ff;
    text-style: bold;
}

#alerts-box {
    border: round #ff5c5c;
    height: 1fr;
    padding: 0 1;
}

#alerts-box.calm {
    border: round #2a3f5f;
}

#alerts-title {
    color: #ff8080;
    text-style: bold;
    padding: 0 1;
}

#alerts-title.calm {
    color: #7aa2f7;
}

#log-box {
    border: round #3d4a63;
    height: 14;
    padding: 0 1;
    color: #a9b7cf;
}

#log-title {
    color: #7aa2f7;
    text-style: bold;
    padding: 0 1;
}

DataTable {
    background: #0f1622;
    color: #e0e7ff;
}
"""


def _fmt_protos(d: dict[str, int]) -> Text:
    if not d:
        return Text("—", style="dim")
    t = Text()
    parts = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
    for i, (proto, count) in enumerate(parts[:5]):
        if i:
            t.append("  ")
        t.append(f"{proto}", style="bold #7aa2f7")
        t.append(f" {count}", style="#e0e7ff")
    return t


def _fmt_talkers(top: list) -> Text:
    if not top:
        return Text("—", style="dim")
    t = Text()
    for i, (ip, count) in enumerate(top[:5]):
        if i:
            t.append("\n")
        t.append(f"{ip:<18}", style="#e0e7ff")
        t.append(f"{count}", style="bold #f7c873")
    return t


class MetricCard(Static):
    """Tarjeta genérica de métrica."""

    def __init__(self, title: str, id: str):
        super().__init__(id=id)
        self._title = title
        self.add_class("metric-card")

    def on_mount(self) -> None:
        self.render_content(Text("—"))

    def render_content(self, body) -> None:
        content = Text()
        content.append(self._title + "\n", style="bold #7aa2f7")
        if isinstance(body, Text):
            content.append(body)
        else:
            content.append(str(body), style="#e0e7ff")
        self.update(content)


class DoSDetectApp(App):
    """Aplicación principal Textual."""

    CSS = CSS
    TITLE = "DoS_Detect  ·  Blue Team Network Monitor"
    SUB_TITLE = ""
    BINDINGS = [
        ("q", "quit", "Salir"),
        ("c", "clear_log", "Limpiar log"),
    ]

    def __init__(self, detector: Detector, mode: str = "sim"):
        super().__init__()
        self.detector = detector
        self.mode = mode
        self.SUB_TITLE = f"modo: {mode.upper()}"

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="top"):
            yield MetricCard("Paquetes / seg", id="card-pps")
            yield MetricCard("Paquetes totales", id="card-total")
            yield MetricCard("Protocolos (top)", id="card-proto")
            yield MetricCard("Top talkers (IP)", id="card-talkers")

        with Vertical(id="alerts-box") as box:
            self._alerts_box = box
            yield Static("ALERTAS RECIENTES", id="alerts-title")
            table = DataTable(id="alerts-table", zebra_stripes=True, cursor_type="row")
            table.add_columns("Hora", "Tipo", "IP Origen", "Tasa", "Umbral", "Mitigación (iptables/ufw)")
            yield table

        with Vertical(id="log-box"):
            yield Static("LOG DE TRÁFICO EN VIVO", id="log-title")
            yield Log(id="traffic-log", highlight=True, max_lines=500)

        yield Footer()

    # ------------------------------------------------------------------
    def on_mount(self) -> None:
        # Estado inicial "calm" en el panel de alertas
        self._alerts_box.add_class("calm")
        self.query_one("#alerts-title", Static).add_class("calm")
        self._last_alert_count = 0
        self._log_cursor = 0
        # Timer de refresh
        self.set_interval(0.5, self._refresh)

    # ------------------------------------------------------------------
    def _refresh(self) -> None:
        m = self.detector.metrics_snapshot()

        # Tarjetas
        self.query_one("#card-pps", MetricCard).render_content(
            Text(f"{m.packets_per_sec:.0f}", style="bold #f7c873")
        )
        self.query_one("#card-total", MetricCard).render_content(
            Text(f"{m.total_packets}", style="bold #e0e7ff")
        )
        self.query_one("#card-proto", MetricCard).render_content(_fmt_protos(m.by_protocol))
        self.query_one("#card-talkers", MetricCard).render_content(_fmt_talkers(m.top_talkers))

        # Panel de alertas
        alerts = self.detector.recent_alerts(limit=15)
        table = self.query_one("#alerts-table", DataTable)
        table.clear()
        for a in alerts:
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            table.add_row(
                ts,
                a.label or ATTACK_LABELS.get(a.attack_type, a.attack_type),
                a.src_ip,
                f"{a.rate:.0f} pkt/s",
                str(a.threshold),
                a.mitigation,
            )

        # Efecto visual: rojo si hay alertas nuevas
        if alerts and alerts[0].timestamp > time.time() - 5:
            self._alerts_box.remove_class("calm")
            self.query_one("#alerts-title", Static).remove_class("calm")
            self.query_one("#alerts-title", Static).update("🚨 ALERTAS RECIENTES  (ATAQUE ACTIVO)")
        else:
            self._alerts_box.add_class("calm")
            self.query_one("#alerts-title", Static).add_class("calm")
            self.query_one("#alerts-title", Static).update("ALERTAS RECIENTES")

        # Log de tráfico
        traffic = self.detector.recent_traffic(limit=100)
        log = self.query_one("#traffic-log", Log)
        # Escribimos solo lo nuevo (basado en longitud aproximada)
        new_lines = traffic[self._log_cursor :] if self._log_cursor < len(traffic) else []
        for line in new_lines:
            log.write_line(line)
        self._log_cursor = len(traffic)

    # ------------------------------------------------------------------
    def action_clear_log(self) -> None:
        self.query_one("#traffic-log", Log).clear()
        self._log_cursor = 0
