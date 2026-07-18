# DoS_Detect

**Herramienta profesional de Blue Team para monitorización de red y detección de ataques DoS/DDoS en tiempo real.**
Escrita en Python 3, con TUI interactiva basada en [Textual](https://textual.textualize.io/), captura de paquetes con [scapy](https://scapy.net/) y modo forense automático a `.pcap`.

![status](https://img.shields.io/badge/status-production--ready-brightgreen)
![python](https://img.shields.io/badge/python-3.10+-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ✨ Características

| Módulo | Descripción |
| --- | --- |
| **Motor de detección** | Clasificador basado en ventanas deslizantes con umbrales configurables para **SYN Flood**, **ICMP Flood**, **UDP Flood** y **HTTP GET Flood** (Capa 7). |
| **TUI en vivo** | Dashboard con métricas (pps, top talkers, protocolos), panel de **Alertas Recientes** que se ilumina en rojo, y log continuo de tráfico. |
| **Modo forense** | Guarda automáticamente los paquetes del ataque a `./forensics/attack_<tipo>_<ip>_<timestamp>.pcap` (abrible en Wireshark). |
| **Alertas externas** | Webhooks a **Discord**, **Slack** o endpoint genérico (auto-detección por URL). |
| **Sugerencias de mitigación** | Comando `iptables` / `ufw` exacto para bloquear la IP atacante, mostrado en la UI y en el webhook. |
| **Modo simulación** | Genera tráfico sintético para validar el motor **sin necesidad de root**. Ideal para demos, CI y pruebas. |
| **Resiliencia** | Manejo de errores por permisos, interfaces inexistentes, scapy no disponible, cooldowns anti-spam y ejecución del sniffer en hilo dedicado. |

---

## 🧭 Arquitectura

```
dos_detect/
├── main.py                    # CLI + wiring
├── config.yaml                # Umbrales, forense, webhook, simulación
├── requirements.txt
├── dos_detect/
│   ├── config.py              # Carga y validación de configuración
│   ├── detector.py            # Motor: ventanas deslizantes, alertas, métricas
│   ├── sniffer.py             # Captura live (scapy) + clasificación L3/L4/L7
│   ├── simulator.py           # Generador de tráfico sintético
│   ├── forensics.py           # Buffer circular + volcado a .pcap
│   ├── alerts.py              # WebhookNotifier (Discord/Slack/genérico)
│   ├── mitigation.py          # Sugerencias iptables/ufw
│   └── tui.py                 # Dashboard Textual
├── tests/
│   └── test_detector.py       # Tests unitarios (no requieren red)
└── forensics/                 # .pcap generados en tiempo real
```

**Concurrencia:**
- El *sniffer* / *simulador* corre en un hilo dedicado (`threading.Thread` daemon).
- El *Detector* es **thread-safe** (`RLock`) y expone snapshots a la TUI.
- La *TUI* refresca cada 500 ms con `asyncio` (`set_interval`), nunca bloquea al sniffer.
- Los *webhooks* se envían en threads efímeros para no bloquear las detecciones.

---

## 📦 Instalación

Requiere **Python 3.10+**. En Debian/Ubuntu, `scapy` necesita además `libpcap`:

```bash
sudo apt install -y libpcap-dev tcpdump
git clone <tu-repo>/dos_detect.git
cd dos_detect
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Uso

### 1. Modo simulación (sin privilegios)
Ideal para probar la UI, el motor de detección, el forense y los webhooks sin capturar tráfico real.

```bash
python main.py --sim
```

### 2. Modo captura real (requiere root / CAP_NET_RAW)
```bash
sudo python main.py --live
sudo python main.py --live -i eth0             # interfaz específica
sudo python main.py --live -i wlan0 --headless # sin TUI (útil para servidores)
```

### 3. Listar interfaces disponibles
```bash
python main.py --list-interfaces
```

### 4. Enviar alertas a Discord/Slack
```bash
sudo python main.py --live \
    --webhook-url \"https://discord.com/api/webhooks/XXXX/YYYY\"
```
o en `config.yaml`:
```yaml
webhook:
  enabled: true
  url: \"https://hooks.slack.com/services/T000/B000/XXXX\"
```

---

## ⚠️ Aviso de privilegios de root

`scapy` necesita acceso RAW a las interfaces de red del sistema. En Linux esto implica:

- Ejecutar como **root** (`sudo`), **o**
- Otorgar la capability `CAP_NET_RAW` al intérprete Python:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
  ```

Si la herramienta detecta que no hay privilegios, **no se cierra**: muestra un aviso claro y sugiere cómo relanzarla o usar `--sim`.

---

## ⚙️ Configuración (`config.yaml`)

```yaml
thresholds:
  syn_flood: 100        # paquetes/s por IP origen
  icmp_flood: 200
  udp_flood: 500
  http_get_flood: 50

window_seconds: 5       # ventana deslizante para calcular tasas
cooldown_seconds: 30    # anti-spam por (IP, tipo)

forensics:
  enabled: true
  output_dir: \"./forensics\"
  max_packets: 2000

webhook:
  enabled: false
  url: null             # Discord/Slack/genérico
```

Umbrales típicos para un servidor pequeño; ajústalos según tu baseline.

---

## 🧪 Tests

Los tests unitarios validan el motor de detección **sin necesidad de red**:

```bash
python tests/test_detector.py       # runner minimalista integrado
# ó
pytest -q
```

Se cubren: disparo de cada tipo de ataque, no-alerta bajo umbral, cooldowns, callbacks, métricas, mitigación y forense.

---

## 🖼️ Vista previa

```
┌─── DoS_Detect · Blue Team Network Monitor ────────── modo: SIM ──┐
│ Paquetes/s  │ Totales   │ Protocolos       │ Top talkers       │
│    712      │  18,432   │ UDP 9k  TCP 5k…  │ 203.0.113.5  4231 │
├──────────────────────────────────────────────────────────────────┤
│ 🚨 ALERTAS RECIENTES  (ATAQUE ACTIVO)                            │
│ 14:22:03 │ UDP Flood      │ 203.0.113.5 │ 890 pkt/s │ 500 │ …   │
│ 14:21:57 │ SYN Flood      │ 198.51.100.22 │ 302 pkt/s │ 100 │ … │
├──────────────────────────────────────────────────────────────────┤
│ LOG DE TRÁFICO EN VIVO                                           │
│ 14:22:03 UDP 203.0.113.5 -> 10.0.0.1:53                          │
│ 14:22:03 TCP-SYN 198.51.100.22 -> 10.0.0.1:80                    │
└──────────────────────────────────────────────────────────────────┘
    q Salir   c Limpiar log
```

---

## 🛡️ Ejemplo de mitigación (aparece en la alerta)

```bash
sudo iptables -A INPUT -s 203.0.113.5 -j DROP
# alternativa ufw: sudo ufw deny from 203.0.113.5
```

---

## 📜 Licencia

MIT — Úsalo, modifícalo y compártelo. Se agradece atribución si te resulta útil.

## 🙋 Contribuir

PRs bienvenidos. Ideas para roadmap:
- Detección basada en entropía / anomalía (no solo umbrales)
- Integración con fail2ban y Suricata
- Exportador Prometheus para métricas
- Persistencia histórica en SQLite

---
> **Descargo de responsabilidad:** Herramienta para uso defensivo y de aprendizaje. Úsala **solo** en redes que administres o con autorización explícita.
"
