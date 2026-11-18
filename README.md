# SkyRF 🐱

**RF intelligence framework** para seguridad IoT — clasificación automática de señales, playbooks de ataque automatizados y dashboard en vivo sobre **CatSniffer V3**. Proyecto de investigación **by Cinn4mor0ll**. Nombrado por Sky 🐾, la gata que olfatea el espectro.

> Todo el desarrollo y las capturas son sobre dispositivos propios en laboratorio controlado. Uso exclusivo para investigación y auditoría autorizada — mismo marco que KillerBee/Sniffle/Kismet.

## Componentes

```
CatSniffer V3 ──catnip──► lab.hex ──skyrf.bridge──► ws://localhost:8765 ──► Dashboard SkyRF
                                        │
                                        └─► transport-key-watcher (en línea, captura la network key)
```

- **`skyrf.bridge`** — puente WebSocket: sigue el raw-hex de catnip (o un pcapng de Wireshark) y streamea paquetes, alertas y capturas de llaves al dashboard.
- **Dashboard** (`skyrf-dashboard/`, React + Vite) — clasificación en vivo por dispositivo, espectro waterfall, feed de eventos, y Sky celebra contigo cuando un ataque tiene éxito.
- **Playbooks** (`skyrf/playbooks/`) — ataques Zigbee automatizados con criptografía real (AES-CCM, MIC verificado).
- **Clasificador** — 14 features de metadata por ventana, RandomForest / centroides z-score. Protocolo hoy; dispositivo y evento cuando exista el dataset (ver `PROYECTO.md`).

## Instalación

```bash
pip install -r requirements.txt
```

## Uso con el CatSniffer

```bash
# 1 · Captura (catnip flashea el firmware solo)
catnip sniff zigbee --channel 15 -ff --raw lab.hex

# 2 · Bridge (en otra terminal, desde la raíz del repo)
python -m skyrf.bridge --raw-follow lab.hex --channel 15
#    o contra el pipe de Wireshark:
python -m skyrf.bridge --pcap-follow captura.pcapng

# 3 · Dashboard
cd skyrf-dashboard && npm install && npm run build
#    sirve dist/ y abre la página; pulsa CAPTURAR
```

## Playbooks de ataque

| Playbook | Qué hace | Módulo |
|---|---|---|
| **transport-key-watcher** | Detecta el Transport Key (APS cmd `0x05`), lo descifra con la TC link key por defecto (`ZigBeeAlliance09`) y verifica el MIC — cero falsos positivos | `playbooks/transport_key_watcher.py` |
| **zcl-injector** | Construye e inyecta comandos ZCL OnOff (toggle `0x02`) spoofeando al coordinador, con cifrado NWK completo y frame counter válido (sin replay) | `playbooks/zcl_injector.py` |
| **persistence** | `Mgmt_Permit_Joining_Req` (ZDO cluster `0x0036`) para dejar la red abierta a un dispositivo rogue | `playbooks/persistence.py` |

```bash
# Verificación criptográfica sin hardware (round-trips reales AES-CCM)
python -m skyrf.playbooks.selftest
#   ✓ transport key round-trip   ✓ cero falsos positivos
#   ✓ MIC inyección ZCL          ✓ MIC permit-join
```

La construcción de tramas es manual (`playbooks/frames.py`, `struct` puro) para control total de bytes — la serialización de scapy no era determinista para las cabeceras de seguridad Zigbee.

## Clasificador

```bash
python -m skyrf.cli train                          # entrena (dataset sintético etiquetado)
python -m skyrf.cli scan --synthetic zigbee        # scan en vivo sin hardware (dev)
```

Accuracy actual sobre datos sintéticos: validación del pipeline, **no** del modelo — la prueba real llega con el dataset propio (ver `PROYECTO.md`, sección 3). Thread vs Zigbee sigue siendo la confusión honesta: comparten PHY y la metadata se solapa.

## Estado y limitaciones honestas

- ✅ Clasificador + features + CLI · bridge WebSocket · dashboard · playbooks con crypto verificada por round-trip (`selftest` 4/4).
- ⚠️ Los playbooks están **verificados criptográficamente pero no contra hardware aún**: el CC1352P7 del CatSniffer es RX-only con el firmware sniffer — la inyección (TX) requiere un segundo dongle con firmware de inyección o un CC2531.
- ⚠️ La captura de llaves asume la TC link key por defecto (el caso común en dispositivos consumer).

## Estructura

```
skyrf/
├── capture/    # synthetic_source (dev) · pcap_source
├── features/   # extracción de metadata por ventana
├── classify/   # train / predict (RandomForest + centroides)
├── playbooks/  # crypto_zigbee · frames · watcher · injector · persistence · selftest
├── bridge.py   # CatSniffer → WebSocket → dashboard
└── cli.py      # terminal negro + #00e5ff
```

## Roadmap

Ver `PROYECTO.md` — preguntas de investigación (RQ1–RQ3), plan de dataset propio, fases y saga de videos.
