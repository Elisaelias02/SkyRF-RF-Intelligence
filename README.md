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
catnip sniff zigbee --channel 15 -ff --raw lab.hex     # Zigbee/Thread
catnip sniff lora -r lora.raw                          # LoRa (raw + RSSI real)
#    BLE NO tiene --raw en catnip v3.3.x (Sniffle solo sale por Wireshark):
tshark -i sniffle -w ble.pcapng                        # o: catnip sniff ble -ws
#    (un CatSniffer = un protocolo a la vez; multi-protocolo simultáneo
#     requiere varios dongles — roadmap Fase 2)

# 2 · Bridge (en otra terminal, desde la raíz del repo)
python -m skyrf.bridge --raw-follow lab.hex --channel 15            # Zigbee/Thread
python -m skyrf.bridge --pcap-follow ble.pcapng --proto ble         # BLE (ch 37-39)
python -m skyrf.bridge --raw-follow lora.raw --proto lora           # LoRa sub-GHz

# 3 · Dashboard
cd skyrf-dashboard && npm install && npm run build
#    sirve dist/ y abre la página; pulsa CAPTURAR
```

Nota: cada protocolo tiene su arquitectura de llaves — los playbooks son específicos por stack. Zigbee y Thread comparten PHY (802.15.4); BLE y LoRaWAN son mundos aparte. Los cuatro stacks del CatSniffer tienen playbook propio abajo.

## Playbooks de ataque

| Playbook | Protocolo | Qué hace | Módulo |
|---|---|---|---|
| **transport-key-watcher** | Zigbee | Detecta el Transport Key (APS cmd `0x05`), lo descifra con la TC link key por defecto (`ZigBeeAlliance09`) y verifica el MIC — cero falsos positivos. Corre **en línea** en el bridge | `playbooks/transport_key_watcher.py` |
| **zcl-injector** | Zigbee | Construye e inyecta comandos ZCL OnOff (toggle `0x02`) spoofeando al coordinador, con cifrado NWK completo y frame counter válido (sin replay) | `playbooks/zcl_injector.py` |
| **persistence** | Zigbee | `Mgmt_Permit_Joining_Req` (ZDO cluster `0x0036`) para dejar la red abierta a un dispositivo rogue | `playbooks/persistence.py` |
| **ble-legacy** | BLE | Crackeo **offline** de LE Legacy Pairing (estilo crackle): parsea el pcap de Sniffle, fuerza-bruta el TK (passkey 000000–999999, ~20 bits, ~77k keys/s), deriva el STK (`c1`/`s1` de la Core Spec) y **descifra la conexión** AES-CCM con MIC verificado. Exporta pcapng descifrado para Wireshark | `playbooks/ble_legacy.py` |
| **lorawan-auditor** | LoRa | Auditor pasivo **en línea**: FCnt reset (= ABP replay-vulnerable), DevAddr duplicado, DevNonce reutilizado (RNG débil), join-floods | `playbooks/lorawan_auditor.py` |
| **thread-watcher** | Thread | Detección **en línea** sobre 6LoWPAN/IPHC: tráfico MLE (UDP 19788), **ventana de comisionado abierta** (DTLS/5684 — el momento exacto del ataque a la network key vía PSKd) y comandos MLE sensibles en claro | `playbooks/thread_watcher.py` |

```bash
# Crackeo BLE offline (captura el emparejamiento COMPLETO):
tshark -i sniffle -w ble_pairing.pcapng
python -m skyrf.playbooks.ble_legacy ble_pairing.pcapng -o dec.pcapng

# Auditorías en vivo (el bridge las corre solo según --proto):
python -m skyrf.bridge --raw-follow lora.raw --proto lora      # LoRaWAN
python -m skyrf.bridge --raw-follow lab.hex --channel 15       # Zigbee + Thread

# Auditoría forense sobre raws ya capturados:
python -m skyrf.playbooks.lorawan_auditor lora.raw
python -m skyrf.playbooks.thread_watcher lab.hex

# Verificación criptográfica sin hardware (round-trips reales AES-CCM)
python -m skyrf.playbooks.selftest
#   ✓ transport key round-trip    ✓ cero falsos positivos
#   ✓ MIC inyección ZCL           ✓ MIC permit-join
#   ✓ BLE c1/s1 = vectores oficiales de la Core Spec
#   ✓ BLE crack round-trip        ✓ LoRaWAN FCnt reset/DevNonce
#   ✓ Thread MLE/comisionado
```

La construcción de tramas es manual (`playbooks/frames.py`, `struct` puro) para control total de bytes — la serialización de scapy no era determinista para las cabeceras de seguridad Zigbee. La cripto BLE está verificada contra los vectores de prueba de la Bluetooth Core Specification (Vol 3 Part H / Vol 6 Part E); el orden de bytes SKD/IV se resuelve verificando el MIC del primer paquete cifrado, no por suposición.

## Clasificador

```bash
python -m skyrf.cli train                          # entrena (dataset sintético etiquetado)
python -m skyrf.cli scan --synthetic zigbee        # scan en vivo sin hardware (dev)
```

Accuracy actual sobre datos sintéticos: validación del pipeline, **no** del modelo — la prueba real llega con el dataset propio (ver `PROYECTO.md`, sección 3). Thread vs Zigbee sigue siendo la confusión honesta: comparten PHY y la metadata se solapa.

## Estado y limitaciones honestas

- ✅ Clasificador + features + CLI · bridge WebSocket · dashboard · playbooks de los 4 stacks (Zigbee/BLE/LoRa/Thread) con crypto verificada por round-trip (`selftest` 8/8).
- ⚠️ Los playbooks están **verificados criptográficamente pero no contra hardware aún**: el CC1352P7 del CatSniffer es RX-only con el firmware sniffer — la inyección (TX) requiere un segundo dongle con firmware de inyección o un CC2531.
- ⚠️ La captura de llaves Zigbee asume la TC link key por defecto (el caso común en dispositivos consumer).
- ⚠️ BLE: el crackeo aplica solo a **LE Legacy Pairing** (passkey/Just Works). LE Secure Connections (ECDH) no es vulnerable a fuerza bruta offline — el tool lo detecta y lo dice. Requiere capturar el emparejamiento completo desde el CONNECT_IND.
- ⚠️ LoRaWAN: el auditor detecta debilidades de sesión (FCnt/DevNonce); no descifra payloads sin las claves OTAA.

## Estructura

```
skyrf/
├── capture/    # synthetic_source (dev) · pcap_source
├── features/   # extracción de metadata por ventana
├── classify/   # train / predict (RandomForest + centroides)
├── playbooks/  # crypto_zigbee · frames · transport-key · zcl · persistence ·
│               # ble_legacy (crack TK + descifrado LL) · lorawan_auditor ·
│               # thread_watcher (6LoWPAN/IPHC) · selftest
├── bridge.py   # CatSniffer → WebSocket → dashboard
└── cli.py      # terminal negro + #00e5ff
```

## Roadmap

Ver `PROYECTO.md` — preguntas de investigación (RQ1–RQ3), plan de dataset propio, fases y saga de videos.
