# SkyRF 🐱

**RF intelligence framework** para seguridad IoT — auditoría pasiva de privacidad BLE, clasificación automática de señales, playbooks de análisis con criptografía real y dashboard en vivo sobre **CatSniffer V3**. Proyecto de investigación **by Cinn4mor0ll**. Nombrado por Sky 🐾, la gata que olfatea el espectro.

> Todo el desarrollo y las capturas son sobre dispositivos propios en laboratorio controlado. Uso exclusivo para investigación y auditoría autorizada — mismo marco que KillerBee/Sniffle/Kismet.

## Qué es

Una plataforma completa encima del CatSniffer: un **bridge** en Python que parsea cada paquete a mano (byte a byte, sin scapy) y lo retransmite por WebSocket, un **dashboard** web que convierte el ruido del espectro en inteligencia accionable, y una suite de **playbooks** ejecutables con un botón — desde el reporte de auditoría hasta el crackeo offline de pairings BLE Legacy.

## Para qué sirve

- **Ver el aire, no adivinarlo**: cada dispositivo BLE cercano identificado por lo que él mismo anuncia — nombre, fabricante, mensajes de Apple Continuity (AirPods, iPhone cercano, Find My/AirTag), servicios (Tile, Fast Pair, Xiaomi…) — más Zigbee, Thread y LoRa según el firmware del CatSniffer.
- **Medir exposición real**: cada dispositivo recibe un nivel de exposición (bajo/medio/alto) con razones concretas — nombre en claro, MAC pública trackeable, rastreador por diseño — y una estimación de distancia física a partir del RSSI.
- **Entregar resultados**: el playbook `ble_audit` genera el reporte de auditoría en Markdown (resumen ejecutivo, hallazgos, inventario, metodología, recomendaciones) directamente desde la captura.
- **Atacar cuando toca**: `ble_legacy` crackea LE Legacy Pairing (TK por fuerza bruta, STK con `c1`/`s1` verificados contra los vectores oficiales de la Bluetooth Core Spec) y descifra la conexión AES-CCM con MIC verificado. Si el objetivo usa Secure Connections, lo detecta y lo dice — también eso es un resultado.

## Cómo ayuda en tu investigación

- **Auditoría de tu propio espacio**: qué gritan tus dispositivos, cuáles se pueden seguir entre lugares (MAC pública) y cuáles rotan su dirección como debe ser. Una captura de 5 minutos responde "¿qué sabe de mí cualquiera con una placa de $40?".
- **Detección de rastreadores**: los mensajes Find My de Apple y los Tiles se marcan solos — útil para revisar si hay un tracker ajeno moviéndose contigo.
- **Reconocimiento ofensivo serio**: el primer paso de cualquier operación sobre infraestructura inalámbrica es saber qué hay. SkyRF lo convierte en un inventario con niveles de riesgo, no en un volcado de MACs.
- **Reverse engineering de gadgets**: el pcap queda en formato estándar para Wireshark; los playbooks añaden la capa de análisis (¿habla cifrado? ¿qué servicios anuncia? ¿su pairing es del 2010?).
- **Evidencia reproducible**: metodología documentada en cada reporte, crypto verificada con `selftest` 8/8, y todo el pipeline inspeccionable — nada de caja negra.

## Componentes

```
CatSniffer V3 ──catnip──► lab.hex ──skyrf.bridge──► ws://localhost:8765 ──► Dashboard SkyRF
                                        │                                        │
                                        └─► transport-key-watcher (en línea)     └─► run_playbook (el dashboard
                                            …y el dashboard devuelve órdenes:        lanza los playbooks con un
                                            playbooks ejecutables desde la web       botón y ve la salida en vivo)
```

- **`skyrf.bridge`** — puente WebSocket **bidireccional**: sigue el raw-hex de catnip (o un pcapng de Wireshark) y streamea paquetes, alertas y capturas de llaves al dashboard; además acepta órdenes `run_playbook` (lista blanca cerrada, sin shell), `victim_mode` (prepara la Kali como víctima BLE emparejable en modo Legacy — requiere hci0) y `capture_control` (arranca/para tshark+Sniffle con parámetros validados por regex), devolviendo la salida en vivo. En BLE decodifica las **AD structures** de cada anuncio: identidad, fabricante, Apple Continuity, servicios, tipo de MAC y nivel de exposición viajan en cada paquete.
- **Dashboard** (`skyrf-dashboard/`, React + Vite) — tabla de dispositivos con **identidad real** (no solo MACs), **exposición** con razones y **distancia estimada**; espectro waterfall, feed de eventos, panel de **captura Sniffle** (recon promiscuo o seguimiento por MAC) y panel de **playbooks** (BLE AUDIT → reporte, BLE LEGACY CRACK, SELFTEST) con consola en vivo. Sky celebra contigo cuando un análisis tiene éxito.
- **Playbooks** (`skyrf/playbooks/`) — auditoría BLE con reporte, crack de pairing Legacy, y watchers de Zigbee/Thread/LoRa, con criptografía real (AES-CCM, MIC verificado).
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

#    ¿Ves el dashboard desde OTRO equipo (p. ej. grabas desde el Windows
#    host y la Kali es una VM)? El bridge por defecto solo escucha en
#    localhost de la Kali. Exponlo a la red del laboratorio con --host:
python -m skyrf.bridge --host 0.0.0.0 --pcap-follow ble.pcapng --proto ble
#    (el dashboard se conecta a ws://<ip-de-la-kali>:8765 automáticamente;
#     hazlo solo en tu red de laboratorio — quien alcance ese puerto puede
#     lanzar los playbooks)
python -m skyrf.bridge --raw-follow lora.raw --proto lora           # LoRa sub-GHz

# 3 · Dashboard
cd skyrf-dashboard && npx serve dist -l 3000     # dist/ ya viene compilado
#    (o recompílalo: npm install && npm run build)
#    abre la página y pulsa CAPTURAR

# 4 · Playbooks desde la web: sección PLAYBOOKS → EJECUTAR
#    BLE AUDIT REPORT genera <captura>_auditoria.md (reporte de privacidad);
#    BLE LEGACY CRACK crackea la captura y exporta <captura>_descifrado.pcapng;
#    SELFTEST corre la suite 8/8. La salida se streamea en la consola del
#    panel, y si el análisis tiene éxito Sky te da el puñito.

# 4b · Cadena de ataque BLE Legacy (cuando tengas un hci0: dongle BT real o
#    el BT del host pasado a la VM — ver requisitos abajo). El panel de
#    captura cubre el paso 02; victim_mode se lanza por el protocolo del
#    bridge (o reactiva los botones en la UI cuando tengas el adaptador):
#      01 MODO VÍCTIMA   → la Kali se vuelve emparejable con Secure
#                          Connections apagado (el teléfono cae a Legacy
#                          Pairing y su PIN de 6 dígitos queda crackeable).
#                          El agente de pairing queda VIVO y muestra el PIN
#                          en la consola del dashboard cuando el teléfono
#                          lo pida (capability DisplayYesNo).
#      02 CAPTURA        → tshark + Sniffle. OBLIGATORIO escribir la MAC de
#                          la víctima: sin ella Sniffle solo oye advertising
#                          y el pairing (que viaja DENTRO de la conexión)
#                          nunca llega al pcap → el crack dará rc=2.
#      03 CRACK          → ble_legacy sobre el pcap recién capturado.
#
#    ORDEN CRÍTICO: 01 → captura con MAC ANDANDO → emparejar el teléfono
#    (olvidando antes cualquier pairing previo con la Kali) → detener → 03.
#    Si emparejas antes de capturar, el teléfono cachea las llaves y el
#    siguiente intento ya no hace el intercambio completo.
#
#    Requisitos:
#    - Un adaptador Bluetooth HCI en la Kali (hci0). El CatSniffer NO sirve
#      para esto (es sniffer serie, no adaptador): en una VM pásale el BT
#      del host (VMware → Removable Devices → Connect) o un dongle USB.
#      Verifica con `hcitool dev` (y `rfkill unblock bluetooth` si bloqueado).
#    - Regla sudoers NOPASSWD (el bridge usa `sudo -n`; sin ella los pasos
#      01-02 fallan limpio con aviso en consola). v6.3+ también resucita
#      la pila BT sola (bluetoothd / rfkill) si le das permiso:
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/btmgmt, /usr/bin/bluetoothctl, /usr/bin/hcitool, /usr/bin/systemctl unmask bluetooth, /usr/bin/systemctl start bluetooth, /usr/sbin/rfkill" \
  | sudo tee /etc/sudoers.d/skyrf
#
#    Si el paso 01 dice "No hay adaptador Bluetooth usable (hci0)":
#      1) lsusb | grep -iE 'cambridge|csr|realtek|broadcom|bluetooth'
#         → Si NO sale: VMware ▸ VM ▸ Removable Devices ▸ [tu dongle] ▸
#           Connect (Disconnect from Host) — Windows lo tiene secuestrado.
#      2) sudo systemctl unmask bluetooth && sudo systemctl start bluetooth
#      3) rfkill list → sudo rfkill unblock bluetooth
#      4) hcitool dev → debe listar hci0 con una MAC
#      5) sudo dmesg | grep -iE 'bluetooth|hci' | tail
#         (los clones CSR8510 baratos a veces fallan al cargar firmware)
```

Nota: cada protocolo tiene su arquitectura de llaves — los playbooks son específicos por stack. Zigbee y Thread comparten PHY (802.15.4); BLE y LoRaWAN son mundos aparte. Los cuatro stacks del CatSniffer tienen playbook propio abajo.

## Playbooks de ataque

| Playbook | Protocolo | Qué hace | Módulo |
|---|---|---|---|
| **transport-key-watcher** | Zigbee | Detecta el Transport Key (APS cmd `0x05`), lo descifra con la TC link key por defecto (`ZigBeeAlliance09`) y verifica el MIC — cero falsos positivos. Corre **en línea** en el bridge | `playbooks/transport_key_watcher.py` |
| **zcl-injector** | Zigbee | Construye e inyecta comandos ZCL OnOff (toggle `0x02`) spoofeando al coordinador, con cifrado NWK completo y frame counter válido (sin replay) | `playbooks/zcl_injector.py` |
| **persistence** | Zigbee | `Mgmt_Permit_Joining_Req` (ZDO cluster `0x0036`) para dejar la red abierta a un dispositivo rogue | `playbooks/persistence.py` |
| **ble-legacy** | BLE | Crackeo **offline** de LE Legacy Pairing (estilo crackle): parsea el pcap de Sniffle, fuerza-bruta el TK (passkey 000000–999999, ~20 bits, ~77k keys/s), deriva el STK (`c1`/`s1` de la Core Spec) y **descifra la conexión** AES-CCM con MIC verificado. Detecta y reporta Secure Connections (no crackeable). Exporta pcapng descifrado para Wireshark | `playbooks/ble_legacy.py` |
| **ble-audit** | BLE | **Auditoría pasiva de privacidad**: identifica cada dispositivo (nombre, fabricante, Apple Continuity — AirPods/Find My/AirTag —, servicios como Tile/Fast Pair/Xiaomi), tipo de MAC (pública trackeable vs aleatoria), RSSI y distancia estimada, y asigna **nivel de exposición** con razones. Genera el **reporte en Markdown** (resumen ejecutivo, hallazgos, inventario, metodología, recomendaciones) | `playbooks/ble_audit.py` |
| **lorawan-auditor** | LoRa | Auditor pasivo **en línea**: FCnt reset (= ABP replay-vulnerable), DevAddr duplicado, DevNonce reutilizado (RNG débil), join-floods | `playbooks/lorawan_auditor.py` |
| **thread-watcher** | Thread | Detección **en línea** sobre 6LoWPAN/IPHC: tráfico MLE (UDP 19788), **ventana de comisionado abierta** (DTLS/5684 — el momento exacto del ataque a la network key vía PSKd) y comandos MLE sensibles en claro | `playbooks/thread_watcher.py` |

```bash
# Auditoría de privacidad BLE → reporte Markdown:
tshark -i sniffle -w entorno.pcapng
python -m skyrf.playbooks.ble_audit entorno.pcapng -o reporte.md

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

- ✅ Clasificador + features + CLI · bridge WebSocket · dashboard · playbooks de los 4 stacks (Zigbee/BLE/LoRa/Thread) con crypto verificada por round-trip (`selftest` 8/8) · auditoría BLE con reporte (`ble_audit`) e identificación de dispositivos en vivo (AD structures, Apple Continuity, exposición, distancia).
- ⚠️ Los playbooks de ataque están **verificados criptográficamente pero no contra hardware aún**: el CC1352P7 del CatSniffer es RX-only con el firmware sniffer — la inyección (TX) requiere un segundo dongle con firmware de inyección o un CC2531.
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
│               # ble_legacy (crack TK + descifrado LL) · ble_audit (reporte
│               # de privacidad) · lorawan_auditor · thread_watcher (6LoWPAN/
│               # IPHC) · selftest
├── bridge.py   # CatSniffer → WebSocket → dashboard
└── cli.py      # terminal negro + #00e5ff
```

## Roadmap

Ver `PROYECTO.md` — preguntas de investigación (RQ1–RQ3), plan de dataset propio, fases y saga de videos.
