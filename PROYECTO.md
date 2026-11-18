# SkyRF — Framework de Inteligencia RF para IoT

> Proyecto de investigación Cinn4mor0ll · Hardware: CatSniffer V3 (+ radio TX opcional)
> Estado: Fases 1–3 en código — clasificador, bridge, dashboard y playbooks funcionando (crypto verificada; validación en hardware en curso)
> Los bigotes del gato: sensores que sienten lo que no se ve.

---

## 1. Visión

El ecosistema de herramientas RF está fragmentado y envejecido: KillerBee (Zigbee, casi abandonado), Sniffle (BLE), Kismet (detección), Wireshark (análisis manual). Ninguno aprovecha hardware multiprotocolo moderno ni automatiza nada.

**SkyRF es un framework unificado de inteligencia RF:**

```
captura multiprotocolo → clasificación automática (señal, dispositivo, evento)
                       → detección de ventanas de ataque → playbooks automatizados
```

Todo sobre tráfico **cifrado o no** — la tesis central del proyecto es que la metadata basta para saber casi todo.

---

## 2. Preguntas de investigación (la parte publicable)

- **RQ1 — Fingerprinting de dispositivos:** ¿Se puede clasificar el *tipo* de dispositivo IoT (foco, sensor de puerta, enchufe, cerradura, wearable) usando únicamente metadata 802.15.4/BLE — tamaños de paquete, tiempos inter-llegada, bursts, duty cycle — con F1 > 0.90, sin descifrar nada?
- **RQ2 — Inferencia de eventos:** ¿Se pueden inferir eventos físicos ("puerta abierta", "persona despierta", "casa vacía") solo del patrón temporal del tráfico cifrado?
- **RQ3 — Detección de anomalías:** ¿Puede un modelo de comportamiento base detectar la aparición de un dispositivo rogue o un cambio de patrón (posible compromiso) en tiempo real?

**RQ3 es el ángulo defensivo**: la misma máquina que ataca, auditando, defiende. Cierra el círculo ético del proyecto.

---

## 3. Dataset propio (el activo más valioso)

No existe un dataset público bueno de tráfico multiprotocolo IoT etiquetado a nivel de metadata. **Vamos a crearlo**:

| Fase de captura | Qué se graba | Etiquetas |
|---|---|---|
| Captura base | Cada dispositivo del lab, solo, en reposo (24h) | dispositivo, protocolo |
| Eventos | Cada dispositivo ejecutando cada acción (on/off, open/close, movimiento) ×50 reps | evento |
| Escenarios | Casa simulada con actividad guionizada (rutina mañana/noche/ausencia) | estado del hogar |
| Adversario | Ataques propios (rejoin, inyección, rogue) etiquetados | tipo de ataque |

Formato: PCAP-NG (Kismet/catnip) + CSV de labels. Publicable al final del proyecto (writeup + dataset = material de conferencia).

---

## 4. Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│  UI (Fase 3): dashboard web — negro + #00e5ff           │
├─────────────────────────────────────────────────────────┤
│  Motor de clasificación (Fase 1 ← ESTAMOS AQUÍ)         │
│   · skyrf.classify: protocolo, dispositivo, evento    │
│   · skyrf.features: extracción de metadata por ventana│
├─────────────────────────────────────────────────────────┤
│  Orquestador de playbooks (Fase 2)                      │
│   · skyrf.playbooks: transport-key-watcher,           │
│     inyección ZCL, persistencia rogue                   │
├─────────────────────────────────────────────────────────┤
│  Captura: skyrf.capture                               │
│   · catnip_source (CatSniffer live)                     │
│   · pcap_source (Kismet/Wireshark PCAP-NG)              │
│   · synthetic_source (desarrollo sin hardware)          │
└─────────────────────────────────────────────────────────┘
```

Núcleo: Python + scikit-learn + Scapy + rich (terminal cyan). La web llega después encima del mismo núcleo — no se reescribe nada.

---

## 5. Roadmap (alineado a la saga de videos)

| Fase | Entregable | Estado | Video |
|---|---|---|---|
| **1** | Clasificador de protocolo/dispositivo + pipeline de captura real | ✅ hecho | Video kill chain (teaser del proyecto al final) |
| **2** | transport-key-watcher automático (dentro del bridge) | ✅ hecho · falta dataset propio y fingerprinting real | "Construí una máquina que escucha casas" |
| **3** | Playbooks de ataque + dashboard web + bridge WebSocket | ✅ hecho (crypto verificada; TX requiere 2º dongle) | "El ataque completo, sin tocar el teclado" |
| **4** | Dataset público + writeup de investigación (RQ1–3 con métricas) | pendiente | "Lo que tu casa revela: la investigación completa" |

---

## 6. Ética y marco legal (público, en el README del repo)

- Todo el desarrollo y capturas sobre **dispositivos propios en laboratorio controlado**.
- El dataset nunca incluirá tráfico de terceros identificable.
- Los playbooks ofensivos son para investigación autorizada y auditoría de redes propias — mismo marco legal que KillerBee/Sniffle/Kismet.
- El proyecto tiene explícitamente un módulo defensivo (RQ3) como parte central, no como adorno.
