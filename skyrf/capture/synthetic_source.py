"""Fuente sintética: genera tráfico etiquetado por protocolo para desarrollar
y validar el clasificador sin hardware.

Cada protocolo tiene una firma estadística distinta inspirada en su PHY/MAC real:

- Zigbee (802.15.4, 2.4 GHz): paquetes cortos (~30-90 B), tráfico periódico de
  sensores + bursts al haber comandos, beacon-ish del coordinador.
- BLE: advertising corto y muy regular, connection events agrupados con
  intervalos de conexión estrictos, paquetes pequeños (~10-40 B).
- Thread: igual PHY que Zigbee pero tráfico más conversacional (CoAP),
  paquetes medianos, patrones request/response.
- LoRa: paquetes largos, airtime enorme (SF alto = cientos de ms), tráfico
  muy esporádico, duty cycle bajísimo.

La hipótesis del proyecto (RQ1) es que estas firmas bastan para clasificar.
Aquí lo comprobamos de forma controlada antes de ir al aire real.

Parámetros anclados a documentación oficial de cada estándar:
- IEEE 802.15.4-2020 (Zigbee/Thread): O-QPSK 250 kbps en 2.4 GHz → 32 µs/byte
  de airtime; PSDU máx 127 B; canales 11-26. Zigbee NWK típico: sensores con
  polling/reporting periódico y bursts de comandos ZCL.
- Bluetooth Core Spec (BLE): advertising en canales 37/38/39, intervalo de
  advertising típico 100 ms-1 s (rango especificado 20 ms-10.24 s); connection
  events agrupados por connection interval (7.5 ms-4 s); PDUs cortos.
- Thread: mismo PHY 802.15.4 pero tráfico CoAP request/response (paquetes
  medianos, patrones conversacionales).
- LoRaWAN: airtime por SF (SF7 ≈ 40-100 ms … SF12 ≈ 1-1.5 s para payloads
  típicos), duty cycle regulado (1% EU868), tráfico muy esporádico, payloads
  hasta 222 B (SF7) / 51 B (SF12).

Pendiente (Fase 2): validar contra el dataset propio capturado con CatSniffer;
no existe dataset público etiquetado equivalente a nivel metadata.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class Packet:
    """Unidad mínima de metadata de una captura (válida para cualquier fuente)."""

    timestamp: float          # segundos (epoch o relativo)
    length: int               # bytes en el aire
    protocol_hint: str        # etiqueta ground-truth (solo en fuentes etiquetadas)
    channel: int = 0
    src: str = ""
    dst: str = ""
    frame_type: str = "data"  # data | beacon | ack | command


PROTOCOLS = ("zigbee", "ble", "thread", "lora")


def _gen_zigbee(t0: float, dur: float, rng: random.Random) -> list[Packet]:
    pkts, t = [], t0
    while t < t0 + dur:
        # sensor periódico + ruido de comandos ocasionales
        if rng.random() < 0.08:  # burst de comando (p. ej. on/off)
            for _ in range(rng.randint(3, 7)):
                pkts.append(Packet(t, rng.randint(30, 90), "zigbee",
                                     channel=rng.choice([15, 20, 25]),
                                     frame_type="command"))
                t += rng.uniform(0.002, 0.010)
        else:
            pkts.append(Packet(t, rng.randint(25, 70), "zigbee",
                                 channel=rng.choice([15, 20, 25])))
            t += rng.expovariate(1 / 0.250)  # media ~250 ms
    return pkts


def _gen_ble(t0: float, dur: float, rng: random.Random) -> list[Packet]:
    pkts, t = [], t0
    while t < t0 + dur:
        # advertising muy regular (cada ~100 ms) + eventos de conexión densos
        if rng.random() < 0.15:  # connection event: ráfaga densa
            base = t
            for _ in range(rng.randint(4, 10)):
                pkts.append(Packet(base, rng.randint(10, 40), "ble",
                                     channel=rng.choice([37, 38, 39])))
                base += rng.uniform(0.0005, 0.002)
            t += rng.uniform(0.030, 0.050)  # connection interval
        else:
            pkts.append(Packet(t, rng.randint(12, 31), "ble",
                               channel=rng.choice([37, 38, 39]),
                               frame_type="beacon"))
            t += rng.gauss(0.100, 0.005)  # advertising interval muy estable
    return pkts


def _gen_thread(t0: float, dur: float, rng: random.Random) -> list[Packet]:
    pkts, t = [], t0
    while t < t0 + dur:
        # CoAP request/response: pares de paquetes medianos
        if rng.random() < 0.3:
            pkts.append(Packet(t, rng.randint(60, 120), "thread",
                               channel=rng.choice(range(11, 27)),
                               frame_type="command"))
            t += rng.uniform(0.005, 0.020)  # vuelta del response
            pkts.append(Packet(t, rng.randint(60, 120), "thread",
                               channel=rng.choice(range(11, 27))))
        else:
            pkts.append(Packet(t, rng.randint(40, 110), "thread",
                               channel=rng.choice(range(11, 27))))
        t += rng.expovariate(1 / 0.400)
    return pkts


def _gen_lora(t0: float, dur: float, rng: random.Random) -> list[Packet]:
    pkts, t = [], t0
    while t < t0 + dur:
        # airtime largo (SF7-SF12), tráfico esporádico, paquetes grandes
        pkts.append(Packet(t, rng.randint(51, 222), "lora",
                           channel=rng.choice(range(0, 8))))
        t += rng.expovariate(1 / 3.0) + rng.uniform(0.05, 0.4)  # airtime
    return pkts


_GENERATORS = {
    "zigbee": _gen_zigbee,
    "ble": _gen_ble,
    "thread": _gen_thread,
    "lora": _gen_lora,
}


def generate(protocol: str, duration_s: float = 60.0,
             seed: int | None = None) -> list[Packet]:
    """Genera un stream etiquetado de un protocolo."""
    if protocol not in _GENERATORS:
        raise ValueError(f"protocolo desconocido: {protocol!r} "
                         f"(válidos: {', '.join(PROTOCOLS)})")
    rng = random.Random(seed)
    return _GENERATORS[protocol](0.0, duration_s, rng)


def generate_dataset(duration_per_protocol: float = 60.0,
                     samples: int = 30, seed: int = 1337) -> list[list[Packet]]:
    """Genera `samples` streams independientes por protocolo (para entrenar)."""
    streams: list[list[Packet]] = []
    rng = random.Random(seed)
    for proto in PROTOCOLS:
        for _ in range(samples):
            streams.append(generate(proto, duration_per_protocol,
                                    seed=rng.randrange(2**32)))
    return streams
